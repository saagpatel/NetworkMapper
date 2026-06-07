"""Scan orchestrator — coordinates ARP → nmap → classify → risk → persist."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from db import repository
from models.internal import NmapHostResult
from models.schemas import ScanProgressEvent
from oui.resolver import OUIResolver
from scanner import arp_scanner, classifier, risk_engine
from scanner.nmap_scanner import scan_hosts
from scanner.profile import get_profile

if TYPE_CHECKING:
    from cve.index import CVEIndex

logger = logging.getLogger(__name__)


async def run_scan(
    target_cidr: str,
    profile_name: str,
    db_path: str | Path,
    oui_resolver: OUIResolver,
    progress_queue: asyncio.Queue[ScanProgressEvent],
    cve_index: CVEIndex | None = None,
) -> int:
    """Run a full scan pipeline and return the scan_run_id.

    Pipeline: ARP sweep → nmap scan → classify → risk score → persist to SQLite.
    Emits ScanProgressEvent messages to the queue throughout.
    """
    conn = repository.get_connection(db_path)
    scan_id = repository.create_scan_run(conn, target_cidr, profile_name)

    try:
        profile = get_profile(profile_name)

        # Step 1: ARP sweep
        arp_results = await asyncio.to_thread(arp_scanner.sweep, target_cidr)

        await progress_queue.put(
            ScanProgressEvent(
                type="arp_complete",
                message=f"ARP sweep complete: {len(arp_results)} hosts found",
                hosts_found=len(arp_results),
            )
        )

        if not arp_results:
            repository.update_scan_run(
                conn,
                scan_id,
                status="completed",
                host_count=0,
                completed_at=datetime.now(UTC).isoformat(),
            )
            await progress_queue.put(
                ScanProgressEvent(type="complete", message="Scan complete: no hosts found")
            )
            return scan_id

        # Step 2: nmap scan
        ips = [h["ip"] for h in arp_results]
        mac_by_ip: dict[str, str] = {h["ip"]: h["mac"] for h in arp_results}

        nmap_results: list[NmapHostResult] = []
        if not profile.arp_only:
            nmap_results = await asyncio.to_thread(scan_hosts, ips, profile)

            for i, result in enumerate(nmap_results):
                # Backfill MAC from ARP if nmap didn't capture it
                if result.mac is None and result.ip in mac_by_ip:
                    result.mac = mac_by_ip[result.ip]

                await progress_queue.put(
                    ScanProgressEvent(
                        type="host_scanned",
                        message=f"Scanned {result.ip}",
                        hosts_total=len(ips),
                        current_host=result.ip,
                    )
                )
        else:
            # ARP-only mode — create minimal host results
            for arp_host in arp_results:
                nmap_results.append(
                    NmapHostResult(
                        ip=arp_host["ip"],
                        mac=arp_host["mac"],
                        state="up",
                    )
                )

        # Step 3: Classify and score each device
        for host in nmap_results:
            if host.mac is None:
                logger.warning("Skipping host %s — no MAC address available", host.ip)
                continue

            vendor = oui_resolver.lookup(host.mac)
            device_type = classifier.classify(host, vendor)
            score, port_flags, summary, cve_matches = risk_engine.score_device(
                device_type, host.ports, cve_index=cve_index,
            )

            # Step 4: Persist
            device_id = repository.upsert_device(
                conn,
                mac_address=host.mac,
                ip_address=host.ip,
                hostname=host.hostname,
                vendor=vendor,
                device_type=device_type,
                os_guess=host.os_guess,
                os_accuracy=host.os_accuracy,
                scan_id=scan_id,
                risk_score=score,
            )

            repository.insert_appearance(conn, scan_id, device_id, host.ip)

            for port in host.ports:
                if port.state != "open":
                    continue
                repository.insert_port(
                    conn,
                    device_id=device_id,
                    scan_run_id=scan_id,
                    port=port.port,
                    protocol=port.protocol,
                    state=port.state,
                    service=port.service,
                    version=port.version,
                    risk_flag=port_flags.get(port.port),
                )

            # Persist CVE matches
            for port_num, cve in cve_matches:
                repository.insert_cve_match(
                    conn,
                    device_id=device_id,
                    scan_run_id=scan_id,
                    port=port_num,
                    cve_id=cve.cve_id,
                    cvss_score=cve.cvss_score,
                    severity=cve.severity,
                    description=cve.description,
                    service=next(
                        (p.service for p in host.ports if p.port == port_num), None
                    ),
                    version=next(
                        (p.version for p in host.ports if p.port == port_num), None
                    ),
                )

        await progress_queue.put(
            ScanProgressEvent(
                type="classification_done",
                message=f"Classified {len(nmap_results)} devices",
            )
        )

        # Step 5: Finalize
        repository.update_scan_run(
            conn,
            scan_id,
            status="completed",
            host_count=len(nmap_results),
            completed_at=datetime.now(UTC).isoformat(),
        )

        await progress_queue.put(
            ScanProgressEvent(
                type="complete",
                message=f"Scan complete: {len(nmap_results)} hosts scanned",
                hosts_found=len(nmap_results),
            )
        )

    except Exception as exc:
        logger.exception("Scan %d failed", scan_id)
        repository.update_scan_run(
            conn, scan_id, status="failed", error_msg=str(exc),
            completed_at=datetime.now(UTC).isoformat(),
        )
        await progress_queue.put(
            ScanProgressEvent(type="error", message=f"Scan failed: {exc}")
        )
        raise
    finally:
        conn.close()

    return scan_id
