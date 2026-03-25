import type { ApiResponse, CVEIndexStatus, Device, DeviceDetail, ScanDelta, ScanRun } from '../types';

const BASE = '/api';

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init);
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(res.status, body?.detail?.message || body?.detail || res.statusText);
  }
  const json: ApiResponse<T> = await res.json();
  return json.data;
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export async function fetchDevices(): Promise<Device[]> {
  return fetchJson<Device[]>(`${BASE}/devices`);
}

export async function fetchDevice(id: number): Promise<DeviceDetail> {
  return fetchJson<DeviceDetail>(`${BASE}/devices/${id}`);
}

export async function fetchScans(): Promise<ScanRun[]> {
  return fetchJson<ScanRun[]>(`${BASE}/scans`);
}

export async function fetchScan(id: number): Promise<ScanRun> {
  return fetchJson<ScanRun>(`${BASE}/scans/${id}`);
}

export async function fetchScanDelta(id: number): Promise<ScanDelta> {
  return fetchJson<ScanDelta>(`${BASE}/scans/${id}/delta`);
}

export async function startScan(target_cidr: string, profile: string): Promise<ScanRun> {
  return fetchJson<ScanRun>(`${BASE}/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target_cidr, profile }),
  });
}

export async function fetchCVEStatus(): Promise<CVEIndexStatus> {
  return fetchJson<CVEIndexStatus>(`${BASE}/cve/status`);
}

export async function refreshCVE(): Promise<void> {
  const res = await fetch(`${BASE}/cve/refresh`, { method: 'POST' });
  if (!res.ok) throw new ApiError(res.status, 'Failed to start CVE refresh');
}

export async function fetchWhitelist(): Promise<string[]> {
  return fetchJson<string[]>(`${BASE}/config/whitelist`);
}
