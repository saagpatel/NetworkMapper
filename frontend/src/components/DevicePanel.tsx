import { useEffect, useState } from 'react';
import { X, Shield } from 'lucide-react';
import type { DeviceDetail } from '../types';
import { fetchDevice } from '../lib/api';
import { riskBgClass, riskLabel, severityColor } from '../lib/risk-colors';

interface DevicePanelProps {
  deviceId: number | null;
  onClose: () => void;
}

export function DevicePanel({ deviceId, onClose }: DevicePanelProps) {
  const [device, setDevice] = useState<DeviceDetail | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!deviceId) { setDevice(null); return; }
    setLoading(true);
    fetchDevice(deviceId)
      .then(setDevice)
      .catch(() => setDevice(null))
      .finally(() => setLoading(false));
  }, [deviceId]);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [onClose]);

  if (!deviceId) return null;

  return (
    <div className="fixed right-0 top-0 h-full w-[420px] bg-surface-raised border-l border-border overflow-y-auto z-50 shadow-2xl">
      <div className="sticky top-0 bg-surface-raised border-b border-border p-4 flex items-center justify-between">
        <h2 className="text-lg font-bold tracking-tight">Device Detail</h2>
        <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-surface-overlay transition-colors">
          <X size={18} />
        </button>
      </div>

      {loading && (
        <div className="p-6 space-y-4">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="h-4 bg-surface-overlay rounded animate-pulse" />
          ))}
        </div>
      )}

      {device && !loading && (
        <div className="p-4 space-y-6">
          {/* Header */}
          <div className="space-y-2">
            <div className="flex items-center gap-3">
              <span className="text-2xl font-bold font-mono">{device.ip_address}</span>
              <span className={`px-2 py-0.5 rounded text-xs font-bold ${riskBgClass(device.risk_score)}`}>
                {riskLabel(device.risk_score)} ({device.risk_score})
              </span>
            </div>
            {device.hostname && <p className="text-text-secondary">{device.hostname}</p>}
            <span className="inline-block px-2 py-0.5 rounded bg-accent/20 text-accent text-xs font-medium uppercase">
              {device.device_type}
            </span>
          </div>

          {/* Info */}
          <div className="space-y-2 text-sm">
            <Row label="MAC" value={device.mac_address} mono />
            {device.vendor && <Row label="Vendor" value={device.vendor} />}
            {device.os_guess && <Row label="OS" value={`${device.os_guess} (${device.os_accuracy}%)`} />}
          </div>

          {/* Risk Summary */}
          {device.risk_summary && (
            <div className="p-3 rounded-lg bg-surface-overlay text-sm leading-relaxed">
              <div className="flex items-center gap-2 mb-1 text-text-secondary text-xs font-bold uppercase tracking-wider">
                <Shield size={14} /> Risk Summary
              </div>
              {device.risk_summary}
            </div>
          )}

          {/* Ports */}
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-text-secondary mb-2">
              Open Ports ({device.ports.length})
            </h3>
            {device.ports.length === 0 ? (
              <p className="text-sm text-text-secondary">No open ports detected</p>
            ) : (
              <div className="space-y-1">
                {device.ports.map((p) => (
                  <div key={`${p.port}-${p.protocol}`} className="flex items-center gap-2 text-sm py-1.5 px-2 rounded bg-surface-overlay/50">
                    <span className="font-mono font-bold w-14">{p.port}</span>
                    <span className="text-text-secondary flex-1">{p.service || '—'}</span>
                    {p.version && <span className="text-xs text-text-secondary truncate max-w-[120px]">{p.version}</span>}
                    {p.risk_flag && (
                      <span className={`text-xs px-1.5 py-0.5 rounded font-medium ${
                        p.risk_flag === 'critical' ? 'bg-risk-high/20 text-risk-high' :
                        p.risk_flag === 'outdated' ? 'bg-risk-medium/20 text-risk-medium' :
                        'bg-risk-low/20 text-risk-low'
                      }`}>
                        {p.risk_flag}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* CVE Matches */}
          {device.cve_matches.length > 0 && (
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-text-secondary mb-2">
                CVE Matches ({device.cve_matches.length})
              </h3>
              <div className="space-y-2">
                {device.cve_matches.map((cve) => (
                  <div key={cve.cve_id} className="p-2 rounded-lg bg-surface-overlay text-sm">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-mono font-bold text-xs">{cve.cve_id}</span>
                      <span className="text-xs px-1.5 py-0.5 rounded font-bold" style={{ color: severityColor(cve.severity), background: `${severityColor(cve.severity)}20` }}>
                        {cve.severity}
                      </span>
                      {cve.cvss_score !== null && (
                        <span className="text-xs text-text-secondary ml-auto">{cve.cvss_score.toFixed(1)}</span>
                      )}
                    </div>
                    <p className="text-xs text-text-secondary leading-relaxed">{cve.description}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex justify-between">
      <span className="text-text-secondary">{label}</span>
      <span className={mono ? 'font-mono text-xs' : ''}>{value}</span>
    </div>
  );
}
