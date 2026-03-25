import { Shield, AlertTriangle, AlertCircle, Info } from 'lucide-react';
import type { Device } from '../types';
import { riskColor, riskLabel } from '../lib/risk-colors';

interface RiskDashboardProps {
  devices: Device[];
}

export function RiskDashboard({ devices }: RiskDashboardProps) {
  if (devices.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-text-secondary gap-4 py-24">
        <Shield size={48} className="opacity-30" />
        <p className="text-lg font-light">No devices to analyze</p>
        <p className="text-sm">Run a scan to see your network's risk profile</p>
      </div>
    );
  }

  const avgScore = Math.round(devices.reduce((sum, d) => sum + d.risk_score, 0) / devices.length);
  const high = devices.filter((d) => d.risk_score >= 60).length;
  const medium = devices.filter((d) => d.risk_score >= 30 && d.risk_score < 60).length;
  const low = devices.filter((d) => d.risk_score < 30).length;
  const topRisk = [...devices].sort((a, b) => b.risk_score - a.risk_score).slice(0, 5);

  return (
    <div className="p-8 max-w-5xl mx-auto space-y-8">
      <h1 className="text-3xl font-bold tracking-tight">Risk Dashboard</h1>

      {/* Overall Score */}
      <div className="flex items-center gap-6 p-6 rounded-2xl bg-surface-raised border border-border">
        <div
          className="w-24 h-24 rounded-full flex items-center justify-center text-3xl font-bold border-4"
          style={{ borderColor: riskColor(avgScore), color: riskColor(avgScore) }}
        >
          {avgScore}
        </div>
        <div>
          <div className="text-2xl font-bold">{riskLabel(avgScore)} Risk</div>
          <div className="text-text-secondary">Average across {devices.length} devices</div>
        </div>
      </div>

      {/* Severity Cards */}
      <div className="grid grid-cols-3 gap-4">
        <SeverityCard icon={AlertCircle} label="High Risk" count={high} color="var(--color-risk-high)" />
        <SeverityCard icon={AlertTriangle} label="Medium Risk" count={medium} color="var(--color-risk-medium)" />
        <SeverityCard icon={Info} label="Low Risk" count={low} color="var(--color-risk-low)" />
      </div>

      {/* Top Riskiest Devices */}
      <div>
        <h2 className="text-sm font-bold uppercase tracking-wider text-text-secondary mb-3">Top Risk Devices</h2>
        <div className="rounded-xl border border-border overflow-hidden">
          {topRisk.map((d, i) => (
            <div key={d.id} className={`flex items-center gap-4 px-4 py-3 ${i > 0 ? 'border-t border-border' : ''}`}>
              <span className="font-mono font-bold text-sm w-36">{d.ip_address}</span>
              <span className="text-xs uppercase px-2 py-0.5 rounded bg-surface-overlay text-text-secondary">{d.device_type}</span>
              {d.hostname && <span className="text-sm text-text-secondary flex-1 truncate">{d.hostname}</span>}
              <span className="font-bold font-mono text-sm" style={{ color: riskColor(d.risk_score) }}>
                {d.risk_score}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function SeverityCard({ icon: Icon, label, count, color }: { icon: typeof AlertCircle; label: string; count: number; color: string }) {
  return (
    <div className="p-5 rounded-xl bg-surface-raised border border-border">
      <div className="flex items-center gap-2 mb-2">
        <Icon size={16} style={{ color }} />
        <span className="text-xs font-bold uppercase tracking-wider text-text-secondary">{label}</span>
      </div>
      <div className="text-4xl font-bold" style={{ color }}>{count}</div>
    </div>
  );
}
