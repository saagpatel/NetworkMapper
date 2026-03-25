import { useState } from 'react';
import { Clock, Plus, Minus } from 'lucide-react';
import type { ScanRun, ScanDelta } from '../types';
import { fetchScanDelta } from '../lib/api';

interface TimelineViewProps {
  scans: ScanRun[];
}

export function TimelineView({ scans }: TimelineViewProps) {
  const [selectedScan, setSelectedScan] = useState<number | null>(null);
  const [delta, setDelta] = useState<ScanDelta | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSelect = async (scanId: number) => {
    setSelectedScan(scanId);
    setLoading(true);
    try {
      const d = await fetchScanDelta(scanId);
      setDelta(d);
    } catch {
      setDelta(null);
    } finally {
      setLoading(false);
    }
  };

  if (scans.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-text-secondary gap-4 py-24">
        <Clock size={48} className="opacity-30" />
        <p className="text-lg font-light">No scan history</p>
      </div>
    );
  }

  return (
    <div className="p-8 max-w-5xl mx-auto space-y-6">
      <h1 className="text-3xl font-bold tracking-tight">Scan History</h1>

      <div className="grid grid-cols-[300px_1fr] gap-6">
        {/* Scan List */}
        <div className="space-y-2">
          {scans.map((scan) => (
            <button
              key={scan.id}
              onClick={() => handleSelect(scan.id)}
              className={`w-full text-left p-3 rounded-lg border transition-all ${
                selectedScan === scan.id
                  ? 'border-accent bg-accent/10'
                  : 'border-border hover:border-text-secondary'
              }`}
            >
              <div className="text-sm font-bold">Scan #{scan.id}</div>
              <div className="text-xs text-text-secondary mt-1">
                {new Date(scan.started_at).toLocaleString()}
              </div>
              <div className="flex items-center gap-2 mt-1">
                <span className={`text-xs px-1.5 py-0.5 rounded font-medium ${
                  scan.status === 'completed' ? 'bg-risk-low/20 text-risk-low' :
                  scan.status === 'failed' ? 'bg-risk-high/20 text-risk-high' :
                  'bg-accent/20 text-accent'
                }`}>
                  {scan.status}
                </span>
                <span className="text-xs text-text-secondary">{scan.host_count} hosts</span>
                <span className="text-xs text-text-secondary font-mono">{scan.profile}</span>
              </div>
            </button>
          ))}
        </div>

        {/* Delta View */}
        <div className="min-h-[300px]">
          {!selectedScan && (
            <div className="flex items-center justify-center h-full text-text-secondary text-sm">
              Select a scan to view changes
            </div>
          )}

          {loading && (
            <div className="space-y-3">
              {[...Array(4)].map((_, i) => (
                <div key={i} className="h-12 bg-surface-raised rounded-lg animate-pulse" />
              ))}
            </div>
          )}

          {delta && !loading && (
            <div className="space-y-4">
              {delta.new_devices.length > 0 && (
                <div>
                  <h3 className="text-xs font-bold uppercase tracking-wider text-risk-low mb-2 flex items-center gap-1">
                    <Plus size={14} /> New Devices ({delta.new_devices.length})
                  </h3>
                  {delta.new_devices.map((d) => (
                    <div key={d.id} className="p-2 rounded bg-risk-low/10 border border-risk-low/20 text-sm mb-1">
                      <span className="font-mono">{d.ip_address}</span>
                      <span className="text-text-secondary ml-2">{d.mac_address}</span>
                      {d.vendor && <span className="text-text-secondary ml-2">({d.vendor})</span>}
                    </div>
                  ))}
                </div>
              )}

              {delta.disappeared_devices.length > 0 && (
                <div>
                  <h3 className="text-xs font-bold uppercase tracking-wider text-risk-high mb-2 flex items-center gap-1">
                    <Minus size={14} /> Disappeared Devices ({delta.disappeared_devices.length})
                  </h3>
                  {delta.disappeared_devices.map((d) => (
                    <div key={d.id} className="p-2 rounded bg-risk-high/10 border border-risk-high/20 text-sm mb-1">
                      <span className="font-mono">{d.ip_address}</span>
                      <span className="text-text-secondary ml-2">{d.mac_address}</span>
                    </div>
                  ))}
                </div>
              )}

              {delta.new_devices.length === 0 && delta.disappeared_devices.length === 0 && (
                <p className="text-text-secondary text-sm">No changes detected in this scan</p>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
