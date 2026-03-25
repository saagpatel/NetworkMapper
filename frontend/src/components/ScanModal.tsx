import { useEffect, useState } from 'react';
import { X, Radar, Zap, Search, ScanEye } from 'lucide-react';
import type { ScanProfile } from '../types';
import { fetchWhitelist, startScan, ApiError } from '../lib/api';

interface ScanModalProps {
  open: boolean;
  onClose: () => void;
  onScanStarted: (scanId: number) => void;
}

const PROFILES: { value: ScanProfile; label: string; icon: typeof Zap; desc: string; time: string }[] = [
  { value: 'quick', label: 'Quick', icon: Zap, desc: 'Top 100 ports, no version detection', time: '~30s' },
  { value: 'standard', label: 'Standard', icon: Search, desc: 'Top 1000 ports with version detection', time: '2-5 min' },
  { value: 'deep', label: 'Deep', icon: ScanEye, desc: 'All ports, version + OS detection', time: '5-15 min' },
];

export function ScanModal({ open, onClose, onScanStarted }: ScanModalProps) {
  const [cidr, setCidr] = useState('');
  const [profile, setProfile] = useState<ScanProfile>('quick');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (!open) return;
    fetchWhitelist().then((list) => {
      if (list.length > 0 && !cidr) setCidr(list[0]);
    }).catch(() => {});
  }, [open]);

  if (!open) return null;

  const handleSubmit = async () => {
    setError(null);
    setSubmitting(true);
    try {
      const scan = await startScan(cidr, profile);
      onScanStarted(scan.id);
      onClose();
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.status === 403 ? `CIDR "${cidr}" is not in the whitelist` : err.message);
      } else {
        setError('Failed to start scan');
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div className="bg-surface-raised border border-border rounded-2xl w-[480px] shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between p-5 border-b border-border">
          <div className="flex items-center gap-3">
            <Radar size={20} className="text-accent" />
            <h2 className="text-lg font-bold">New Scan</h2>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-surface-overlay transition-colors">
            <X size={18} />
          </button>
        </div>

        <div className="p-5 space-y-5">
          {/* CIDR Input */}
          <div>
            <label className="block text-xs font-bold uppercase tracking-wider text-text-secondary mb-2">Target CIDR</label>
            <input
              type="text"
              value={cidr}
              onChange={(e) => setCidr(e.target.value)}
              placeholder="192.168.1.0/24"
              className="w-full px-3 py-2.5 bg-surface rounded-lg border border-border text-sm font-mono focus:border-accent focus:outline-none transition-colors"
            />
          </div>

          {/* Profile Selector */}
          <div>
            <label className="block text-xs font-bold uppercase tracking-wider text-text-secondary mb-2">Scan Profile</label>
            <div className="space-y-2">
              {PROFILES.map((p) => (
                <button
                  key={p.value}
                  onClick={() => setProfile(p.value)}
                  className={`w-full flex items-center gap-3 p-3 rounded-lg border text-left transition-all ${
                    profile === p.value
                      ? 'border-accent bg-accent/10'
                      : 'border-border hover:border-text-secondary'
                  }`}
                >
                  <p.icon size={18} className={profile === p.value ? 'text-accent' : 'text-text-secondary'} />
                  <div className="flex-1">
                    <div className="text-sm font-bold">{p.label}</div>
                    <div className="text-xs text-text-secondary">{p.desc}</div>
                  </div>
                  <span className="text-xs text-text-secondary font-mono">{p.time}</span>
                </button>
              ))}
            </div>
          </div>

          {error && (
            <div className="p-3 rounded-lg bg-risk-high/10 border border-risk-high/30 text-risk-high text-sm">
              {error}
            </div>
          )}
        </div>

        <div className="p-5 border-t border-border flex gap-3 justify-end">
          <button onClick={onClose} className="px-4 py-2 rounded-lg text-sm font-medium text-text-secondary hover:bg-surface-overlay transition-colors">
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={submitting || !cidr}
            className="px-5 py-2 rounded-lg text-sm font-bold bg-accent hover:bg-accent-hover text-white transition-colors disabled:opacity-50"
          >
            {submitting ? 'Starting...' : 'Start Scan'}
          </button>
        </div>
      </div>
    </div>
  );
}
