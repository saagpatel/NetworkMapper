import { useEffect, useState } from 'react';
import { Plus, Trash2, Save, Clock } from 'lucide-react';
import { fetchWhitelist, ApiError } from '../lib/api';
import { useToast } from './Toast';
import type { ScanProfile } from '../types';

export function SettingsView() {
  return (
    <div className="p-8 max-w-3xl mx-auto space-y-10">
      <h1 className="text-3xl font-bold tracking-tight">Settings</h1>
      <WhitelistSection />
      <ScheduleSection />
    </div>
  );
}

function WhitelistSection() {
  const [cidrs, setCidrs] = useState<string[]>([]);
  const [newCidr, setNewCidr] = useState('');
  const [saving, setSaving] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    fetchWhitelist().then(setCidrs).catch(() => toast('error', 'Failed to load whitelist'));
  }, []);

  const addCidr = () => {
    const trimmed = newCidr.trim();
    if (!trimmed || cidrs.includes(trimmed)) return;
    setCidrs([...cidrs, trimmed]);
    setNewCidr('');
  };

  const removeCidr = (cidr: string) => {
    setCidrs(cidrs.filter((c) => c !== cidr));
  };

  const save = async () => {
    setSaving(true);
    try {
      const res = await fetch('/api/config/whitelist', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cidrs }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new ApiError(res.status, body?.detail || 'Save failed');
      }
      toast('success', 'Whitelist updated');
    } catch (err) {
      toast('error', err instanceof Error ? err.message : 'Failed to save whitelist');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-4">
      <h2 className="text-sm font-bold uppercase tracking-wider text-text-secondary">Scan Whitelist</h2>
      <p className="text-sm text-text-secondary">Only CIDRs in this list can be scanned.</p>

      <div className="space-y-2">
        {cidrs.map((cidr) => (
          <div key={cidr} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-surface-raised border border-border">
            <span className="font-mono text-sm flex-1">{cidr}</span>
            <button onClick={() => removeCidr(cidr)} className="p-1 rounded hover:bg-surface-overlay text-text-secondary hover:text-risk-high transition-colors">
              <Trash2 size={14} />
            </button>
          </div>
        ))}
      </div>

      <div className="flex gap-2">
        <input
          type="text"
          value={newCidr}
          onChange={(e) => setNewCidr(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && addCidr()}
          placeholder="e.g. 10.0.0.0/24"
          className="flex-1 px-3 py-2 bg-surface rounded-lg border border-border text-sm font-mono focus:border-accent focus:outline-none"
        />
        <button onClick={addCidr} className="px-3 py-2 rounded-lg border border-border hover:bg-surface-overlay transition-colors">
          <Plus size={16} />
        </button>
      </div>

      <button
        onClick={save}
        disabled={saving}
        className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-bold bg-accent hover:bg-accent-hover text-white transition-colors disabled:opacity-50"
      >
        <Save size={14} />
        {saving ? 'Saving...' : 'Save Whitelist'}
      </button>
    </div>
  );
}

function ScheduleSection() {
  const [cron, setCron] = useState('');
  const [targetCidr, setTargetCidr] = useState('');
  const [profile, setProfile] = useState<ScanProfile>('quick');
  const [saving, setSaving] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    fetch('/api/schedule')
      .then((r) => r.json())
      .then((body) => {
        const data = body.data;
        setCron(data.cron_expression || '');
        setTargetCidr(data.target_cidr || '');
        setProfile(data.profile || 'quick');
      })
      .catch(() => {});
  }, []);

  const save = async () => {
    setSaving(true);
    try {
      const res = await fetch('/api/schedule', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          cron_expression: cron || null,
          target_cidr: targetCidr || null,
          profile,
        }),
      });
      if (!res.ok) throw new Error('Save failed');
      toast('success', cron ? 'Schedule updated' : 'Schedule disabled');
    } catch {
      toast('error', 'Failed to save schedule');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-4">
      <h2 className="text-sm font-bold uppercase tracking-wider text-text-secondary flex items-center gap-2">
        <Clock size={14} /> Scheduled Scanning
      </h2>
      <p className="text-sm text-text-secondary">Configure automatic scans on a cron schedule. Leave cron empty to disable.</p>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-xs text-text-secondary mb-1">Cron Expression</label>
          <input
            type="text"
            value={cron}
            onChange={(e) => setCron(e.target.value)}
            placeholder="0 */6 * * *"
            className="w-full px-3 py-2 bg-surface rounded-lg border border-border text-sm font-mono focus:border-accent focus:outline-none"
          />
          <span className="text-xs text-text-secondary mt-1 block">e.g. "0 */6 * * *" = every 6 hours</span>
        </div>
        <div>
          <label className="block text-xs text-text-secondary mb-1">Target CIDR</label>
          <input
            type="text"
            value={targetCidr}
            onChange={(e) => setTargetCidr(e.target.value)}
            placeholder="192.168.1.0/24"
            className="w-full px-3 py-2 bg-surface rounded-lg border border-border text-sm font-mono focus:border-accent focus:outline-none"
          />
        </div>
      </div>

      <div>
        <label className="block text-xs text-text-secondary mb-1">Profile</label>
        <select
          value={profile}
          onChange={(e) => setProfile(e.target.value as ScanProfile)}
          className="px-3 py-2 bg-surface rounded-lg border border-border text-sm focus:border-accent focus:outline-none"
        >
          <option value="quick">Quick</option>
          <option value="standard">Standard</option>
          <option value="deep">Deep</option>
        </select>
      </div>

      <button
        onClick={save}
        disabled={saving}
        className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-bold bg-accent hover:bg-accent-hover text-white transition-colors disabled:opacity-50"
      >
        <Save size={14} />
        {saving ? 'Saving...' : 'Save Schedule'}
      </button>
    </div>
  );
}
