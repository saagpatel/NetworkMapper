import { useEffect, useState } from 'react';
import { Database, RefreshCw } from 'lucide-react';
import type { CVEIndexStatus } from '../types';
import { fetchCVEStatus, refreshCVE } from '../lib/api';

export function CVEStatusBar() {
  const [status, setStatus] = useState<CVEIndexStatus | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const loadStatus = async () => {
    try {
      const s = await fetchCVEStatus();
      setStatus(s);
    } catch { /* ignore */ }
  };

  useEffect(() => {
    loadStatus();
  }, []);

  // Poll during download
  useEffect(() => {
    if (!status?.downloading) return;
    const interval = setInterval(loadStatus, 5000);
    return () => clearInterval(interval);
  }, [status?.downloading]);

  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      await refreshCVE();
      // Start polling
      setTimeout(loadStatus, 2000);
    } catch { /* ignore */ }
    setRefreshing(false);
  };

  if (!status) return null;

  return (
    <div className="flex items-center gap-3 text-xs text-text-secondary">
      <Database size={14} />
      {status.download_complete ? (
        <>
          <span>{status.cve_count.toLocaleString()} CVEs</span>
          {status.last_updated && (
            <span>Updated {new Date(status.last_updated).toLocaleDateString()}</span>
          )}
        </>
      ) : (
        <span>NVD not downloaded</span>
      )}

      {status.downloading && status.download_progress !== null && (
        <div className="flex items-center gap-2">
          <div className="w-24 h-1.5 bg-surface-overlay rounded-full overflow-hidden">
            <div className="h-full bg-accent rounded-full transition-all" style={{ width: `${status.download_progress}%` }} />
          </div>
          <span>{status.download_progress.toFixed(0)}%</span>
        </div>
      )}

      {!status.downloading && (
        <button
          onClick={handleRefresh}
          disabled={refreshing}
          className="p-1 rounded hover:bg-surface-overlay transition-colors"
          title="Refresh NVD feed"
        >
          <RefreshCw size={12} className={refreshing ? 'animate-spin' : ''} />
        </button>
      )}
    </div>
  );
}
