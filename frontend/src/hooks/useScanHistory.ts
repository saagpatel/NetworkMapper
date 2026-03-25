import { useCallback, useEffect, useState } from 'react';
import type { ScanRun } from '../types';
import { fetchScans } from '../lib/api';

export function useScanHistory() {
  const [scans, setScans] = useState<ScanRun[]>([]);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fetchScans();
      setScans(data);
    } catch {
      // Silently fail — scans list is non-critical
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  return { scans, loading, refresh };
}
