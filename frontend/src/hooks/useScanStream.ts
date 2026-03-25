import { useCallback, useEffect, useRef, useState } from 'react';
import type { ScanProgressEvent } from '../types';

interface ScanStreamState {
  status: ScanProgressEvent['type'] | 'idle';
  progress: number;
  currentHost: string | null;
  message: string;
  isComplete: boolean;
}

export function useScanStream(scanId: number | null) {
  const [state, setState] = useState<ScanStreamState>({
    status: 'idle',
    progress: 0,
    currentHost: null,
    message: '',
    isComplete: false,
  });
  const sourceRef = useRef<EventSource | null>(null);

  useEffect(() => {
    if (!scanId) return;

    const source = new EventSource(`/api/scans/${scanId}/stream`);
    sourceRef.current = source;

    source.onmessage = (e) => {
      const event: ScanProgressEvent = JSON.parse(e.data);

      let progress = 0;
      if (event.type === 'arp_complete') progress = 10;
      else if (event.type === 'host_scanned' && event.hosts_total) {
        const hostsScanned = event.hosts_found ?? 0;
        progress = 10 + (hostsScanned / event.hosts_total) * 70;
      } else if (event.type === 'classification_done') progress = 90;
      else if (event.type === 'complete') progress = 100;

      setState({
        status: event.type,
        progress,
        currentHost: event.current_host ?? null,
        message: event.message,
        isComplete: event.type === 'complete' || event.type === 'error',
      });

      if (event.type === 'complete' || event.type === 'error') {
        source.close();
      }
    };

    source.onerror = () => {
      setState((prev) => ({ ...prev, isComplete: true, status: 'error', message: 'Connection lost' }));
      source.close();
    };

    return () => {
      source.close();
      sourceRef.current = null;
    };
  }, [scanId]);

  const reset = useCallback(() => {
    setState({ status: 'idle', progress: 0, currentHost: null, message: '', isComplete: false });
  }, []);

  return { ...state, reset };
}
