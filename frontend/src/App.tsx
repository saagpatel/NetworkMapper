import { useCallback, useState } from 'react';
import { Network, LayoutDashboard, Clock, Grid3X3, Radar, Settings } from 'lucide-react';
import { TopologyGraph } from './components/TopologyGraph';
import { DevicePanel } from './components/DevicePanel';
import { ScanModal } from './components/ScanModal';
import { RiskDashboard } from './components/RiskDashboard';
import { TimelineView } from './components/TimelineView';
import { SubnetView } from './components/SubnetView';
import { CVEStatusBar } from './components/CVEStatusBar';
import { SettingsView } from './components/SettingsView';
import { ToastProvider } from './components/Toast';
import { useDevices } from './hooks/useDevices';
import { useScanHistory } from './hooks/useScanHistory';
import { useScanStream } from './hooks/useScanStream';

type View = 'topology' | 'dashboard' | 'timeline' | 'subnet' | 'settings';

const NAV_ITEMS: { id: View; label: string; icon: typeof Network }[] = [
  { id: 'topology', label: 'Topology', icon: Network },
  { id: 'subnet', label: 'Subnets', icon: Grid3X3 },
  { id: 'dashboard', label: 'Risk', icon: LayoutDashboard },
  { id: 'timeline', label: 'History', icon: Clock },
  { id: 'settings', label: 'Settings', icon: Settings },
];

export default function App() {
  const [view, setView] = useState<View>('topology');
  const [selectedDevice, setSelectedDevice] = useState<number | null>(null);
  const [scanModalOpen, setScanModalOpen] = useState(false);
  const [activeScanId, setActiveScanId] = useState<number | null>(null);

  const { devices, loading: devicesLoading, refresh: refreshDevices } = useDevices();
  const { scans, refresh: refreshScans } = useScanHistory();
  const scanStream = useScanStream(activeScanId);

  const handleScanStarted = useCallback((scanId: number) => {
    setActiveScanId(scanId);
  }, []);

  // Refresh data when scan completes
  if (scanStream.isComplete && activeScanId) {
    setTimeout(() => {
      refreshDevices();
      refreshScans();
      setActiveScanId(null);
      scanStream.reset();
    }, 1000);
  }

  const handleDeviceSelect = useCallback((id: number) => {
    setSelectedDevice(id);
  }, []);

  return (
    <ToastProvider>
    <div className="flex w-full min-h-screen">
      {/* Sidebar */}
      <aside className="w-56 bg-surface-raised border-r border-border flex flex-col shrink-0">
        <div className="p-5 border-b border-border">
          <h1 className="text-lg font-bold tracking-tight flex items-center gap-2">
            <Network size={20} className="text-accent" />
            NetMapper
          </h1>
        </div>

        <nav className="flex-1 p-3 space-y-1">
          {NAV_ITEMS.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setView(id)}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                view === id
                  ? 'bg-accent/15 text-accent'
                  : 'text-text-secondary hover:text-text-primary hover:bg-surface-overlay'
              }`}
            >
              <Icon size={16} />
              {label}
            </button>
          ))}
        </nav>

        <div className="p-4 border-t border-border">
          <div className="text-xs text-text-secondary space-y-1">
            <div>{devices.length} devices</div>
            <div>{scans.length} scans</div>
          </div>
        </div>
      </aside>

      {/* Main */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top Bar */}
        <header className="h-14 border-b border-border flex items-center justify-between px-5 shrink-0 bg-surface-raised">
          <div className="flex items-center gap-4">
            <CVEStatusBar />
          </div>

          <div className="flex items-center gap-3">
            {activeScanId && !scanStream.isComplete && (
              <div className="flex items-center gap-2 text-xs">
                <div className="w-32 h-1.5 bg-surface-overlay rounded-full overflow-hidden">
                  <div
                    className="h-full bg-accent rounded-full transition-all duration-500"
                    style={{ width: `${scanStream.progress}%` }}
                  />
                </div>
                <span className="text-text-secondary truncate max-w-[200px]">{scanStream.message}</span>
              </div>
            )}

            <button
              onClick={() => setScanModalOpen(true)}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-bold bg-accent hover:bg-accent-hover text-white transition-colors"
            >
              <Radar size={15} />
              New Scan
            </button>
          </div>
        </header>

        {/* Content */}
        <main className="flex-1 relative">
          {devicesLoading && view !== 'timeline' && (
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="w-8 h-8 border-2 border-accent border-t-transparent rounded-full animate-spin" />
            </div>
          )}

          {!devicesLoading && (
            <>
              {view === 'topology' && <TopologyGraph devices={devices} onDeviceSelect={handleDeviceSelect} />}
              {view === 'subnet' && <SubnetView devices={devices} onDeviceSelect={handleDeviceSelect} />}
              {view === 'dashboard' && <RiskDashboard devices={devices} />}
              {view === 'timeline' && <TimelineView scans={scans} />}
              {view === 'settings' && <SettingsView />}
            </>
          )}
        </main>
      </div>

      <DevicePanel deviceId={selectedDevice} onClose={() => setSelectedDevice(null)} />
      <ScanModal open={scanModalOpen} onClose={() => setScanModalOpen(false)} onScanStarted={handleScanStarted} />
    </div>
    </ToastProvider>
  );
}
