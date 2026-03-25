export type DeviceType =
  | 'router' | 'server' | 'workstation' | 'mobile' | 'iot' | 'printer' | 'unknown';

export type ScanProfile = 'quick' | 'standard' | 'deep';
export type ScanStatus = 'running' | 'completed' | 'failed';
export type RiskSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface Device {
  id: number;
  mac_address: string;
  ip_address: string;
  hostname: string | null;
  vendor: string | null;
  device_type: DeviceType;
  os_guess: string | null;
  os_accuracy: number | null;
  risk_score: number;
  first_seen_scan: number;
  last_seen_scan: number;
}

export interface OpenPort {
  port: number;
  protocol: string;
  state: string;
  service: string | null;
  version: string | null;
  risk_flag: 'unexpected' | 'outdated' | 'critical' | null;
}

export interface CVEMatch {
  cve_id: string;
  cvss_score: number | null;
  severity: RiskSeverity;
  description: string;
  port: number;
  service: string | null;
  version: string | null;
}

export interface DeviceDetail extends Device {
  ports: OpenPort[];
  cve_matches: CVEMatch[];
  risk_summary: string;
}

export interface ScanRun {
  id: number;
  started_at: string;
  completed_at: string | null;
  target_cidr: string;
  profile: ScanProfile;
  status: ScanStatus;
  host_count: number;
  error_msg: string | null;
}

export interface ScanDelta {
  scan_run_id: number;
  new_devices: Device[];
  disappeared_devices: Device[];
  changed_devices: Array<{ device: Device; changes: string[] }>;
}

export interface ScanProgressEvent {
  type: 'arp_complete' | 'host_scanned' | 'classification_done' | 'complete' | 'error';
  message: string;
  hosts_found?: number;
  hosts_total?: number;
  current_host?: string;
}

export interface CVEIndexStatus {
  download_complete: boolean;
  last_updated: string | null;
  cve_count: number;
  downloading: boolean;
  download_progress: number | null;
}

export interface ApiResponse<T> {
  success: boolean;
  data: T;
  meta: { request_id: string; timestamp: string };
}
