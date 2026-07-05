export interface PacketRow {
  stt: number; ts: number;
  src: string; dst: string;
  src_port: number; dst_port: number;
  proto: string; len: number; info: string;
}
export interface CaptureStatus {
  running: boolean; paused: boolean;
  interface: string | null; uptime: number;
  packets: number; bytes: number; dropped: number;
  pps: number; bps: number;
  protocols: Record<string, number>;
  ws_drop_total?: number;
}
export interface InterfaceInfo { name: string; exists: boolean; ipv4: string; mac: string; up: boolean; }
export interface Conversation { proto: string; src: string; dst: string; sport: number; dport: number; packets: number; bytes: number; duration: number; }
export interface ServiceStatus { name: string; active: boolean; }
export interface KafkaTopic { name: string; partitions: number; replication: number; }
export interface KafkaLag { group: string; total_lag: number; partitions: { topic: string; partition: number; lag: number }[]; }
export interface Counts {
  flows_all?: number; flows_dos?: number; flows_exploits?: number;
  flows_fuzzers?: number; flows_generic?: number; flows_analysis?: number;
  flows_reconnaissance?: number; flows_shellcode?: number; pipeline_runs?: number;
}
export interface PcapFile { name: string; size: number; mtime: number; }
export interface SystemInfo {
  hostname: string; uptime_seconds: number; loadavg: number[];
  cpu_count: number; mem_total_mb: number; mem_available_mb: number;
  disk_total_gb: number; disk_used_gb: number; nic_count: number;
}
export interface LastConfig {
  interface: string; bpf_filter: string; snaplen: number;
  promisc: boolean; auto_restore: boolean; saved_at: string;
}
export interface WSMessage<T> { type: string; data: T; }

// --- Dashboard summary (new) ----------------------------------------------
export interface AlertItem {
  alert_id: string;
  label: string;
  src?: string; dst?: string;
  sport?: number; dport?: number;
  proto?: string;
  priority?: string;            // 'low' | 'medium' | 'high' | 'critical'
  category?: string;
  ts_sec?: number;
  received_at?: number;         // epoch s when the alert was ingested
  details?: Record<string, unknown>;
}
export interface RateHistory {
  pps: number[];
  bps: number[];
  ts: number[];
}
export interface TopTalker {
  proto: string;
  src: string;                  // "ip:port"
  dst: string;                  // "ip:port"
  packets: number;
  bytes: number;
  duration: number;
}
export interface DashboardSummary {
  capture: CaptureStatus;
  services: ServiceStatus[];
  counts: Counts;
  protocols: Record<string, number>;
  top_talkers: TopTalker[];
  alerts_recent: AlertItem[];
  rate_history: RateHistory;
  grafana_url: string;          // "" if not configured
  generated_at: number;
}

// --- Integrations credentials (new) ---------------------------------------
export interface IntegrationCredential {
  url: string;
  username: string;
  password: string | null;
  password_hint?: string;
  note?: string;
  dashboard_path?: string;      // grafana only
  native_port?: number;         // clickhouse only
  protocol?: string;            // kafka only
}
export interface IntegrationsPayload {
  sniff_web: IntegrationCredential;
  grafana:   IntegrationCredential;
  clickhouse: IntegrationCredential;
  kafka:     IntegrationCredential;
}
