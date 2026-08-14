/**
 * Types mirroring the backend's v1 schemas.
 *
 * Hand-written rather than generated, and deliberately narrow: these describe
 * what the dashboard reads, not the whole surface. Enum members are string
 * unions matching the values PostgreSQL stores, so a value that drifts shows up
 * as a type error rather than an empty badge.
 */

export type UserRole = "admin" | "analyst" | "viewer";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type IncidentStatus = "open" | "investigating" | "resolved";

export type IncidentPriority = "p1" | "p2" | "p3" | "p4";

export type AttackType =
  | "brute_force"
  | "credential_access"
  | "privilege_escalation"
  | "lateral_movement"
  | "malware"
  | "ransomware"
  | "phishing"
  | "data_exfiltration"
  | "denial_of_service"
  | "reconnaissance"
  | "insider_threat"
  | "policy_violation"
  | "misconfiguration"
  | "unknown"
  | "other";

export type AnomalyType =
  | "statistical"
  | "behavioral"
  | "signature"
  | "correlation"
  | "threshold"
  | "machine_learning";

export type AnomalyStatus =
  | "new"
  | "triaged"
  | "investigating"
  | "confirmed"
  | "false_positive"
  | "dismissed";

export type LogSourceStatus = "pending" | "active" | "paused" | "error" | "disabled";

export type LogSourceType =
  | "syslog"
  | "firewall"
  | "ids"
  | "endpoint"
  | "cloud_trail"
  | "application"
  | "authentication"
  | "network_flow"
  | "database"
  | "other";

export type ReportStatus =
  | "draft"
  | "in_review"
  | "approved"
  | "published"
  | "archived";

export interface User {
  id: string;
  email: string;
  username: string;
  full_name: string | null;
  role: UserRole;
  is_active: boolean;
  created_at: string;
  last_login_at: string | null;
}

export interface TokenResponse {
  access_token: string;
  token_type: "bearer";
  expires_in: number;
  user: User;
}

export interface LinkedAnomaly {
  id: string;
  title: string;
  anomaly_type: AnomalyType;
  severity: Severity;
  score: number;
  detector: string;
  detected_at: string;
}

export interface IncidentNote {
  id: string;
  incident_id: string;
  author_id: string | null;
  author_username: string | null;
  body: string;
  is_system: boolean;
  created_at: string;
}

export interface IncidentSummary {
  id: string;
  number: number;
  reference: string;
  title: string;
  summary: string | null;
  status: IncidentStatus;
  severity: Severity;
  priority: IncidentPriority;
  attack_type: AttackType;
  assigned_to_id: string | null;
  created_by_id: string | null;
  detected_at: string;
  acknowledged_at: string | null;
  resolved_at: string | null;
  sla_due_at: string | null;
  tags: string[];
  created_at: string;
  updated_at: string;
}

export interface Incident extends IncidentSummary {
  description: string | null;
  affected_assets: Record<string, unknown>[];
  indicators: Record<string, unknown>[];
  mitre_techniques: string[];
  context: Record<string, unknown>;
  anomalies: LinkedAnomaly[];
  notes: IncidentNote[];
}

export interface Anomaly {
  id: string;
  log_source_id: string | null;
  log_entry_id: string | null;
  title: string;
  description: string | null;
  anomaly_type: AnomalyType;
  severity: Severity;
  status: AnomalyStatus;
  score: number;
  confidence: number | null;
  detector: string;
  detector_version: string | null;
  detected_at: string;
  evidence: Record<string, unknown>;
  features: Record<string, unknown>;
  mitre_techniques: string[];
  created_at: string;
}

export interface LogSource {
  id: string;
  name: string;
  description: string | null;
  source_type: LogSourceType;
  status: LogSourceStatus;
  vendor: string | null;
  hostname: string | null;
  ip_address: string | null;
  timezone: string;
  is_enabled: boolean;
  tags: string[];
  events_ingested: number;
  last_ingested_at: string | null;
  last_error: string | null;
  created_at: string;
  updated_at: string;
}

export interface LogEntry {
  id: string;
  log_source_id: string;
  event_timestamp: string;
  ingested_at: string;
  severity: Severity;
  category: string | null;
  event_type: string | null;
  action: string | null;
  outcome: string | null;
  message: string;
  host: string | null;
  process: string | null;
  username: string | null;
  source_ip: string | null;
  source_port: number | null;
  destination_ip: string | null;
  destination_port: number | null;
  protocol: string | null;
  attributes: Record<string, unknown>;
}

export interface RecommendedAction {
  action: string;
  priority: string;
  rationale: string | null;
}

/** The structured half of an AI report, as stored in `sections`. */
export interface ReportSections {
  summary?: string;
  attack_type?: string;
  severity?: string;
  evidence?: string[];
  likely_cause?: string;
  confidence?: number;
}

export interface IncidentReport {
  id: string;
  incident_id: string;
  author_id: string | null;
  title: string;
  version: number;
  status: ReportStatus;
  format: string;
  executive_summary: string | null;
  content: string;
  sections: ReportSections;
  recommendations: RecommendedAction[];
  is_ai_generated: boolean;
  generation_metadata: Record<string, unknown>;
  published_at: string | null;
  created_at: string;
}

export type IngestionStatus =
  | "pending"
  | "running"
  | "completed"
  | "partial"
  | "failed";

/** One rejected record, located by its line in the uploaded file. */
export interface RowError {
  line: number;
  field: string | null;
  reason: string;
}

export interface IngestionJob {
  id: string;
  log_source_id: string;
  filename: string;
  content_type: string | null;
  size_bytes: number;
  format: string;
  status: IngestionStatus;
  total_records: number;
  accepted_records: number;
  rejected_records: number;
  errors: RowError[];
  error_detail: string | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
}

/** Counts describing one detection run. */
export interface AnalysisSummary {
  entries_analysed: number;
  findings: number;
  persisted: number;
  duplicates_skipped: number;
  by_severity: Record<string, number>;
  truncated: boolean;
}

export interface Finding {
  detector: string;
  detector_version: string;
  anomaly_type: AnomalyType;
  severity: Severity;
  score: number;
  title: string;
  reason: string;
  log_entry_id: string | null;
}

export interface AnalyzeResponse {
  window_start: string;
  window_end: string;
  log_source_id: string | null;
  detectors_run: string[];
  summary: AnalysisSummary;
  findings: Finding[];
  anomalies: Anomaly[];
}

export interface CountByKey {
  key: string;
  count: number;
}

export interface CountByDay {
  day: string;
  count: number;
}

export interface DashboardStats {
  incidents_total: number;
  incidents_open: number;
  incidents_investigating: number;
  incidents_resolved: number;
  anomalies_total: number;
  log_sources_total: number;
  log_entries_total: number;
  incidents_by_severity: CountByKey[];
  incidents_by_attack_type: CountByKey[];
  incidents_over_time: CountByDay[];
  anomalies_by_type: CountByKey[];
  anomalies_by_severity: CountByKey[];
}
