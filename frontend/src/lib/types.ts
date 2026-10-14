// Mirrors the backend DTOs in backend/app/pipeline/models.py,
// backend/app/risk_engine/models.py and backend/app/integrations/models.py.

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";

export type ArtifactCategory = "ipv4" | "ipv6" | "urls" | "domains" | "emails" | "phone_numbers" | "hashes";

export type StageStatus = "PENDING" | "RUNNING" | "COMPLETED" | "FAILED" | "SKIPPED";

export type LookupStatus =
  | "SUCCESS"
  | "PARTIAL"
  | "FAILED"
  | "RATE_LIMITED"
  | "UNAVAILABLE"
  | "UNSUPPORTED";

export interface StageMetric {
  stage_name: string;
  status: StageStatus;
  duration_ms: number;
  error: string | null;
}

export interface ValidationResult {
  valid: boolean;
  artifact: string;
  artifact_type: string;
  properties?: Record<string, unknown>;
  reason?: string | null;
  [key: string]: unknown;
}

export interface ThreatIndicator {
  category: string;
  severity: string;
  description: string | null;
  tags: string[];
}

export interface ThreatIntelResponse {
  provider: string;
  artifact: string;
  artifact_type: string;
  status: LookupStatus;
  confidence: number;
  threat_indicators: ThreatIndicator[];
  raw_data: Record<string, unknown>;
  timestamp: string;
  latency_ms: number;
  error_message: string | null;
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  url: string;
}

export interface CweReference {
  id: string;
  name: string;
  url: string;
}

export interface RiskFinding {
  finding_id: string;
  title: string;
  description: string;
  severity?: Severity | string;
  score_impact: number;
  artifact: string | null;
  rule_id?: string | null;
  categories?: string[];
  mitre_techniques?: MitreTechnique[];
  cwes?: CweReference[];
}

export interface AppliedRule {
  rule_id: string;
  rule_name: string;
  description: string;
  weight: number;
  severity: Severity | string;
  matched: boolean;
  evidence_context: Record<string, unknown>;
}

export interface RiskAssessment {
  total_score: number;
  severity: Severity;
  confidence: number;
  findings: RiskFinding[];
  applied_rules: AppliedRule[];
  artifact_breakdown: Record<string, number>;
  classification: string;
  threat_categories: string[];
  mitre_techniques: MitreTechnique[];
  timestamp: string;
  execution_time_ms: number;
}

export interface AnalystReport {
  summary: string;
  key_findings: string[];
  recommended_actions: string[];
  generated_by: "claude" | "template";
  model: string | null;
  note: string | null;
  disclaimer: string;
}

export interface FileAnalysis {
  filename: string;
  extension: string;
  size: number;
  kind: string;
  mime: string;
  md5: string;
  sha1: string;
  sha256: string;
  dangerous: boolean;
  extension_mismatch?: boolean;
  qr_payloads?: string[];
  ocr?: { available: boolean; characters: number; note?: string; error?: string };
  pdf?: { pages: number; metadata: Record<string, string>; links: string[]; active_content: string[]; error?: string };
  apk?: {
    package: string | null;
    permissions: string[];
    dangerous_permissions: string[];
    embedded_urls: string[];
    file_count?: number;
    has_native_code?: boolean;
    error?: string;
  };
}

export interface EmailAnalysis {
  subject: string;
  from: string | null;
  display_name: string | null;
  from_domain: string | null;
  to: string[];
  reply_to: string | null;
  return_path: string | null;
  date: string | null;
  message_id: string | null;
  authentication: Record<string, string>;
  received_ips: string[];
  links: string[];
  attachments: (FileAnalysis & { content_type: string })[];
}

export interface IngestionAnalysis {
  file?: FileAnalysis;
  email?: EmailAnalysis;
}

export interface RiskSummary {
  total_score: number;
  severity: Severity;
  confidence: number;
  findings_count: number;
}

export type Evidence = Partial<Record<ArtifactCategory, string[]>>;

export interface InvestigationResult {
  investigation_id: string;
  status: "success" | "partial_success" | "failed";
  duration_ms: number;
  pipeline_version: string;
  source_type: string;
  source_name: string | null;
  input_preview: string;
  ingestion: IngestionAnalysis;
  analyst_report: AnalystReport | null;
  evidence_summary: Record<string, number> | null;
  validation_summary: Record<string, number> | null;
  threat_summary: Record<string, number> | null;
  risk_summary: RiskSummary | null;
  evidence: Evidence;
  normalized_evidence: Evidence;
  validation_results: Partial<Record<ArtifactCategory, ValidationResult[]>>;
  threat_intelligence: Partial<Record<ArtifactCategory, ThreatIntelResponse[]>>;
  risk_assessment: RiskAssessment | null;
  warnings: string[];
  errors: string[];
  execution_metrics: StageMetric[];
  timestamp: string;
}

export interface InvestigationRequest {
  text: string;
  refang: boolean;
  source_type?: string;
  metadata?: Record<string, unknown>;
}

export interface HealthResponse {
  status: string;
  app_name: string;
  version: string;
  environment: string;
}

export interface InvestigationSummary {
  investigation_id: string;
  created_at: string;
  status: string;
  source_type: string;
  source_name: string | null;
  input_preview: string;
  score: number;
  severity: Severity;
  classification: string;
  ioc_count: number;
}

export interface InvestigationList {
  total: number;
  items: InvestigationSummary[];
}

export interface InvestigationStats {
  total: number;
  last_7_days: number;
  average_score: number;
  by_severity: Record<Severity, number>;
  top_classifications: { classification: string; count: number }[];
}

export interface ProviderStatus {
  name: string;
  enabled: boolean;
  requires_key: boolean;
  key_setting: string | null;
  artifact_types: string[];
  docs_url: string;
}

export interface Capabilities {
  version: string;
  environment: string;
  auth_enabled: boolean;
  rate_limit_per_minute: number;
  persistence: boolean;
  analyst: { mode: "claude" | "template"; model: string | null };
  ingestion: { max_upload_mb: number; qr_decoding: boolean; ocr: boolean; file_types: string[] };
  threat_intel: ProviderStatus[];
  rules: { id: string; name: string; severity: Severity; weight: number; enabled: boolean }[];
}

export type ReportFormat = "json" | "stix" | "markdown" | "pdf";
