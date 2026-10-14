// Mirrors the backend DTOs in backend/app/pipeline/models.py,
// backend/app/risk_engine/models.py and backend/app/integrations/models.py.

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";

export type ArtifactCategory = "ipv4" | "ipv6" | "urls" | "domains" | "emails" | "phone_numbers";

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

export interface RiskFinding {
  finding_id: string;
  title: string;
  description: string;
  severity?: Severity | string;
  score_impact: number;
  artifact: string | null;
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
  timestamp: string;
  execution_time_ms: number;
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
