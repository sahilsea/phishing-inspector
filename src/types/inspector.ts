export type MetricStatus = 'SAFE' | 'WARNING' | 'CRITICAL';
export type ClauseCategory = 'FINANCIAL' | 'DOMAIN' | 'DARK_PATTERN';
export type ClauseSeverity = 'CRITICAL' | 'WARNING';
export type ThreatVerdict = 'Clean Offer' | 'Suspicious (Gray Zone)' | 'Critical Danger';
export type ActionMandateLevel = 'SAFE' | 'CRITICAL';

export interface MetricScore {
  score: number;
  label: string;
  detail: string;
  status: MetricStatus;
}

export interface FlaggedClause {
  id: string;
  text: string;
  category: ClauseCategory;
  severity: ClauseSeverity;
  explanation: string;
  offset?: string;
  tag?: string;
}

export interface ScanPayload {
  type: 'text' | 'url';
  content: string;
}

export interface ActionMandate {
  title: string;
  recommendation: string;
  level: ActionMandateLevel;
}

export interface ScanResult {
  threatIndex: number;
  verdict: ThreatVerdict;
  confidence: number;
  analysisTimeSec: number;
  domainTrust: MetricScore;
  financialTrap: MetricScore;
  darkPatterns: MetricScore;
  flaggedClauses: FlaggedClause[];
  actionMandate: ActionMandate;
  summaryAnalysis?: string;
  aiPowered?: boolean;
}
