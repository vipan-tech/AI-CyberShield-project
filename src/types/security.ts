export type ThreatSeverity = 'Safe' | 'Low' | 'Medium' | 'High' | 'Critical';

export type PhishingVerdict = 'Safe' | 'Suspicious' | 'Malicious';

export type ThemeMode = 'dark' | 'light';

export interface UserProfile {
  id: string;
  name: string;
  email: string;
  organization: string;
  roleTitle: string;
  preferredTheme: ThemeMode;
  createdAt: string;
  lastLoginAt: string;
}

export interface AuthSessionResponse {
  token: string;
  user: UserProfile;
}

export interface PhishingEvidenceItem {
  id: string;
  category: 'URL Structure' | 'DNS & Domain' | 'SSL/TLS' | 'HTTP & Content';
  severity: 'Pass' | 'Info' | 'Warning' | 'Critical';
  title: string;
  evidence: string;
  riskPoints: number;
}

export interface UrlSignalBreakdown {
  normalizedUrl: string;
  hostname: string;
  registrableDomain: string;
  protocol: string;
  port: string;
  pathAndQuery: string;
  isIpLiteral: boolean;
  hasCredentialTrap: boolean;
  isPunycodeOrHomoglyph: boolean;
  isUrlShortener: boolean;
  suspiciousTld: string | null;
  subdomainCount: number;
  urlLength: number;
  impersonatedBrand: string | null;
  matchedKeywords: string[];
}

export interface DnsIntel {
  resolved: boolean;
  ipv4: string[];
  ipv6: string[];
  cname: string[];
  nameservers: string[];
  mxRecords: string[];
  spfRecord: string | null;
  dmarcRecord: string | null;
  hasSpf: boolean;
  hasDmarc: boolean;
  error?: string;
}

export interface RdapIntel {
  checked: boolean;
  registrar: string | null;
  createdAt: string | null;
  updatedAt: string | null;
  expiresAt: string | null;
  domainAgeDays: number | null;
  dnssecSigned: boolean | null;
  error?: string;
}

export interface TlsIntel {
  checked: boolean;
  valid: boolean;
  authorized: boolean;
  authorizationError: string | null;
  protocol: string | null;
  cipher: string | null;
  issuer: string | null;
  subject: string | null;
  subjectAltNames: string[];
  serialNumber: string | null;
  fingerprint256: string | null;
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  selfSigned: boolean;
  error?: string;
}

export interface HttpRedirectHop {
  statusCode: number;
  url: string;
}

export interface HttpIntel {
  checked: boolean;
  finalUrl: string | null;
  statusCode: number | null;
  redirectChain: HttpRedirectHop[];
  crossDomainRedirect: boolean;
  serverHeader: string | null;
  contentType: string | null;
  pageTitle: string | null;
  passwordInputCount: number;
  externalFormAction: string | null;
  hiddenIframeCount: number;
  securityHeaders: {
    hsts: boolean;
    csp: boolean;
    xFrameOptions: boolean;
    xContentTypeOptions: boolean;
    referrerPolicy: boolean;
  };
  error?: string;
}

export interface AiSynthesisInfo {
  status: 'completed' | 'unavailable';
  model?: string;
  narrative?: string;
  recommendations?: string[];
  error?: string;
}

export interface UrlScanResult {
  id: string;
  scannedAt: string;
  durationMs: number;
  verdict: PhishingVerdict;
  riskScore: number;
  threatCategory: string;
  summary: string;
  evidenceItems: PhishingEvidenceItem[];
  recommendations: string[];
  signals: UrlSignalBreakdown;
  dns: DnsIntel;
  rdap: RdapIntel;
  tls: TlsIntel;
  http: HttpIntel;
  aiAssessment: AiSynthesisInfo;
}

export interface BatchUrlScanItem {
  inputUrl: string;
  ok: boolean;
  error?: string;
  result?: UrlScanResult;
}

export interface BatchUrlScanResponse {
  batchId: string;
  scannedAt: string;
  totalDurationMs: number;
  summary: {
    total: number;
    completed: number;
    failed: number;
    safe: number;
    suspicious: number;
    malicious: number;
  };
  items: BatchUrlScanItem[];
}

export interface ExtractedIoc {
  value: string;
  type: 'IPv4' | 'URL' | 'Domain' | 'Email' | 'Hash' | 'CVE';
  riskLevel: 'Informational' | 'Suspicious' | 'Malicious';
  note: string;
}

export interface MitreTechnique {
  id: string;
  tactic: string;
  name: string;
}

export interface ThreatAnalysisResult {
  id: string;
  analyzedAt: string;
  contextType: string;
  inputPreview: string;
  severity: 'Benign' | 'Low' | 'Medium' | 'High' | 'Critical';
  riskScore: number;
  threatCategory: string;
  attackVector: string;
  summary: string;
  indicators: ExtractedIoc[];
  mitreTechniques: MitreTechnique[];
  remediationSteps: string[];
}

export interface SecurityAlert {
  id: string;
  createdAt: string;
  source: 'Phishing Detector' | 'Multi-URL Scanner' | 'Password Auditor' | 'Threat Analyzer';
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  title: string;
  description: string;
  target: string;
  status: 'Open' | 'Acknowledged' | 'Resolved';
}

export interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
}

export interface KevFeedResponse {
  catalogVersion: string;
  dateReleased: string;
  totalCount: number;
  vulnerabilities: KevEntry[];
}

export interface PasswordBreachCheckResponse {
  prefix: string;
  suffixes: Array<{ suffix: string; count: number }>;
}

export interface PasswordAuditSummary {
  id: string;
  auditedAt: string;
  label: string;
  strengthLabel: 'Very Weak' | 'Weak' | 'Fair' | 'Strong' | 'Very Strong';
  score: number;
  entropyBits: number;
  breachCount: number | null;
}

export interface UserHistoryPayload {
  urlScans: UrlScanResult[];
  threatAnalyses: ThreatAnalysisResult[];
  passwordAudits: PasswordAuditSummary[];
  alerts: SecurityAlert[];
}
