import type {
  PasswordAuditSummary,
  SecurityAlert,
  ThemeMode,
  ThreatAnalysisResult,
  UrlScanResult,
} from '../types/security';

const KEYS = {
  urlScans: 'aicybershield_url_scans_v2',
  threatAnalyses: 'aicybershield_threat_analyses_v1',
  passwordAudits: 'aicybershield_password_audits_v1',
  alerts: 'aicybershield_alerts_v1',
  theme: 'aicybershield_theme_v1',
};

function safeRead<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return fallback;
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

function safeWrite<T>(key: string, value: T): void {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // Ignore storage quota errors cleanly
  }
}

export function loadUrlScans(): UrlScanResult[] {
  return safeRead<UrlScanResult[]>(KEYS.urlScans, []);
}

export function saveUrlScans(scans: UrlScanResult[]): void {
  safeWrite(KEYS.urlScans, scans.slice(0, 25));
}

export function loadThreatAnalyses(): ThreatAnalysisResult[] {
  return safeRead<ThreatAnalysisResult[]>(KEYS.threatAnalyses, []);
}

export function saveThreatAnalyses(items: ThreatAnalysisResult[]): void {
  safeWrite(KEYS.threatAnalyses, items.slice(0, 25));
}

export function loadPasswordAudits(): PasswordAuditSummary[] {
  return safeRead<PasswordAuditSummary[]>(KEYS.passwordAudits, []);
}

export function savePasswordAudits(items: PasswordAuditSummary[]): void {
  safeWrite(KEYS.passwordAudits, items.slice(0, 25));
}

export function loadSecurityAlerts(): SecurityAlert[] {
  return safeRead<SecurityAlert[]>(KEYS.alerts, []);
}

export function saveSecurityAlerts(alerts: SecurityAlert[]): void {
  safeWrite(KEYS.alerts, alerts.slice(0, 50));
}

export function loadThemeMode(): ThemeMode {
  try {
    const saved = localStorage.getItem(KEYS.theme);
    if (saved === 'light' || saved === 'dark') return saved;
  } catch {
    // Ignore
  }
  return 'dark';
}

export function saveThemeMode(theme: ThemeMode): void {
  try {
    localStorage.setItem(KEYS.theme, theme);
  } catch {
    // Ignore
  }
}
