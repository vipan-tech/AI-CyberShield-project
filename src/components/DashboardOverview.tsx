import { useState, type FormEvent } from 'react';
import {
  Activity,
  ArrowRight,
  BellRing,
  Globe,
  KeyRound,
  Radar,
  ShieldCheck,
} from 'lucide-react';
import type {
  PasswordAuditSummary,
  SecurityAlert,
  ThreatAnalysisResult,
  UrlScanResult,
  UserProfile,
} from '../types/security';
import { SeverityIndicator, getScoreAccentClass } from './SeverityIndicator';

export type NavTab =
  | 'overview'
  | 'phishing'
  | 'multiurl'
  | 'passwords'
  | 'threats'
  | 'stats'
  | 'alerts'
  | 'profile';

interface DashboardOverviewProps {
  user: UserProfile | null;
  urlScans: UrlScanResult[];
  threatAnalyses: ThreatAnalysisResult[];
  passwordAudits: PasswordAuditSummary[];
  alerts: SecurityAlert[];
  onNavigate: (tab: NavTab) => void;
  onQuickScanUrl: (url: string) => void;
  onAcknowledgeAlert: (id: string) => void;
}

export function DashboardOverview({
  user,
  urlScans,
  threatAnalyses,
  passwordAudits,
  alerts,
  onNavigate,
  onQuickScanUrl,
  onAcknowledgeAlert,
}: DashboardOverviewProps) {
  const [quickUrl, setQuickUrl] = useState('');

  const threatsDetected =
    urlScans.filter((s) => s.verdict !== 'Safe').length +
    threatAnalyses.filter((t) => t.severity === 'High' || t.severity === 'Critical' || t.severity === 'Medium').length;

  const openAlerts = alerts.filter((a) => a.status === 'Open');
  const breachedPasswords = passwordAudits.filter((p) => (p.breachCount ?? 0) > 0).length;

  const safeScans = urlScans.filter((s) => s.verdict === 'Safe').length;
  const suspiciousScans = urlScans.filter((s) => s.verdict === 'Suspicious').length;
  const maliciousScans = urlScans.filter((s) => s.verdict === 'Malicious').length;
  const totalScans = urlScans.length;

  const handleQuickSubmit = (e: FormEvent) => {
    e.preventDefault();
    const trimmed = quickUrl.trim();
    if (!trimmed) return;
    onQuickScanUrl(trimmed);
    setQuickUrl('');
  };

  return (
    <div className="space-y-6">
      {/* Hero Command Strip & Instant URL Check */}
      <section className="neon-panel rounded-2xl p-5 sm:p-7 relative overflow-hidden">
        <div
          className="pointer-events-none absolute -top-24 -right-24 w-72 h-72 rounded-full bg-sky-500/10 blur-3xl"
          aria-hidden="true"
        />
        <div className="relative flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
          <div className="max-w-xl">
            <p className="text-xs font-medium text-sky-600 dark:text-sky-400 tracking-wide mb-1.5">
              {user ? `Welcome back, ${user.name}` : 'Security Command Center'}
            </p>
            <h1 className="text-2xl sm:text-3xl font-bold text-slate-900 dark:text-slate-50 tracking-tight text-balance">
              Inspect URLs, audit passwords, and triage active threats.
            </h1>
            <p className="mt-2 text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
              Every check runs live DNS, RDAP domain-age, SSL/TLS certificate, HTTP header, and breach-database verification with downloadable PDF reports.
            </p>
          </div>

          <form onSubmit={handleQuickSubmit} className="w-full lg:max-w-md shrink-0">
            <label htmlFor="quick-url-input" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-2">
              Quick Phishing URL Scan
            </label>
            <div className="flex flex-col sm:flex-row gap-2.5">
              <input
                id="quick-url-input"
                type="text"
                inputMode="url"
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
                value={quickUrl}
                onChange={(e) => setQuickUrl(e.target.value)}
                placeholder="https://example.com/login"
                className="flex-1 min-h-[44px] px-3.5 py-2.5 rounded-xl bg-slate-50 dark:bg-slate-950/80 border border-slate-300 dark:border-sky-500/25 text-sm font-mono text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:outline-none focus:border-sky-500 focus:ring-2 focus:ring-sky-500/25"
              />
              <button
                type="submit"
                disabled={!quickUrl.trim()}
                className="neon-btn-primary min-h-[44px] px-5 py-2.5 rounded-xl text-sm font-semibold text-white whitespace-nowrap shrink-0 inline-flex items-center justify-center gap-2 transition-all disabled:opacity-45 disabled:cursor-not-allowed cursor-pointer"
              >
                <Globe className="w-4 h-4" aria-hidden="true" />
                <span>Scan URL</span>
              </button>
            </div>
          </form>
        </div>
      </section>

      {/* 4-Column KPI Strip */}
      <section className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4" aria-label="Security metrics summary">
        <button
          type="button"
          onClick={() => onNavigate('phishing')}
          className="neon-panel rounded-2xl p-4 sm:p-5 text-left hover:border-sky-400/50 transition-colors cursor-pointer group"
        >
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 text-xs font-medium">
            <span>URLs Scanned</span>
            <Globe className="w-4 h-4 text-sky-600 dark:text-sky-400 group-hover:scale-105 transition-transform" aria-hidden="true" />
          </div>
          <p className="mt-2.5 text-2xl sm:text-3xl font-bold font-mono tabular-nums text-slate-900 dark:text-slate-50">
            {urlScans.length}
          </p>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400 tabular-nums">
            {maliciousScans} malicious · {suspiciousScans} suspicious
          </p>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('threats')}
          className="neon-panel rounded-2xl p-4 sm:p-5 text-left hover:border-sky-400/50 transition-colors cursor-pointer group"
        >
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 text-xs font-medium">
            <span>Threats Flagged</span>
            <Radar className="w-4 h-4 text-sky-600 dark:text-sky-400 group-hover:scale-105 transition-transform" aria-hidden="true" />
          </div>
          <p className="mt-2.5 text-2xl sm:text-3xl font-bold font-mono tabular-nums text-slate-900 dark:text-slate-50">
            {threatsDetected}
          </p>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400 tabular-nums">
            {threatAnalyses.length} total threat reports
          </p>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('passwords')}
          className="neon-panel rounded-2xl p-4 sm:p-5 text-left hover:border-sky-400/50 transition-colors cursor-pointer group"
        >
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 text-xs font-medium">
            <span>Password Audits</span>
            <KeyRound className="w-4 h-4 text-sky-600 dark:text-sky-400 group-hover:scale-105 transition-transform" aria-hidden="true" />
          </div>
          <p className="mt-2.5 text-2xl sm:text-3xl font-bold font-mono tabular-nums text-slate-900 dark:text-slate-50">
            {passwordAudits.length}
          </p>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400 tabular-nums">
            {breachedPasswords} exposed in breaches
          </p>
        </button>

        <button
          type="button"
          onClick={() => onNavigate('alerts')}
          className="neon-panel rounded-2xl p-4 sm:p-5 text-left hover:border-sky-400/50 transition-colors cursor-pointer group"
        >
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 text-xs font-medium">
            <span>Open Alerts</span>
            <BellRing className="w-4 h-4 text-sky-600 dark:text-sky-400 group-hover:scale-105 transition-transform" aria-hidden="true" />
          </div>
          <p
            className={`mt-2.5 text-2xl sm:text-3xl font-bold font-mono tabular-nums ${
              openAlerts.length > 0 ? 'text-amber-600 dark:text-amber-400' : 'text-emerald-600 dark:text-emerald-400'
            }`}
          >
            {openAlerts.length}
          </p>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400 tabular-nums">
            {alerts.length} recorded events
          </p>
        </button>
      </section>

      {/* Main 2-Column Workspace Split */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
        <section className="lg:col-span-7 neon-panel rounded-2xl p-5 sm:p-6 flex flex-col justify-between gap-6">
          <div>
            <div className="flex items-center justify-between gap-4 mb-4">
              <div>
                <h2 className="text-base sm:text-lg font-semibold text-slate-900 dark:text-slate-50">Core Security Modules</h2>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                  Launch any inspection or analytics workflow
                </p>
              </div>
              <Activity className="w-4 h-4 text-sky-600 dark:text-sky-400 shrink-0" aria-hidden="true" />
            </div>

            <div className="divide-y divide-slate-200 dark:divide-slate-800/80 border-y border-slate-200 dark:border-slate-800/80">
              {[
                {
                  tab: 'phishing' as const,
                  title: 'Phishing URL Detector',
                  desc: 'Checks DNS, RDAP domain age, SSL/TLS certificates, HTTP forms, and phishing indicators',
                },
                {
                  tab: 'multiurl' as const,
                  title: 'Multi-URL Batch Scanner',
                  desc: 'Scan up to 10 URLs simultaneously with CSV and PDF batch exports',
                },
                {
                  tab: 'passwords' as const,
                  title: 'Password Strength & Breach Auditor',
                  desc: 'Entropy math, crack-time estimates, k-anonymity breach lookup, and CSPRNG generator',
                },
                {
                  tab: 'threats' as const,
                  title: 'Cyber Threat Analyzer',
                  desc: 'Extracts IOCs, maps MITRE ATT&CK tactics, and generates containment PDFs',
                },
                {
                  tab: 'stats' as const,
                  title: 'Advanced Security Statistics',
                  desc: 'Risk trend charts, verdict distribution, and DNS/TLS compliance analytics',
                },
              ].map((mod) => (
                <button
                  key={mod.tab}
                  type="button"
                  onClick={() => onNavigate(mod.tab)}
                  className="w-full py-3.5 flex items-center justify-between gap-4 text-left hover:bg-sky-500/5 px-2 -mx-2 rounded-lg transition-colors cursor-pointer"
                >
                  <div className="min-w-0">
                    <p className="text-sm font-semibold text-slate-900 dark:text-slate-100">{mod.title}</p>
                    <p className="text-xs text-slate-600 dark:text-slate-400 mt-0.5">{mod.desc}</p>
                  </div>
                  <span className="inline-flex items-center gap-1 text-xs font-medium text-sky-600 dark:text-sky-400 whitespace-nowrap shrink-0">
                    <span>Open</span>
                    <ArrowRight className="w-3.5 h-3.5" aria-hidden="true" />
                  </span>
                </button>
              ))}
            </div>
          </div>

          {/* URL Verdict Distribution Bar */}
          <div>
            <div className="flex items-center justify-between text-xs mb-2">
              <span className="font-medium text-slate-700 dark:text-slate-300">URL Scan Verdict Breakdown</span>
              <span className="font-mono tabular-nums text-slate-500 dark:text-slate-400">
                {totalScans === 0 ? 'No scans yet' : `${totalScans} total`}
              </span>
            </div>
            <div className="h-2.5 w-full rounded-full bg-slate-200 dark:bg-slate-900 border border-slate-300 dark:border-slate-800 overflow-hidden flex">
              {totalScans === 0 ? (
                <div className="w-full bg-slate-200 dark:bg-slate-800/60" />
              ) : (
                <>
                  <div
                    className="bg-emerald-500 transition-all"
                    style={{ width: `${(safeScans / totalScans) * 100}%` }}
                  />
                  <div
                    className="bg-amber-500 transition-all"
                    style={{ width: `${(suspiciousScans / totalScans) * 100}%` }}
                  />
                  <div
                    className="bg-rose-500 transition-all"
                    style={{ width: `${(maliciousScans / totalScans) * 100}%` }}
                  />
                </>
              )}
            </div>
            <div className="mt-2.5 flex flex-wrap items-center gap-4 text-xs text-slate-600 dark:text-slate-400 tabular-nums">
              <span>Safe: {safeScans}</span>
              <span aria-hidden="true">·</span>
              <span>Suspicious: {suspiciousScans}</span>
              <span aria-hidden="true">·</span>
              <span>Malicious: {maliciousScans}</span>
            </div>
          </div>
        </section>

        {/* Right: Active Security Alerts & Recent Scans */}
        <section className="lg:col-span-5 neon-panel rounded-2xl p-5 sm:p-6 flex flex-col justify-between gap-5">
          <div>
            <div className="flex items-center justify-between gap-4 mb-4">
              <div>
                <h2 className="text-base sm:text-lg font-semibold text-slate-900 dark:text-slate-50">Active Security Alerts</h2>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                  Findings flagged during your sessions
                </p>
              </div>
              <button
                type="button"
                onClick={() => onNavigate('alerts')}
                className="text-xs font-medium text-sky-600 dark:text-sky-400 hover:text-sky-500 whitespace-nowrap shrink-0 cursor-pointer py-1 px-2"
              >
                View All
              </button>
            </div>

            {openAlerts.length === 0 ? (
              <div className="py-8 text-center border border-dashed border-slate-300 dark:border-slate-800 rounded-xl px-4">
                <ShieldCheck className="w-8 h-8 text-emerald-500 mx-auto mb-2.5" aria-hidden="true" />
                <p className="text-sm font-medium text-slate-800 dark:text-slate-200">No Open Alerts</p>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 max-w-xs mx-auto">
                  Malicious URLs, breached passwords, and high-severity threats will automatically appear here.
                </p>
                <button
                  type="button"
                  onClick={() => onNavigate('alerts')}
                  className="mt-4 px-4 py-2 rounded-lg bg-slate-100 hover:bg-slate-200 dark:bg-slate-800/90 dark:hover:bg-slate-800 text-xs font-medium text-sky-700 dark:text-sky-300 transition-colors cursor-pointer"
                >
                  Browse Live CISA Advisories
                </button>
              </div>
            ) : (
              <ul className="divide-y divide-slate-200 dark:divide-slate-800/80">
                {openAlerts.slice(0, 4).map((alert) => (
                  <li key={alert.id} className="py-3.5 first:pt-0 last:pb-0">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400 mb-1">
                          <SeverityIndicator level={alert.severity} />
                          <span aria-hidden="true">·</span>
                          <span className="truncate">{alert.source}</span>
                        </div>
                        <p className="text-sm font-medium text-slate-900 dark:text-slate-100 truncate">{alert.title}</p>
                        <p className="text-xs text-slate-600 dark:text-slate-400 mt-0.5 line-clamp-2">{alert.description}</p>
                      </div>
                      <button
                        type="button"
                        onClick={() => onAcknowledgeAlert(alert.id)}
                        className="min-h-[36px] px-3 py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-xs font-medium text-slate-800 dark:text-slate-200 whitespace-nowrap shrink-0 transition-colors cursor-pointer"
                      >
                        Acknowledge
                      </button>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>

          {/* Latest Scan Snapshot */}
          <div className="pt-4 border-t border-slate-200 dark:border-slate-800/80">
            <p className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-2">Most Recent URL Scan</p>
            {urlScans[0] ? (
              <div className="flex items-center justify-between gap-3 text-sm">
                <div className="min-w-0">
                  <p className="font-mono text-xs text-slate-800 dark:text-slate-200 truncate">{urlScans[0].signals.hostname}</p>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 truncate">{urlScans[0].threatCategory}</p>
                </div>
                <div className="text-right shrink-0">
                  <SeverityIndicator level={urlScans[0].verdict} />
                  <p className={`text-xs font-mono tabular-nums mt-0.5 ${getScoreAccentClass(urlScans[0].riskScore)}`}>
                    Risk {urlScans[0].riskScore}/100
                  </p>
                </div>
              </div>
            ) : (
              <p className="text-xs text-slate-500">Run a URL scan above to populate live telemetry.</p>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
