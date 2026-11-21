import { useState } from 'react';
import { BarChart3, FileDown, ShieldCheck } from 'lucide-react';
import type {
  PasswordAuditSummary,
  SecurityAlert,
  ThreatAnalysisResult,
  UrlScanResult,
  UserProfile,
} from '../types/security';
import { downloadExecutiveStatsPdf } from '../utils/pdfReport';

interface SecurityStatsProps {
  urlScans: UrlScanResult[];
  threatAnalyses: ThreatAnalysisResult[];
  passwordAudits: PasswordAuditSummary[];
  alerts: SecurityAlert[];
  analyst: UserProfile | null;
}

export function SecurityStats({
  urlScans,
  threatAnalyses,
  passwordAudits,
  alerts,
  analyst,
}: SecurityStatsProps) {
  const [scope, setScope] = useState<'all' | 'urls' | 'threats'>('all');

  const safeCount = urlScans.filter((s) => s.verdict === 'Safe').length;
  const suspiciousCount = urlScans.filter((s) => s.verdict === 'Suspicious').length;
  const maliciousCount = urlScans.filter((s) => s.verdict === 'Malicious').length;
  const totalUrls = urlScans.length;

  const avgUrlRisk =
    totalUrls > 0 ? Math.round(urlScans.reduce((sum, s) => sum + s.riskScore, 0) / totalUrls) : 0;

  const httpsRate =
    totalUrls > 0
      ? Math.round((urlScans.filter((s) => s.signals.protocol === 'HTTPS').length / totalUrls) * 100)
      : 0;
  const trustedTlsRate =
    totalUrls > 0 ? Math.round((urlScans.filter((s) => s.tls.authorized).length / totalUrls) * 100) : 0;
  const spfRate =
    totalUrls > 0 ? Math.round((urlScans.filter((s) => s.dns.hasSpf).length / totalUrls) * 100) : 0;
  const dmarcRate =
    totalUrls > 0 ? Math.round((urlScans.filter((s) => s.dns.hasDmarc).length / totalUrls) * 100) : 0;
  const hstsRate =
    totalUrls > 0
      ? Math.round((urlScans.filter((s) => s.http.securityHeaders.hsts).length / totalUrls) * 100)
      : 0;

  // Top triggered phishing/risk indicators across all scans
  const indicatorFrequency = new Map<string, number>();
  for (const scan of urlScans) {
    for (const item of scan.evidenceItems || []) {
      if (item.riskPoints > 0) {
        indicatorFrequency.set(item.title, (indicatorFrequency.get(item.title) || 0) + 1);
      }
    }
  }
  const topIndicators = Array.from(indicatorFrequency.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6);

  // MITRE ATT&CK tactic frequency
  const mitreFrequency = new Map<string, number>();
  for (const rep of threatAnalyses) {
    for (const tech of rep.mitreTechniques || []) {
      const key = `${tech.id} · ${tech.name}`;
      mitreFrequency.set(key, (mitreFrequency.get(key) || 0) + 1);
    }
  }
  const topMitre = Array.from(mitreFrequency.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6);

  // Trend series for SVG chart (chronological order, max 12 points)
  const trendSeries =
    scope === 'threats'
      ? threatAnalyses
          .slice(0, 12)
          .reverse()
          .map((t, i) => ({ label: `#${i + 1}`, score: t.riskScore, name: t.threatCategory }))
      : urlScans
          .slice(0, 12)
          .reverse()
          .map((u, i) => ({ label: `#${i + 1}`, score: u.riskScore, name: u.signals.hostname }));

  // Donut chart stroke math
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  const safeArc = totalUrls > 0 ? (safeCount / totalUrls) * circumference : 0;
  const suspArc = totalUrls > 0 ? (suspiciousCount / totalUrls) * circumference : 0;
  const malArc = totalUrls > 0 ? (maliciousCount / totalUrls) * circumference : 0;

  return (
    <div className="space-y-6">
      <section className="neon-panel rounded-2xl p-5 sm:p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-slate-900 dark:text-slate-50">
            Advanced Security Statistics
          </h1>
          <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400 mt-1">
            Aggregated risk posture, DNS/TLS compliance, and indicator frequency calculated from your live scans.
          </p>
        </div>

        <button
          type="button"
          onClick={() =>
            downloadExecutiveStatsPdf({
              urlScans,
              threatAnalyses,
              passwordAudits,
              alerts,
              analyst,
            })
          }
          className="neon-btn-primary min-h-[44px] px-5 py-2.5 rounded-xl text-xs sm:text-sm font-semibold text-white inline-flex items-center justify-center gap-2 shrink-0 cursor-pointer"
        >
          <FileDown className="w-4 h-4" aria-hidden="true" />
          <span>Export Summary PDF</span>
        </button>
      </section>

      {/* Summary KPI Row */}
      <section className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
        <div className="neon-panel rounded-2xl p-4 sm:p-5">
          <p className="text-xs text-slate-500 dark:text-slate-400">Average URL Risk</p>
          <p className="mt-2 text-2xl sm:text-3xl font-bold font-mono tabular-nums text-slate-900 dark:text-slate-50">
            {avgUrlRisk}
            <span className="text-sm font-normal text-slate-400">/100</span>
          </p>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400 tabular-nums">{totalUrls} scans analyzed</p>
        </div>

        <div className="neon-panel rounded-2xl p-4 sm:p-5">
          <p className="text-xs text-slate-500 dark:text-slate-400">Trusted TLS Rate</p>
          <p className="mt-2 text-2xl sm:text-3xl font-bold font-mono tabular-nums text-emerald-600 dark:text-emerald-400">
            {trustedTlsRate}%
          </p>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400 tabular-nums">{httpsRate}% HTTPS scheme</p>
        </div>

        <div className="neon-panel rounded-2xl p-4 sm:p-5">
          <p className="text-xs text-slate-500 dark:text-slate-400">Breached Passwords</p>
          <p className="mt-2 text-2xl sm:text-3xl font-bold font-mono tabular-nums text-rose-600 dark:text-rose-400">
            {passwordAudits.filter((p) => (p.breachCount ?? 0) > 0).length}
          </p>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400 tabular-nums">
            of {passwordAudits.length} audits
          </p>
        </div>

        <div className="neon-panel rounded-2xl p-4 sm:p-5">
          <p className="text-xs text-slate-500 dark:text-slate-400">Active Open Alerts</p>
          <p className="mt-2 text-2xl sm:text-3xl font-bold font-mono tabular-nums text-amber-600 dark:text-amber-400">
            {alerts.filter((a) => a.status === 'Open').length}
          </p>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400 tabular-nums">
            {alerts.filter((a) => a.status === 'Resolved').length} resolved
          </p>
        </div>
      </section>

      {/* Charts Split: Verdict Donut + Risk Score Trend */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
        {/* Donut Chart */}
        <section className="lg:col-span-5 neon-panel rounded-2xl p-5 sm:p-6 flex flex-col justify-between">
          <div>
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-50">URL Verdict Distribution</h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              Classification breakdown across scanned URLs
            </p>
          </div>

          <div className="my-6 flex flex-col sm:flex-row items-center justify-center gap-6">
            <div className="relative w-36 h-36 shrink-0">
              <svg viewBox="0 0 140 140" className="w-full h-full -rotate-90" aria-label="Verdict distribution donut chart">
                <circle
                  cx="70"
                  cy="70"
                  r={radius}
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="16"
                  className="text-slate-200 dark:text-slate-800"
                />
                {totalUrls > 0 && (
                  <>
                    <circle
                      cx="70"
                      cy="70"
                      r={radius}
                      fill="none"
                      stroke="#10B981"
                      strokeWidth="16"
                      strokeDasharray={`${safeArc} ${circumference}`}
                      strokeDashoffset={0}
                    />
                    <circle
                      cx="70"
                      cy="70"
                      r={radius}
                      fill="none"
                      stroke="#F59E0B"
                      strokeWidth="16"
                      strokeDasharray={`${suspArc} ${circumference}`}
                      strokeDashoffset={-safeArc}
                    />
                    <circle
                      cx="70"
                      cy="70"
                      r={radius}
                      fill="none"
                      stroke="#F43F5E"
                      strokeWidth="16"
                      strokeDasharray={`${malArc} ${circumference}`}
                      strokeDashoffset={-(safeArc + suspArc)}
                    />
                  </>
                )}
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-2xl font-bold font-mono tabular-nums text-slate-900 dark:text-slate-50">
                  {totalUrls}
                </span>
                <span className="text-[11px] text-slate-500 dark:text-slate-400">URLs</span>
              </div>
            </div>

            <dl className="space-y-2.5 text-xs w-full sm:w-auto">
              <div className="flex items-center justify-between gap-6">
                <dt className="flex items-center gap-2 text-slate-700 dark:text-slate-300">
                  <span className="w-2.5 h-2.5 rounded-sm bg-emerald-500" />
                  <span>Safe</span>
                </dt>
                <dd className="font-mono tabular-nums font-semibold text-slate-900 dark:text-slate-100">
                  {safeCount} ({totalUrls ? Math.round((safeCount / totalUrls) * 100) : 0}%)
                </dd>
              </div>
              <div className="flex items-center justify-between gap-6">
                <dt className="flex items-center gap-2 text-slate-700 dark:text-slate-300">
                  <span className="w-2.5 h-2.5 rounded-sm bg-amber-500" />
                  <span>Suspicious</span>
                </dt>
                <dd className="font-mono tabular-nums font-semibold text-slate-900 dark:text-slate-100">
                  {suspiciousCount} ({totalUrls ? Math.round((suspiciousCount / totalUrls) * 100) : 0}%)
                </dd>
              </div>
              <div className="flex items-center justify-between gap-6">
                <dt className="flex items-center gap-2 text-slate-700 dark:text-slate-300">
                  <span className="w-2.5 h-2.5 rounded-sm bg-rose-500" />
                  <span>Malicious</span>
                </dt>
                <dd className="font-mono tabular-nums font-semibold text-slate-900 dark:text-slate-100">
                  {maliciousCount} ({totalUrls ? Math.round((maliciousCount / totalUrls) * 100) : 0}%)
                </dd>
              </div>
            </dl>
          </div>

          <p className="text-xs text-slate-500 dark:text-slate-400 border-t border-slate-200 dark:border-slate-800/80 pt-3">
            {totalUrls === 0
              ? 'Run single or batch URL scans to populate live distribution telemetry.'
              : `${maliciousCount + suspiciousCount} elevated-risk endpoint(s) flagged across ${totalUrls} inspection(s).`}
          </p>
        </section>

        {/* Risk Score Trend Chart */}
        <section className="lg:col-span-7 neon-panel rounded-2xl p-5 sm:p-6 flex flex-col justify-between">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
            <div>
              <h2 className="text-base font-semibold text-slate-900 dark:text-slate-50">Recent Risk Score Trend</h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Last {trendSeries.length} assessments (0 = lowest risk, 100 = highest risk)
              </p>
            </div>

            <div className="inline-flex p-1 rounded-xl bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 self-start">
              <button
                type="button"
                onClick={() => setScope('all')}
                className={`min-h-[34px] px-3 py-1 rounded-lg text-xs font-medium cursor-pointer ${
                  scope !== 'threats' ? 'bg-sky-600 text-white' : 'text-slate-600 dark:text-slate-400'
                }`}
              >
                URL Scans
              </button>
              <button
                type="button"
                onClick={() => setScope('threats')}
                className={`min-h-[34px] px-3 py-1 rounded-lg text-xs font-medium cursor-pointer ${
                  scope === 'threats' ? 'bg-sky-600 text-white' : 'text-slate-600 dark:text-slate-400'
                }`}
              >
                Threat Reports
              </button>
            </div>
          </div>

          {trendSeries.length === 0 ? (
            <div className="flex-1 min-h-[180px] flex flex-col items-center justify-center text-center border border-dashed border-slate-300 dark:border-slate-800 rounded-xl p-6">
              <BarChart3 className="w-8 h-8 text-sky-500 mb-2" aria-hidden="true" />
              <p className="text-sm font-medium text-slate-700 dark:text-slate-200">No Trend Data Yet</p>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                Complete scans in Phishing Detector, Multi-URL Scanner, or Threat Analyzer to visualize risk trends.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              <svg viewBox="0 0 480 160" className="w-full h-44 overflow-visible" aria-label="Risk score trend chart">
                {[0, 25, 50, 75, 100].map((tick) => {
                  const y = 135 - (tick / 100) * 115;
                  return (
                    <g key={tick}>
                      <line x1="34" x2="466" y1={y} y2={y} stroke="currentColor" className="text-slate-200 dark:text-slate-800" strokeWidth="1" />
                      <text x="0" y={y + 4} className="fill-slate-400 text-[10px] font-mono">
                        {tick}
                      </text>
                    </g>
                  );
                })}
                {trendSeries.length > 1 && (
                  <polyline
                    fill="none"
                    stroke="#0EA5E9"
                    strokeWidth="2.5"
                    strokeLinejoin="round"
                    points={trendSeries
                      .map((pt, i) => {
                        const x = 44 + (i / (trendSeries.length - 1)) * 412;
                        const y = 135 - (pt.score / 100) * 115;
                        return `${x},${y}`;
                      })
                      .join(' ')}
                  />
                )}
                {trendSeries.map((pt, i) => {
                  const x =
                    trendSeries.length === 1 ? 250 : 44 + (i / (trendSeries.length - 1)) * 412;
                  const y = 135 - (pt.score / 100) * 115;
                  const fill = pt.score >= 60 ? '#F43F5E' : pt.score >= 25 ? '#F59E0B' : '#10B981';
                  return (
                    <g key={i}>
                      <circle cx={x} cy={y} r="4.5" fill={fill} stroke="#0F172A" strokeWidth="1.5">
                        <title>{`${pt.name}: ${pt.score}/100`}</title>
                      </circle>
                      <text x={x} y="154" textAnchor="middle" className="fill-slate-400 text-[10px] font-mono">
                        {pt.label}
                      </text>
                    </g>
                  );
                })}
              </svg>
            </div>
          )}
        </section>
      </div>

      {/* Infrastructure Posture & Top Indicators */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <section className="neon-panel rounded-2xl p-5 sm:p-6 space-y-4">
          <div>
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-50">
              Domain &amp; Transport Posture Compliance
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              Percentage of scanned domains meeting security standards
            </p>
          </div>

          <div className="space-y-3.5">
            {[
              { label: 'HTTPS Protocol Enforcement', pct: httpsRate },
              { label: 'Trusted Root CA SSL/TLS Certificate', pct: trustedTlsRate },
              { label: 'SPF Email Policy Record', pct: spfRate },
              { label: 'DMARC Policy Record', pct: dmarcRate },
              { label: 'Strict-Transport-Security (HSTS)', pct: hstsRate },
            ].map((row) => (
              <div key={row.label} className="space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-700 dark:text-slate-300">{row.label}</span>
                  <span className="font-mono tabular-nums font-semibold text-slate-900 dark:text-slate-100">
                    {row.pct}%
                  </span>
                </div>
                <div className="h-2 rounded-full bg-slate-200 dark:bg-slate-900 overflow-hidden">
                  <div className="h-full bg-sky-500 transition-all" style={{ width: `${row.pct}%` }} />
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="neon-panel rounded-2xl p-5 sm:p-6 space-y-4">
          <div>
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-50">
              Top Triggered Risk Signals &amp; Techniques
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              Most frequent indicators observed across scans and threat analyses
            </p>
          </div>

          {topIndicators.length === 0 && topMitre.length === 0 ? (
            <div className="py-10 text-center border border-dashed border-slate-300 dark:border-slate-800 rounded-xl px-4">
              <ShieldCheck className="w-8 h-8 text-emerald-500 mx-auto mb-2" aria-hidden="true" />
              <p className="text-xs text-slate-500 dark:text-slate-400">
                No elevated risk signals or MITRE ATT&amp;CK techniques recorded yet.
              </p>
            </div>
          ) : (
            <div className="divide-y divide-slate-200 dark:divide-slate-800/80 text-xs">
              {topIndicators.map(([title, count]) => (
                <div key={title} className="py-2.5 flex items-center justify-between gap-3">
                  <span className="text-slate-700 dark:text-slate-200 truncate">{title}</span>
                  <span className="font-mono tabular-nums text-amber-600 dark:text-amber-400 shrink-0">
                    {count}x
                  </span>
                </div>
              ))}
              {topMitre.map(([title, count]) => (
                <div key={title} className="py-2.5 flex items-center justify-between gap-3">
                  <span className="font-mono text-sky-700 dark:text-sky-300 truncate">{title}</span>
                  <span className="font-mono tabular-nums text-slate-600 dark:text-slate-400 shrink-0">
                    {count}x
                  </span>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
