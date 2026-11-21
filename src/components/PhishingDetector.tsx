import { useEffect, useState, type FormEvent } from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  Check,
  CheckCircle2,
  Copy,
  ExternalLink,
  FileDown,
  Globe,
  Info,
  Loader2,
  Lock,
  RotateCcw,
  Server,
  ShieldAlert,
  Trash2,
  X,
} from 'lucide-react';
import type { PhishingEvidenceItem, UrlScanResult, UserProfile } from '../types/security';
import { downloadUrlScanPdf } from '../utils/pdfReport';
import { SeverityIndicator, getProgressBarClass, getScoreAccentClass } from './SeverityIndicator';

interface PhishingDetectorProps {
  scans: UrlScanResult[];
  analyst: UserProfile | null;
  pendingQuickUrl: string | null;
  onClearPendingQuickUrl: () => void;
  onScanComplete: (result: UrlScanResult) => void;
  onClearHistory: () => void;
}

const SAMPLE_URLS = [
  { label: 'Wikipedia (Verified)', url: 'https://www.wikipedia.org' },
  { label: 'GitHub (Verified)', url: 'https://github.com' },
  { label: 'Lookalike Phish Test', url: 'http://paypa1-secure-verify.xyz/login?session=update' },
];

type EvidenceTab = 'checks' | 'dns' | 'tls' | 'http';

function EvidenceSeverityIcon({ severity }: { severity: PhishingEvidenceItem['severity'] }) {
  switch (severity) {
    case 'Pass':
      return <CheckCircle2 className="w-4 h-4 text-emerald-500 dark:text-emerald-400 shrink-0 mt-0.5" aria-hidden="true" />;
    case 'Info':
      return <Info className="w-4 h-4 text-sky-600 dark:text-sky-400 shrink-0 mt-0.5" aria-hidden="true" />;
    case 'Warning':
      return <AlertTriangle className="w-4 h-4 text-amber-500 dark:text-amber-400 shrink-0 mt-0.5" aria-hidden="true" />;
    case 'Critical':
      return <AlertOctagon className="w-4 h-4 text-rose-500 dark:text-rose-400 shrink-0 mt-0.5" aria-hidden="true" />;
  }
}

export function PhishingDetector({
  scans,
  analyst,
  pendingQuickUrl,
  onClearPendingQuickUrl,
  onScanComplete,
  onClearHistory,
}: PhishingDetectorProps) {
  const [urlInput, setUrlInput] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeResult, setActiveResult] = useState<UrlScanResult | null>(scans[0] || null);
  const [evidenceTab, setEvidenceTab] = useState<EvidenceTab>('checks');
  const [copiedReport, setCopiedReport] = useState(false);

  const runScan = async (targetUrl: string) => {
    const trimmed = targetUrl.trim();
    if (!trimmed) {
      setError('Enter a URL or domain name before running a scan.');
      return;
    }

    setUrlInput(trimmed);
    setIsScanning(true);
    setError(null);

    try {
      const response = await fetch('/api/scan-url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: trimmed }),
      });

      const data = await response.json();
      if (!response.ok) {
        setError(data.error || `Scan failed with status ${response.status}.`);
        return;
      }

      const result = data as UrlScanResult;
      setActiveResult(result);
      setEvidenceTab('checks');
      onScanComplete(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Network error while contacting backend scanner.');
    } finally {
      setIsScanning(false);
    }
  };

  useEffect(() => {
    if (pendingQuickUrl) {
      const target = pendingQuickUrl;
      onClearPendingQuickUrl();
      void runScan(target);
    }
  }, [pendingQuickUrl]);

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    void runScan(urlInput);
  };

  const handleCopyJson = async () => {
    if (!activeResult) return;
    try {
      await navigator.clipboard.writeText(JSON.stringify(activeResult, null, 2));
      setCopiedReport(true);
      setTimeout(() => setCopiedReport(false), 1800);
    } catch {
      // Clipboard blocked
    }
  };

  return (
    <div className="space-y-6">
      {/* Scanner Input Card */}
      <section className="neon-panel rounded-2xl p-5 sm:p-6">
        <div className="mb-4">
          <h1 className="text-xl sm:text-2xl font-bold text-slate-900 dark:text-slate-50">Phishing URL Detector</h1>
          <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400 mt-1">
            Runs live backend DNS, RDAP domain-age, SSL/TLS certificate, HTTP redirect/form, and URL indicator checks with PDF export.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-3">
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <input
                type="text"
                inputMode="url"
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
                value={urlInput}
                onChange={(e) => {
                  setUrlInput(e.target.value);
                  if (error) setError(null);
                }}
                placeholder="https://example.com/login"
                aria-label="URL to scan"
                className="w-full min-h-[46px] pl-4 pr-11 py-2.5 rounded-xl bg-slate-50 dark:bg-slate-950/90 border border-slate-300 dark:border-sky-500/25 text-sm font-mono text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:outline-none focus:border-sky-500 focus:ring-2 focus:ring-sky-500/25"
              />
              {urlInput && (
                <button
                  type="button"
                  onClick={() => setUrlInput('')}
                  aria-label="Clear URL input"
                  className="absolute right-1.5 top-1/2 -translate-y-1/2 min-w-[38px] min-h-[38px] flex items-center justify-center rounded-lg text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 cursor-pointer"
                >
                  <X className="w-4 h-4" aria-hidden="true" />
                </button>
              )}
            </div>

            <button
              type="submit"
              disabled={isScanning || !urlInput.trim()}
              className="neon-btn-primary min-h-[46px] px-6 py-2.5 rounded-xl text-sm font-semibold text-white whitespace-nowrap shrink-0 inline-flex items-center justify-center gap-2 transition-all disabled:opacity-45 disabled:cursor-not-allowed cursor-pointer"
            >
              {isScanning ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" />
                  <span>Inspecting Target...</span>
                </>
              ) : (
                <>
                  <Globe className="w-4 h-4" aria-hidden="true" />
                  <span>Scan URL</span>
                </>
              )}
            </button>
          </div>

          <div className="flex flex-wrap items-center gap-2 pt-1">
            <span className="text-xs text-slate-500 dark:text-slate-400">Sample targets:</span>
            {SAMPLE_URLS.map((sample) => (
              <button
                key={sample.url}
                type="button"
                disabled={isScanning}
                onClick={() => void runScan(sample.url)}
                className="min-h-[36px] px-3 py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 dark:bg-slate-900/90 dark:hover:bg-slate-800 border border-slate-300 dark:border-slate-800 text-xs text-sky-700 dark:text-sky-300 transition-colors cursor-pointer disabled:opacity-50"
              >
                {sample.label}
              </button>
            ))}
          </div>
        </form>

        {error && (
          <div
            role="alert"
            className="mt-4 p-4 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-500/35 text-sm text-rose-800 dark:text-rose-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
          >
            <div className="flex items-start gap-3">
              <ShieldAlert className="w-5 h-5 text-rose-500 shrink-0 mt-0.5" aria-hidden="true" />
              <div>
                <p className="font-semibold text-rose-700 dark:text-rose-300">Scan Error</p>
                <p className="text-xs text-rose-700 dark:text-rose-200/90 mt-1">{error}</p>
              </div>
            </div>
            {urlInput.trim() && (
              <button
                type="button"
                onClick={() => void runScan(urlInput)}
                className="min-h-[38px] px-4 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-xs font-medium text-white self-start sm:self-center shrink-0 cursor-pointer"
              >
                Retry
              </button>
            )}
          </div>
        )}
      </section>

      {/* Loading Skeleton */}
      {isScanning && (
        <section className="neon-panel rounded-2xl p-6 space-y-5 animate-pulse" aria-busy="true">
          <div className="flex items-center justify-between">
            <div className="space-y-2">
              <div className="h-4 w-36 bg-slate-200 dark:bg-slate-800 rounded" />
              <div className="h-6 w-64 bg-slate-200 dark:bg-slate-800 rounded" />
            </div>
            <div className="h-10 w-24 bg-slate-200 dark:bg-slate-800 rounded-xl" />
          </div>
          <div className="h-2 w-full bg-slate-200 dark:bg-slate-800 rounded-full" />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="h-28 bg-slate-100 dark:bg-slate-900 rounded-xl" />
            <div className="h-28 bg-slate-100 dark:bg-slate-900 rounded-xl" />
          </div>
        </section>
      )}

      {/* Active Scan Report */}
      {!isScanning && activeResult && (
        <section className="neon-panel neon-panel-active rounded-2xl p-5 sm:p-6 space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
            <div className="min-w-0 space-y-1.5">
              <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
                <SeverityIndicator level={activeResult.verdict} />
                <span aria-hidden="true">·</span>
                <span>{activeResult.threatCategory}</span>
                <span aria-hidden="true">·</span>
                <span className="font-mono tabular-nums">{activeResult.durationMs} ms</span>
                <span aria-hidden="true">·</span>
                <span className="font-mono tabular-nums">
                  {new Date(activeResult.scannedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </span>
              </div>
              <h2 className="text-base sm:text-lg font-mono font-semibold text-slate-900 dark:text-slate-50 break-all">
                {activeResult.signals.normalizedUrl}
              </h2>
              <p className="text-sm text-slate-600 dark:text-slate-300 leading-relaxed">{activeResult.summary}</p>
            </div>

            <div className="flex sm:flex-col items-center sm:items-end justify-between gap-3 shrink-0">
              <div className="sm:text-right">
                <p className="text-xs text-slate-500 dark:text-slate-400">Risk Score</p>
                <p className={`text-3xl font-bold font-mono tabular-nums ${getScoreAccentClass(activeResult.riskScore)}`}>
                  {activeResult.riskScore}
                  <span className="text-sm text-slate-400 font-normal">/100</span>
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={() => void handleCopyJson()}
                  className="min-h-[38px] px-3 py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 dark:bg-slate-900 dark:hover:bg-slate-800 border border-slate-300 dark:border-slate-800 text-xs text-slate-700 dark:text-slate-200 inline-flex items-center gap-1.5 cursor-pointer"
                >
                  {copiedReport ? <Check className="w-3.5 h-3.5 text-emerald-500" aria-hidden="true" /> : <Copy className="w-3.5 h-3.5" aria-hidden="true" />}
                  <span>{copiedReport ? 'Copied' : 'JSON'}</span>
                </button>
                <button
                  type="button"
                  onClick={() => downloadUrlScanPdf(activeResult, analyst)}
                  className="min-h-[38px] px-3.5 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-xs font-semibold text-white inline-flex items-center gap-1.5 cursor-pointer"
                >
                  <FileDown className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>Download PDF</span>
                </button>
              </div>
            </div>
          </div>

          <div className="h-2 w-full rounded-full bg-slate-200 dark:bg-slate-900 overflow-hidden">
            <div
              className={`h-full transition-all ${getProgressBarClass(activeResult.riskScore)}`}
              style={{ width: `${activeResult.riskScore}%` }}
            />
          </div>

          {/* Evidence Tabs */}
          <div className="flex items-center gap-1.5 overflow-x-auto pb-1 border-b border-slate-200 dark:border-slate-800/80">
            {[
              { id: 'checks' as const, label: `Evidence (${activeResult.evidenceItems?.length ?? 0})` },
              { id: 'dns' as const, label: 'DNS & RDAP' },
              { id: 'tls' as const, label: 'SSL/TLS Cert' },
              { id: 'http' as const, label: 'HTTP & Content' },
            ].map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setEvidenceTab(tab.id)}
                className={`min-h-[40px] px-3.5 py-2 rounded-lg text-xs font-medium whitespace-nowrap shrink-0 transition-colors cursor-pointer ${
                  evidenceTab === tab.id
                    ? 'bg-sky-600 text-white'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 hover:bg-slate-100 dark:hover:bg-slate-900'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {evidenceTab === 'checks' && (
            <div className="space-y-6">
              <div className="divide-y divide-slate-200 dark:divide-slate-800/80">
                {(activeResult.evidenceItems || []).map((item) => (
                  <div key={item.id} className="py-3 first:pt-0 last:pb-0 flex items-start justify-between gap-3">
                    <div className="flex items-start gap-2.5 min-w-0">
                      <EvidenceSeverityIcon severity={item.severity} />
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2 text-xs">
                          <span className="font-semibold text-slate-900 dark:text-slate-100">{item.title}</span>
                          <span className="text-slate-400">·</span>
                          <span className="text-slate-500 dark:text-slate-400">{item.category}</span>
                        </div>
                        <p className="text-xs text-slate-600 dark:text-slate-300 mt-1 break-words">{item.evidence}</p>
                      </div>
                    </div>
                    <span
                      className={`font-mono text-xs tabular-nums shrink-0 ${
                        item.riskPoints > 0 ? 'text-amber-600 dark:text-amber-400' : 'text-emerald-600 dark:text-emerald-400'
                      }`}
                    >
                      {item.riskPoints > 0 ? `+${item.riskPoints}` : '0'} pts
                    </span>
                  </div>
                ))}
              </div>

              <div className="pt-4 border-t border-slate-200 dark:border-slate-800/80 space-y-2.5">
                <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">Recommended Actions</h3>
                <ul className="space-y-2 text-xs sm:text-sm text-slate-700 dark:text-slate-300">
                  {activeResult.recommendations.map((rec, idx) => (
                    <li key={idx} className="flex items-start gap-2.5">
                      <CheckCircle2 className="w-4 h-4 text-sky-600 dark:text-sky-400 shrink-0 mt-0.5" aria-hidden="true" />
                      <span>{rec}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {activeResult.aiAssessment && (
                <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800/80 text-xs text-slate-600 dark:text-slate-400">
                  {activeResult.aiAssessment.status === 'completed' ? (
                    <span>
                      AI narrative synthesis completed via{' '}
                      <strong className="font-mono text-slate-800 dark:text-slate-300">{activeResult.aiAssessment.model}</strong> using verified backend evidence.
                    </span>
                  ) : (
                    <span>AI narrative status: {activeResult.aiAssessment.error}</span>
                  )}
                </div>
              )}
            </div>
          )}

          {evidenceTab === 'dns' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800/80 space-y-3">
                <div className="flex items-center justify-between text-xs font-semibold text-slate-800 dark:text-slate-200">
                  <span>DNS Resolution Evidence</span>
                  <Server className="w-4 h-4 text-sky-600 dark:text-sky-400" aria-hidden="true" />
                </div>
                <dl className="space-y-2 text-xs">
                  <div>
                    <dt className="text-slate-500 dark:text-slate-400">IPv4 (A Records)</dt>
                    <dd className="font-mono text-slate-900 dark:text-slate-100 mt-0.5 break-all">
                      {activeResult.dns.ipv4.length > 0 ? activeResult.dns.ipv4.join(', ') : 'None'}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-slate-500 dark:text-slate-400">IPv6 (AAAA Records)</dt>
                    <dd className="font-mono text-slate-900 dark:text-slate-100 mt-0.5 break-all">
                      {activeResult.dns.ipv6.length > 0 ? activeResult.dns.ipv6.join(', ') : 'None'}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-slate-500 dark:text-slate-400">Nameservers (NS)</dt>
                    <dd className="font-mono text-slate-900 dark:text-slate-100 mt-0.5 break-all">
                      {activeResult.dns.nameservers?.length > 0 ? activeResult.dns.nameservers.join(', ') : 'None'}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-slate-500 dark:text-slate-400">Mail Exchangers (MX)</dt>
                    <dd className="font-mono text-slate-900 dark:text-slate-100 mt-0.5 break-all">
                      {activeResult.dns.mxRecords.length > 0 ? activeResult.dns.mxRecords.join(', ') : 'None'}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-slate-500 dark:text-slate-400">SPF Record</dt>
                    <dd className="font-mono text-slate-700 dark:text-slate-200 mt-0.5 break-all">
                      {activeResult.dns.spfRecord || 'Not Configured'}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-slate-500 dark:text-slate-400">DMARC Record</dt>
                    <dd className="font-mono text-slate-700 dark:text-slate-200 mt-0.5 break-all">
                      {activeResult.dns.dmarcRecord || 'Not Configured'}
                    </dd>
                  </div>
                </dl>
              </div>

              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800/80 space-y-3">
                <div className="flex items-center justify-between text-xs font-semibold text-slate-800 dark:text-slate-200">
                  <span>RDAP Domain Registration</span>
                  <Globe className="w-4 h-4 text-sky-600 dark:text-sky-400" aria-hidden="true" />
                </div>
                {activeResult.rdap?.error ? (
                  <p className="text-xs text-slate-500 dark:text-slate-400">{activeResult.rdap.error}</p>
                ) : (
                  <dl className="space-y-2 text-xs">
                    <div>
                      <dt className="text-slate-500 dark:text-slate-400">Registrable Domain</dt>
                      <dd className="font-mono text-slate-900 dark:text-slate-100 mt-0.5">{activeResult.signals.registrableDomain}</dd>
                    </div>
                    <div>
                      <dt className="text-slate-500 dark:text-slate-400">Registrar</dt>
                      <dd className="text-slate-900 dark:text-slate-100 mt-0.5">{activeResult.rdap?.registrar || 'Unknown'}</dd>
                    </div>
                    <div>
                      <dt className="text-slate-500 dark:text-slate-400">Registered Date &amp; Age</dt>
                      <dd className="font-mono tabular-nums text-slate-900 dark:text-slate-100 mt-0.5">
                        {activeResult.rdap?.createdAt
                          ? `${activeResult.rdap.createdAt.slice(0, 10)} (${activeResult.rdap.domainAgeDays?.toLocaleString()} days)`
                          : 'Unavailable'}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-slate-500 dark:text-slate-400">Expiration Date</dt>
                      <dd className="font-mono tabular-nums text-slate-900 dark:text-slate-100 mt-0.5">
                        {activeResult.rdap?.expiresAt ? activeResult.rdap.expiresAt.slice(0, 10) : 'Unavailable'}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-slate-500 dark:text-slate-400">DNSSEC Signed</dt>
                      <dd className="text-slate-900 dark:text-slate-100 mt-0.5">
                        {activeResult.rdap?.dnssecSigned === null
                          ? 'Unknown'
                          : activeResult.rdap?.dnssecSigned
                            ? 'Signed'
                            : 'Unsigned'}
                      </dd>
                    </div>
                  </dl>
                )}
              </div>
            </div>
          )}

          {evidenceTab === 'tls' && (
            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800/80 space-y-3">
              <div className="flex items-center justify-between text-xs font-semibold text-slate-800 dark:text-slate-200">
                <span>SSL/TLS Certificate Verification</span>
                <Lock className="w-4 h-4 text-sky-600 dark:text-sky-400" aria-hidden="true" />
              </div>
              {!activeResult.tls.checked || activeResult.tls.error ? (
                <p className="text-xs text-amber-600 dark:text-amber-300">
                  {activeResult.tls.error || 'TLS certificate could not be inspected.'}
                </p>
              ) : (
                <dl className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  <div>
                    <dt className="text-slate-500 dark:text-slate-400">Trust Verification</dt>
                    <dd className={activeResult.tls.authorized ? 'text-emerald-600 dark:text-emerald-400 font-semibold mt-0.5' : 'text-rose-600 dark:text-rose-400 font-semibold mt-0.5'}>
                      {activeResult.tls.authorized
                        ? 'Trusted by Root CA'
                        : activeResult.tls.authorizationError || 'Untrusted Certificate'}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-slate-500 dark:text-slate-400">Protocol &amp; Cipher</dt>
                    <dd className="font-mono text-slate-900 dark:text-slate-100 mt-0.5 break-all">
                      {activeResult.tls.protocol || '—'} {activeResult.tls.cipher ? `· ${activeResult.tls.cipher}` : ''}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-slate-500 dark:text-slate-400">Subject Common Name</dt>
                    <dd className="font-mono text-slate-900 dark:text-slate-100 mt-0.5 break-all">{activeResult.tls.subject || '—'}</dd>
                  </div>
                  <div>
                    <dt className="text-slate-500 dark:text-slate-400">Issuer</dt>
                    <dd className="font-mono text-slate-900 dark:text-slate-100 mt-0.5 break-all">{activeResult.tls.issuer || '—'}</dd>
                  </div>
                  <div>
                    <dt className="text-slate-500 dark:text-slate-400">Validity Window</dt>
                    <dd className="font-mono tabular-nums text-slate-900 dark:text-slate-100 mt-0.5">
                      {activeResult.tls.validFrom ? activeResult.tls.validFrom.slice(0, 16) : '—'} →{' '}
                      {activeResult.tls.validTo ? activeResult.tls.validTo.slice(0, 16) : '—'} (
                      {activeResult.tls.daysRemaining ?? '?'} days left)
                    </dd>
                  </div>
                  <div>
                    <dt className="text-slate-500 dark:text-slate-400">Subject Alternative Names (SANs)</dt>
                    <dd className="font-mono text-slate-700 dark:text-slate-200 mt-0.5 break-all">
                      {activeResult.tls.subjectAltNames?.length > 0
                        ? activeResult.tls.subjectAltNames.join(', ')
                        : 'None'}
                    </dd>
                  </div>
                  <div className="sm:col-span-2">
                    <dt className="text-slate-500 dark:text-slate-400">SHA-256 Certificate Fingerprint</dt>
                    <dd className="font-mono text-slate-700 dark:text-slate-200 mt-0.5 break-all">
                      {activeResult.tls.fingerprint256 || 'Unavailable'}
                    </dd>
                  </div>
                </dl>
              )}
            </div>
          )}

          {evidenceTab === 'http' && (
            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800/80 space-y-4">
              <div className="flex items-center justify-between text-xs font-semibold text-slate-800 dark:text-slate-200">
                <span>HTTP Response &amp; Page Inspection</span>
                <ExternalLink className="w-4 h-4 text-sky-600 dark:text-sky-400" aria-hidden="true" />
              </div>

              {activeResult.http.error ? (
                <p className="text-xs text-amber-600 dark:text-amber-300">{activeResult.http.error}</p>
              ) : (
                <dl className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  <div>
                    <dt className="text-slate-500 dark:text-slate-400">Final Status &amp; URL</dt>
                    <dd className="font-mono text-slate-900 dark:text-slate-100 mt-0.5 break-all">
                      HTTP {activeResult.http.statusCode ?? '—'} · {activeResult.http.finalUrl || activeResult.signals.normalizedUrl}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-slate-500 dark:text-slate-400">Page Title</dt>
                    <dd className="text-slate-900 dark:text-slate-100 mt-0.5 break-words">{activeResult.http.pageTitle || 'None / Non-HTML'}</dd>
                  </div>
                  <div>
                    <dt className="text-slate-500 dark:text-slate-400">Password Forms &amp; External Actions</dt>
                    <dd className="font-mono tabular-nums text-slate-900 dark:text-slate-100 mt-0.5">
                      {activeResult.http.passwordInputCount} password input(s) ·{' '}
                      {activeResult.http.externalFormAction
                        ? `External POST: ${activeResult.http.externalFormAction}`
                        : 'No external form action'}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-slate-500 dark:text-slate-400">Security Headers</dt>
                    <dd className="text-slate-700 dark:text-slate-200 mt-0.5">
                      HSTS: {activeResult.http.securityHeaders.hsts ? 'Yes' : 'No'} · CSP:{' '}
                      {activeResult.http.securityHeaders.csp ? 'Yes' : 'No'} · X-Frame:{' '}
                      {activeResult.http.securityHeaders.xFrameOptions ? 'Yes' : 'No'}
                    </dd>
                  </div>
                  {activeResult.http.redirectChain?.length > 0 && (
                    <div className="sm:col-span-2">
                      <dt className="text-slate-500 dark:text-slate-400">Redirect Chain ({activeResult.http.redirectChain.length} hop(s))</dt>
                      <dd className="mt-1 space-y-1 font-mono text-slate-700 dark:text-slate-200">
                        {activeResult.http.redirectChain.map((hop, idx) => (
                          <div key={idx} className="break-all">
                            [{hop.statusCode}] → {hop.url}
                          </div>
                        ))}
                      </dd>
                    </div>
                  )}
                </dl>
              )}
            </div>
          )}
        </section>
      )}

      {/* Scan History */}
      <section className="neon-panel rounded-2xl p-5 sm:p-6">
        <div className="flex items-center justify-between gap-4 mb-4">
          <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">Scan History</h3>
          {scans.length > 0 && (
            <button
              type="button"
              onClick={() => {
                onClearHistory();
                setActiveResult(null);
              }}
              className="inline-flex items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400 hover:text-rose-500 transition-colors cursor-pointer py-1 px-2"
            >
              <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Clear History</span>
            </button>
          )}
        </div>

        {scans.length === 0 ? (
          <p className="text-xs sm:text-sm text-slate-500 dark:text-slate-400 py-4">
            No URLs scanned yet. Enter any link above or tap a sample target to run a live inspection.
          </p>
        ) : (
          <div className="divide-y divide-slate-200 dark:divide-slate-800/80">
            {scans.map((scan) => (
              <div key={scan.id} className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <button
                  type="button"
                  onClick={() => {
                    setActiveResult(scan);
                    setEvidenceTab('checks');
                  }}
                  className="min-w-0 text-left flex-1 cursor-pointer group"
                >
                  <p className="text-xs sm:text-sm font-mono text-slate-900 dark:text-slate-100 group-hover:text-sky-600 dark:group-hover:text-sky-300 truncate transition-colors">
                    {scan.signals.normalizedUrl}
                  </p>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 tabular-nums">
                    {scan.threatCategory} · Risk {scan.riskScore}/100 ·{' '}
                    {new Date(scan.scannedAt).toLocaleString([], {
                      month: 'short',
                      day: 'numeric',
                      hour: '2-digit',
                      minute: '2-digit',
                    })}
                  </p>
                </button>

                <div className="flex items-center justify-between sm:justify-end gap-2.5 shrink-0">
                  <SeverityIndicator level={scan.verdict} />
                  <button
                    type="button"
                    onClick={() => downloadUrlScanPdf(scan, analyst)}
                    className="min-h-[36px] px-3 py-1 rounded-lg bg-slate-100 hover:bg-slate-200 dark:bg-slate-900 dark:hover:bg-slate-800 border border-slate-300 dark:border-slate-800 text-xs text-slate-700 dark:text-slate-300 inline-flex items-center gap-1 cursor-pointer"
                  >
                    <FileDown className="w-3 h-3" aria-hidden="true" />
                    <span>PDF</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => void runScan(scan.signals.normalizedUrl)}
                    disabled={isScanning}
                    className="min-h-[36px] px-3 py-1 rounded-lg bg-slate-100 hover:bg-slate-200 dark:bg-slate-900 dark:hover:bg-slate-800 border border-slate-300 dark:border-slate-800 text-xs text-slate-700 dark:text-slate-300 inline-flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                  >
                    <RotateCcw className="w-3 h-3" aria-hidden="true" />
                    <span>Rescan</span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
