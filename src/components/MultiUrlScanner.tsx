import { useRef, useState, type ChangeEvent, type FormEvent } from 'react';
import {
  AlertOctagon,
  ChevronDown,
  ChevronUp,
  Download,
  FileDown,
  FileUp,
  Layers,
  Loader2,
  ShieldAlert,
  Trash2,
} from 'lucide-react';
import type { BatchUrlScanResponse, UrlScanResult, UserProfile } from '../types/security';
import { downloadBatchScanPdf, downloadUrlScanPdf } from '../utils/pdfReport';
import { SeverityIndicator, getScoreAccentClass } from './SeverityIndicator';

interface MultiUrlScannerProps {
  analyst: UserProfile | null;
  onBatchComplete: (results: UrlScanResult[]) => void;
}

const SAMPLE_BATCH = `https://github.com
https://www.wikipedia.org
http://paypa1-secure-verify.xyz/login?session=update
https://cloudflare.com`;

export function MultiUrlScanner({ analyst, onBatchComplete }: MultiUrlScannerProps) {
  const [urlsText, setUrlsText] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [batchResult, setBatchResult] = useState<BatchUrlScanResponse | null>(null);
  const [expandedIndex, setExpandedIndex] = useState<number | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const parsedUrls = Array.from(
    new Set(
      urlsText
        .split(/[\n,]+/)
        .map((s) => s.trim())
        .filter(Boolean),
    ),
  );

  const handleFileUpload = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const content = await file.text();
      const extracted = content
        .split(/[\r\n,;]+/)
        .map((s) => s.trim().replace(/^["']|["']$/g, ''))
        .filter((s) => s.length > 3 && !s.toLowerCase().startsWith('url'))
        .slice(0, 10);
      if (extracted.length === 0) {
        setError('No URLs found in the uploaded file.');
        return;
      }
      setUrlsText(extracted.join('\n'));
      setError(null);
    } catch {
      setError('Unable to read the selected file.');
    } finally {
      e.target.value = '';
    }
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (parsedUrls.length === 0) {
      setError('Enter at least 1 URL (up to 10 URLs per batch).');
      return;
    }

    setIsScanning(true);
    setError(null);
    setExpandedIndex(null);

    try {
      const response = await fetch('/api/scan-urls', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ urls: parsedUrls.slice(0, 10) }),
      });

      const data = await response.json();
      if (!response.ok) {
        setError(data.error || `Batch scan failed with HTTP ${response.status}.`);
        return;
      }

      const payload = data as BatchUrlScanResponse;
      setBatchResult(payload);

      const successfulScans = payload.items
        .filter((item): item is { inputUrl: string; ok: true; result: UrlScanResult } => item.ok && Boolean(item.result))
        .map((item) => item.result);
      if (successfulScans.length > 0) {
        onBatchComplete(successfulScans);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Network error running batch scan.');
    } finally {
      setIsScanning(false);
    }
  };

  const handleExportCsv = () => {
    if (!batchResult) return;
    const header = ['Input URL', 'Status', 'Verdict', 'Risk Score', 'Category', 'TLS Authorized', 'DNS Resolved', 'Error'];
    const rows = batchResult.items.map((item) => {
      if (!item.ok || !item.result) {
        return [item.inputUrl, 'Failed', 'Error', '', '', '', '', item.error || 'Failed'];
      }
      const r = item.result;
      return [
        r.signals.normalizedUrl,
        'Completed',
        r.verdict,
        String(r.riskScore),
        r.threatCategory,
        r.tls.authorized ? 'Yes' : 'No',
        r.dns.resolved ? 'Yes' : 'No',
        '',
      ];
    });
    const csv = [header, ...rows]
      .map((row) => row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(','))
      .join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `AICyberShield-MultiURL-${batchResult.scannedAt.slice(0, 10)}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <section className="neon-panel rounded-2xl p-5 sm:p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h1 className="text-xl sm:text-2xl font-bold text-slate-900 dark:text-slate-50">Multi-URL Batch Scanner</h1>
            <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400 mt-1">
              Scan up to 10 URLs simultaneously with live DNS, RDAP, SSL/TLS, HTTP, and phishing indicator checks.
            </p>
          </div>
          <span className="font-mono text-xs tabular-nums text-slate-600 dark:text-slate-400 self-start sm:self-center">
            {Math.min(10, parsedUrls.length)}/10 queued
          </span>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <textarea
            rows={5}
            value={urlsText}
            onChange={(e) => {
              setUrlsText(e.target.value);
              if (error) setError(null);
            }}
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            placeholder={'Enter one URL per line (up to 10):\nhttps://github.com\nhttp://paypa1-secure-verify.xyz/login'}
            aria-label="Multiple URLs to scan"
            className="w-full p-4 rounded-xl bg-slate-50 dark:bg-slate-950/90 border border-slate-300 dark:border-sky-500/25 text-xs sm:text-sm font-mono text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:outline-none focus:border-sky-500 focus:ring-2 focus:ring-sky-500/25 resize-y"
          />

          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => setUrlsText(SAMPLE_BATCH)}
                className="min-h-[38px] px-3 py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 dark:bg-slate-900 dark:hover:bg-slate-800 border border-slate-300 dark:border-slate-800 text-xs font-medium text-sky-700 dark:text-sky-300 cursor-pointer"
              >
                Load Sample Batch
              </button>

              <input
                ref={fileInputRef}
                type="file"
                accept=".txt,.csv"
                onChange={(e) => void handleFileUpload(e)}
                className="hidden"
              />
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="min-h-[38px] px-3 py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 dark:bg-slate-900 dark:hover:bg-slate-800 border border-slate-300 dark:border-slate-800 text-xs font-medium text-slate-700 dark:text-slate-200 inline-flex items-center gap-1.5 cursor-pointer"
              >
                <FileUp className="w-3.5 h-3.5" aria-hidden="true" />
                <span>Import .txt/.csv</span>
              </button>

              {urlsText && (
                <button
                  type="button"
                  onClick={() => setUrlsText('')}
                  className="min-h-[38px] px-3 py-1.5 rounded-lg text-xs text-slate-500 hover:text-rose-500 inline-flex items-center gap-1 cursor-pointer"
                >
                  <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>Clear</span>
                </button>
              )}
            </div>

            <button
              type="submit"
              disabled={isScanning || parsedUrls.length === 0}
              className="neon-btn-primary min-h-[46px] px-6 py-2.5 rounded-xl text-sm font-semibold text-white whitespace-nowrap shrink-0 inline-flex items-center justify-center gap-2 transition-all disabled:opacity-45 disabled:cursor-not-allowed cursor-pointer"
            >
              {isScanning ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" />
                  <span>Scanning {Math.min(10, parsedUrls.length)} URLs...</span>
                </>
              ) : (
                <>
                  <Layers className="w-4 h-4" aria-hidden="true" />
                  <span>Scan Batch</span>
                </>
              )}
            </button>
          </div>
        </form>

        {error && (
          <div role="alert" className="p-4 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-500/35 text-xs sm:text-sm text-rose-800 dark:text-rose-200 flex items-start gap-3">
            <ShieldAlert className="w-5 h-5 text-rose-500 shrink-0 mt-0.5" aria-hidden="true" />
            <span>{error}</span>
          </div>
        )}
      </section>

      {isScanning && (
        <section className="neon-panel rounded-2xl p-6 space-y-3 animate-pulse" aria-busy="true">
          <div className="h-5 w-48 bg-slate-200 dark:bg-slate-800 rounded" />
          <div className="h-14 w-full bg-slate-100 dark:bg-slate-900 rounded-xl" />
          <div className="h-14 w-full bg-slate-100 dark:bg-slate-900 rounded-xl" />
        </section>
      )}

      {!isScanning && batchResult && (
        <section className="neon-panel neon-panel-active rounded-2xl p-5 sm:p-6 space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <h2 className="text-lg font-bold text-slate-900 dark:text-slate-50">Batch Scan Results</h2>
              <p className="text-xs text-slate-600 dark:text-slate-400 tabular-nums mt-0.5">
                {batchResult.summary.total} targets · {batchResult.summary.safe} Safe · {batchResult.summary.suspicious} Suspicious ·{' '}
                {batchResult.summary.malicious} Malicious · {batchResult.totalDurationMs} ms
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2 shrink-0">
              <button
                type="button"
                onClick={handleExportCsv}
                className="min-h-[40px] px-3.5 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 dark:bg-slate-900 dark:hover:bg-slate-800 border border-slate-300 dark:border-slate-700 text-xs font-medium text-slate-800 dark:text-slate-200 inline-flex items-center gap-1.5 cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" aria-hidden="true" />
                <span>Export CSV</span>
              </button>
              <button
                type="button"
                onClick={() => downloadBatchScanPdf(batchResult, analyst)}
                className="min-h-[40px] px-3.5 py-2 rounded-xl bg-sky-600 hover:bg-sky-500 text-xs font-semibold text-white inline-flex items-center gap-1.5 cursor-pointer"
              >
                <FileDown className="w-3.5 h-3.5" aria-hidden="true" />
                <span>Download PDF</span>
              </button>
            </div>
          </div>

          <div className="divide-y divide-slate-200 dark:divide-slate-800/80">
            {batchResult.items.map((item, idx) => {
              const isExpanded = expandedIndex === idx;
              const r = item.result;
              return (
                <div key={`${item.inputUrl}-${idx}`} className="py-3.5 space-y-3">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="min-w-0 flex-1">
                      <p className="font-mono text-xs sm:text-sm font-medium text-slate-900 dark:text-slate-100 break-all">
                        {r ? r.signals.normalizedUrl : item.inputUrl}
                      </p>
                      {item.ok && r ? (
                        <p className="text-xs text-slate-600 dark:text-slate-400 mt-0.5 tabular-nums">
                          {r.threatCategory} · DNS: {r.dns.resolved ? 'Resolved' : 'NXDOMAIN'} · TLS:{' '}
                          {r.tls.authorized ? 'Trusted' : r.tls.checked ? 'Untrusted' : 'None'}
                        </p>
                      ) : (
                        <p className="text-xs text-rose-600 dark:text-rose-400 mt-0.5">{item.error}</p>
                      )}
                    </div>

                    <div className="flex items-center justify-between sm:justify-end gap-3 shrink-0">
                      {item.ok && r ? (
                        <>
                          <SeverityIndicator level={r.verdict} />
                          <span className={`font-mono text-xs font-bold tabular-nums ${getScoreAccentClass(r.riskScore)}`}>
                            {r.riskScore}/100
                          </span>
                          <button
                            type="button"
                            onClick={() => downloadUrlScanPdf(r, analyst)}
                            aria-label={`Download PDF for ${r.signals.hostname}`}
                            className="min-h-[36px] px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-slate-200 dark:bg-slate-900 dark:hover:bg-slate-800 border border-slate-300 dark:border-slate-700 text-xs text-slate-700 dark:text-slate-200 inline-flex items-center gap-1 cursor-pointer"
                          >
                            <FileDown className="w-3.5 h-3.5" aria-hidden="true" />
                            <span>PDF</span>
                          </button>
                          <button
                            type="button"
                            onClick={() => setExpandedIndex(isExpanded ? null : idx)}
                            aria-label={isExpanded ? 'Hide evidence' : 'Show evidence'}
                            className="min-h-[36px] min-w-[36px] flex items-center justify-center rounded-lg bg-slate-100 hover:bg-slate-200 dark:bg-slate-900 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300 cursor-pointer"
                          >
                            {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                          </button>
                        </>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-xs font-semibold text-rose-600 dark:text-rose-400">
                          <AlertOctagon className="w-3.5 h-3.5" aria-hidden="true" />
                          <span>Blocked / Error</span>
                        </span>
                      )}
                    </div>
                  </div>

                  {isExpanded && r && (
                    <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950/80 border border-slate-200 dark:border-slate-800 space-y-2 text-xs">
                      <p className="text-slate-700 dark:text-slate-300">{r.summary}</p>
                      <ul className="space-y-1 text-slate-600 dark:text-slate-400">
                        {r.evidenceItems.map((ev) => (
                          <li key={ev.id}>
                            <strong className="text-slate-800 dark:text-slate-200">[{ev.severity}] {ev.title}:</strong> {ev.evidence}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </section>
      )}
    </div>
  );
}
