import { useMemo, useState } from 'react';
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  Copy,
  Eye,
  EyeOff,
  KeyRound,
  Loader2,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import type { PasswordAuditSummary, PasswordBreachCheckResponse } from '../types/security';
import {
  analyzePasswordStrength,
  computeSha1Parts,
  generateSecurePassphrase,
  generateSecurePassword,
} from '../utils/passwordAudit';

interface PasswordAuditorProps {
  audits: PasswordAuditSummary[];
  onAuditRecorded: (summary: PasswordAuditSummary) => void;
}

export function PasswordAuditor({ audits, onAuditRecorded }: PasswordAuditorProps) {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isCheckingBreach, setIsCheckingBreach] = useState(false);
  const [breachCount, setBreachCount] = useState<number | null>(null);
  const [breachError, setBreachError] = useState<string | null>(null);

  const [genMode, setGenMode] = useState<'random' | 'passphrase'>('random');
  const [genLength, setGenLength] = useState(16);
  const [includeUpper, setIncludeUpper] = useState(true);
  const [includeLower, setIncludeLower] = useState(true);
  const [includeNumbers, setIncludeNumbers] = useState(true);
  const [includeSymbols, setIncludeSymbols] = useState(true);
  const [generatedValue, setGeneratedValue] = useState(() =>
    generateSecurePassword({
      length: 16,
      uppercase: true,
      lowercase: true,
      numbers: true,
      symbols: true,
    }),
  );
  const [copiedGen, setCopiedGen] = useState(false);

  const analysis = useMemo(() => analyzePasswordStrength(password), [password]);

  const handlePasswordChange = (val: string) => {
    setPassword(val);
    setBreachCount(null);
    setBreachError(null);
  };

  const handleBreachCheck = async () => {
    if (!password) return;
    setIsCheckingBreach(true);
    setBreachError(null);

    try {
      const { prefix, suffix } = await computeSha1Parts(password);
      const response = await fetch('/api/check-password-breach', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prefix }),
      });

      const data = await response.json();
      if (!response.ok) {
        setBreachError(data.error || 'Unable to verify against breach database.');
        return;
      }

      const payload = data as PasswordBreachCheckResponse;
      const match = payload.suffixes.find((entry) => entry.suffix === suffix);
      const count = match ? match.count : 0;
      setBreachCount(count);

      onAuditRecorded({
        id: crypto.randomUUID(),
        auditedAt: new Date().toISOString(),
        label: `Audit (${password.length} chars, ${analysis.entropyBits} bits)`,
        strengthLabel: analysis.strengthLabel,
        score: analysis.score,
        entropyBits: analysis.entropyBits,
        breachCount: count,
      });
    } catch (err) {
      setBreachError(err instanceof Error ? err.message : 'Network error checking breach database.');
    } finally {
      setIsCheckingBreach(false);
    }
  };

  const handleGenerate = () => {
    const next =
      genMode === 'passphrase'
        ? generateSecurePassphrase(4)
        : generateSecurePassword({
            length: genLength,
            uppercase: includeUpper,
            lowercase: includeLower,
            numbers: includeNumbers,
            symbols: includeSymbols,
          });
    setGeneratedValue(next);
    setCopiedGen(false);
  };

  const handleCopyGenerated = async () => {
    try {
      await navigator.clipboard.writeText(generatedValue);
      setCopiedGen(true);
      setTimeout(() => setCopiedGen(false), 1800);
    } catch {
      // Clipboard blocked in restricted frame
    }
  };

  const strengthColor =
    analysis.score >= 82
      ? 'text-emerald-600 dark:text-emerald-400'
      : analysis.score >= 64
        ? 'text-sky-600 dark:text-sky-400'
        : analysis.score >= 42
          ? 'text-amber-600 dark:text-amber-400'
          : 'text-rose-600 dark:text-rose-400';

  const barColor =
    analysis.score >= 82
      ? 'bg-emerald-500'
      : analysis.score >= 64
        ? 'bg-sky-500'
        : analysis.score >= 42
          ? 'bg-amber-500'
          : 'bg-rose-500';

  return (
    <div className="space-y-6">
      {/* Main Password Auditor */}
      <section className="neon-panel rounded-2xl p-5 sm:p-6 space-y-5">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-slate-900 dark:text-slate-50">
            Password Strength &amp; Breach Auditor
          </h1>
          <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400 mt-1">
            Entropy and pattern checks run locally on your device. Breach lookup uses k-anonymity (only a 5-character SHA-1 prefix is sent; your password never leaves the browser).
          </p>
        </div>

        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <input
              type={showPassword ? 'text' : 'password'}
              value={password}
              onChange={(e) => handlePasswordChange(e.target.value)}
              placeholder="Type or paste a password to audit..."
              aria-label="Password to audit"
              autoComplete="off"
              className="w-full min-h-[46px] pl-4 pr-12 py-2.5 rounded-xl bg-slate-50 dark:bg-slate-950/90 border border-slate-300 dark:border-sky-500/25 text-sm font-mono text-slate-900 dark:text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-500 dark:focus:border-sky-400 focus:ring-2 focus:ring-sky-500/25"
            />
            <button
              type="button"
              onClick={() => setShowPassword((prev) => !prev)}
              aria-label={showPassword ? 'Hide password' : 'Show password'}
              className="absolute right-1.5 top-1/2 -translate-y-1/2 min-w-[40px] min-h-[40px] flex items-center justify-center rounded-lg text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 cursor-pointer"
            >
              {showPassword ? <EyeOff className="w-4 h-4" aria-hidden="true" /> : <Eye className="w-4 h-4" aria-hidden="true" />}
            </button>
          </div>

          <button
            type="button"
            disabled={!password || isCheckingBreach}
            onClick={() => void handleBreachCheck()}
            className="neon-btn-primary min-h-[46px] px-5 py-2.5 rounded-xl text-sm font-semibold text-white whitespace-nowrap shrink-0 inline-flex items-center justify-center gap-2 transition-all disabled:opacity-45 disabled:cursor-not-allowed cursor-pointer"
          >
            {isCheckingBreach ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" />
                <span>Checking Breaches...</span>
              </>
            ) : (
              <>
                <KeyRound className="w-4 h-4" aria-hidden="true" />
                <span>Check Data Breaches</span>
              </>
            )}
          </button>
        </div>

        {/* Strength Meter & Metrics */}
        <div className="space-y-3 pt-1">
          <div className="flex items-center justify-between text-xs sm:text-sm">
            <div className="flex items-center gap-2">
              <span className="text-slate-600 dark:text-slate-400">Strength:</span>
              <span className={`font-semibold ${password ? strengthColor : 'text-slate-500'}`}>
                {password ? analysis.strengthLabel : 'Waiting for input'}
              </span>
            </div>
            <span className="font-mono tabular-nums text-slate-700 dark:text-slate-300">
              {analysis.entropyBits} bits · {analysis.score}/100
            </span>
          </div>

          <div className="h-2.5 w-full rounded-full bg-slate-200 dark:bg-slate-900 overflow-hidden">
            <div
              className={`h-full transition-all duration-200 ${password ? barColor : 'bg-slate-300 dark:bg-slate-800'}`}
              style={{ width: `${password ? Math.max(4, analysis.score) : 0}%` }}
            />
          </div>

          {/* Character Classes */}
          <div className="flex flex-wrap items-center gap-x-5 gap-y-2 text-xs pt-1">
            {[
              { label: 'Lowercase', ok: analysis.charClasses.lowercase },
              { label: 'Uppercase', ok: analysis.charClasses.uppercase },
              { label: 'Numbers', ok: analysis.charClasses.numbers },
              { label: 'Symbols', ok: analysis.charClasses.symbols },
              { label: 'NIST 800-63B', ok: analysis.nistCompliant },
            ].map((item) => (
              <span
                key={item.label}
                className={`inline-flex items-center gap-1.5 ${
                  item.ok ? 'text-emerald-600 dark:text-emerald-400 font-medium' : 'text-slate-500'
                }`}
              >
                <CheckCircle2 className="w-3.5 h-3.5" aria-hidden="true" />
                <span>{item.label}</span>
              </span>
            ))}
          </div>
        </div>

        {/* Breach Lookup Result Banner */}
        {breachError && (
          <div
            role="alert"
            className="p-4 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-500/35 text-xs sm:text-sm text-rose-700 dark:text-rose-200"
          >
            {breachError}
          </div>
        )}

        {breachCount !== null && (
          <div
            className={`p-4 rounded-xl border flex items-start gap-3 ${
              breachCount > 0
                ? 'bg-rose-50 dark:bg-rose-950/40 border-rose-200 dark:border-rose-500/40 text-rose-900 dark:text-rose-100'
                : 'bg-emerald-50 dark:bg-emerald-950/35 border-emerald-200 dark:border-emerald-500/35 text-emerald-900 dark:text-emerald-100'
            }`}
          >
            {breachCount > 0 ? (
              <ShieldAlert className="w-5 h-5 text-rose-600 dark:text-rose-400 shrink-0 mt-0.5" aria-hidden="true" />
            ) : (
              <ShieldCheck className="w-5 h-5 text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5" aria-hidden="true" />
            )}
            <div>
              <p className="text-sm font-semibold">
                {breachCount > 0
                  ? `Exposed in ${breachCount.toLocaleString()} known data breach records`
                  : 'Not found in known public password breaches'}
              </p>
              <p className="text-xs opacity-90 mt-1">
                {breachCount > 0
                  ? 'Do not use this password anywhere. Automated credential-stuffing bots test leaked passwords first.'
                  : 'Verified via Have I Been Pwned k-anonymity range lookup. Continue pairing with multi-factor authentication.'}
              </p>
            </div>
          </div>
        )}

        {/* Crack Time Estimates */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2 border-t border-slate-200 dark:border-slate-800/80">
          <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800/80">
            <p className="text-xs text-slate-600 dark:text-slate-400">Online Rate-Limited (100/hr)</p>
            <p className="mt-1 text-base font-mono font-semibold tabular-nums text-slate-900 dark:text-slate-100">
              {analysis.crackTimes.onlineThrottled}
            </p>
          </div>
          <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800/80">
            <p className="text-xs text-slate-600 dark:text-slate-400">Offline GPU Rig (10B/sec)</p>
            <p className="mt-1 text-base font-mono font-semibold tabular-nums text-slate-900 dark:text-slate-100">
              {analysis.crackTimes.offlineGpuRig}
            </p>
          </div>
          <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800/80">
            <p className="text-xs text-slate-600 dark:text-slate-400">Massive Cluster (1T/sec)</p>
            <p className="mt-1 text-base font-mono font-semibold tabular-nums text-slate-900 dark:text-slate-100">
              {analysis.crackTimes.massiveCluster}
            </p>
          </div>
        </div>

        {/* Warnings & Suggestions */}
        {password && (analysis.warnings.length > 0 || analysis.suggestions.length > 0) && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2 border-t border-slate-200 dark:border-slate-800/80 text-xs sm:text-sm">
            {analysis.warnings.length > 0 && (
              <div className="space-y-2">
                <p className="font-semibold text-amber-700 dark:text-amber-300">Detected Weaknesses</p>
                <ul className="space-y-1.5 text-slate-700 dark:text-slate-300">
                  {analysis.warnings.map((w, i) => (
                    <li key={i} className="flex items-start gap-2">
                      <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" aria-hidden="true" />
                      <span>{w}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {analysis.suggestions.length > 0 && (
              <div className="space-y-2">
                <p className="font-semibold text-sky-700 dark:text-sky-300">Hardening Recommendations</p>
                <ul className="space-y-1.5 text-slate-700 dark:text-slate-300">
                  {analysis.suggestions.map((s, i) => (
                    <li key={i} className="flex items-start gap-2">
                      <CheckCircle2 className="w-4 h-4 text-sky-600 dark:text-sky-400 shrink-0 mt-0.5" aria-hidden="true" />
                      <span>{s}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </section>

      {/* Cryptographic Password Generator */}
      <section className="neon-panel rounded-2xl p-5 sm:p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-base sm:text-lg font-semibold text-slate-900 dark:text-slate-50">
              Cryptographic Password Generator
            </h2>
            <p className="text-xs text-slate-600 dark:text-slate-400 mt-0.5">
              Generated using Web Crypto CSPRNG (<code className="font-mono text-slate-800 dark:text-slate-300">crypto.getRandomValues</code>)
            </p>
          </div>

          <div className="inline-flex p-1 rounded-xl bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 self-start">
            <button
              type="button"
              onClick={() => {
                setGenMode('random');
                setGeneratedValue(
                  generateSecurePassword({
                    length: genLength,
                    uppercase: includeUpper,
                    lowercase: includeLower,
                    numbers: includeNumbers,
                    symbols: includeSymbols,
                  }),
                );
              }}
              className={`min-h-[36px] px-3 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                genMode === 'random'
                  ? 'bg-sky-600 text-white'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
              }`}
            >
              Random String
            </button>
            <button
              type="button"
              onClick={() => {
                setGenMode('passphrase');
                setGeneratedValue(generateSecurePassphrase(4));
              }}
              className={`min-h-[36px] px-3 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                genMode === 'passphrase'
                  ? 'bg-sky-600 text-white'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
              }`}
            >
              Passphrase
            </button>
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950/90 border border-slate-200 dark:border-sky-500/20 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <code className="font-mono text-sm sm:text-base text-sky-700 dark:text-sky-200 break-all select-all">
            {generatedValue}
          </code>
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={handleGenerate}
              className="min-h-[42px] px-3.5 py-2 rounded-lg bg-white dark:bg-slate-900 hover:bg-slate-100 dark:hover:bg-slate-800 border border-slate-300 dark:border-slate-700 text-xs font-medium text-slate-700 dark:text-slate-200 inline-flex items-center gap-1.5 cursor-pointer"
            >
              <RefreshCw className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Regenerate</span>
            </button>
            <button
              type="button"
              onClick={() => void handleCopyGenerated()}
              className="min-h-[42px] px-3.5 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 text-xs font-semibold text-white inline-flex items-center gap-1.5 cursor-pointer"
            >
              {copiedGen ? <Check className="w-3.5 h-3.5" aria-hidden="true" /> : <Copy className="w-3.5 h-3.5" aria-hidden="true" />}
              <span>{copiedGen ? 'Copied' : 'Copy'}</span>
            </button>
            <button
              type="button"
              onClick={() => handlePasswordChange(generatedValue)}
              className="min-h-[42px] px-3.5 py-2 rounded-lg bg-sky-50 dark:bg-slate-800 hover:bg-sky-100 dark:hover:bg-slate-700 border border-sky-200 dark:border-transparent text-xs font-medium text-sky-700 dark:text-sky-300 cursor-pointer"
            >
              Audit This
            </button>
          </div>
        </div>

        {genMode === 'random' && (
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pt-1">
            <label className="flex items-center gap-3 text-xs text-slate-700 dark:text-slate-300">
              <span className="whitespace-nowrap">
                Length: <strong className="font-mono tabular-nums text-sky-700 dark:text-sky-300">{genLength}</strong>
              </span>
              <input
                type="range"
                min={10}
                max={32}
                value={genLength}
                onChange={(e) => {
                  const len = Number(e.target.value);
                  setGenLength(len);
                  setGeneratedValue(
                    generateSecurePassword({
                      length: len,
                      uppercase: includeUpper,
                      lowercase: includeLower,
                      numbers: includeNumbers,
                      symbols: includeSymbols,
                    }),
                  );
                }}
                className="w-36 accent-sky-500 cursor-pointer"
              />
            </label>

            <div className="flex flex-wrap items-center gap-4 text-xs text-slate-700 dark:text-slate-300">
              {[
                { label: 'A-Z', checked: includeUpper, toggle: () => setIncludeUpper((v) => !v) },
                { label: 'a-z', checked: includeLower, toggle: () => setIncludeLower((v) => !v) },
                { label: '0-9', checked: includeNumbers, toggle: () => setIncludeNumbers((v) => !v) },
                { label: '!@#', checked: includeSymbols, toggle: () => setIncludeSymbols((v) => !v) },
              ].map((opt) => (
                <label key={opt.label} className="inline-flex items-center gap-2 cursor-pointer min-h-[36px]">
                  <input
                    type="checkbox"
                    checked={opt.checked}
                    onChange={opt.toggle}
                    className="w-4 h-4 rounded accent-sky-500"
                  />
                  <span className="font-mono">{opt.label}</span>
                </label>
              ))}
            </div>
          </div>
        )}
      </section>

      {/* Anonymous Audit Log */}
      {audits.length > 0 && (
        <section className="neon-panel rounded-2xl p-5 sm:p-6">
          <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100 mb-3">
            Recent Audit Log (Metadata Only)
          </h3>
          <div className="divide-y divide-slate-200 dark:divide-slate-800/80">
            {audits.slice(0, 6).map((item) => (
              <div key={item.id} className="py-2.5 flex items-center justify-between gap-4 text-xs">
                <div className="min-w-0">
                  <p className="text-slate-800 dark:text-slate-200 font-medium truncate">{item.label}</p>
                  <p className="text-slate-500 dark:text-slate-400 tabular-nums mt-0.5">
                    {new Date(item.auditedAt).toLocaleString([], {
                      month: 'short',
                      day: 'numeric',
                      hour: '2-digit',
                      minute: '2-digit',
                    })}
                  </p>
                </div>
                <div className="text-right shrink-0 tabular-nums">
                  <p className="font-semibold text-slate-900 dark:text-slate-100">{item.strengthLabel}</p>
                  <p className={item.breachCount && item.breachCount > 0 ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'}>
                    {item.breachCount && item.breachCount > 0
                      ? `${item.breachCount.toLocaleString()} breaches`
                      : '0 breaches'}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
