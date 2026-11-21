import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import {
  BarChart3,
  BellRing,
  Globe,
  KeyRound,
  Layers,
  LayoutDashboard,
  Menu,
  Moon,
  Radar,
  Shield,
  Sun,
  UserCheck,
  UserCircle2,
  X,
} from 'lucide-react';
import { DashboardOverview, type NavTab } from './components/DashboardOverview';
import { MultiUrlScanner } from './components/MultiUrlScanner';
import { PasswordAuditor } from './components/PasswordAuditor';
import { PhishingDetector } from './components/PhishingDetector';
import { SecurityAlerts } from './components/SecurityAlerts';
import { SecurityStats } from './components/SecurityStats';
import { ThreatAnalyzer } from './components/ThreatAnalyzer';
import { UserProfileDashboard } from './components/UserProfileDashboard';
import type {
  AuthSessionResponse,
  PasswordAuditSummary,
  SecurityAlert,
  ThemeMode,
  ThreatAnalysisResult,
  UrlScanResult,
  UserHistoryPayload,
  UserProfile,
} from './types/security';
import {
  loadPasswordAudits,
  loadSecurityAlerts,
  loadThemeMode,
  loadThreatAnalyses,
  loadUrlScans,
  savePasswordAudits,
  saveSecurityAlerts,
  saveThemeMode,
  saveThreatAnalyses,
  saveUrlScans,
} from './utils/storage';

const SIDEBAR_ITEMS: Array<{ id: NavTab; label: string; icon: typeof LayoutDashboard }> = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'phishing', label: 'Phishing Detector', icon: Globe },
  { id: 'multiurl', label: 'Multi-URL Scanner', icon: Layers },
  { id: 'passwords', label: 'Password Auditor', icon: KeyRound },
  { id: 'threats', label: 'Threat Analyzer', icon: Radar },
  { id: 'stats', label: 'Security Stats', icon: BarChart3 },
  { id: 'alerts', label: 'Security Alerts', icon: BellRing },
  { id: 'profile', label: 'Profile & Account', icon: UserCircle2 },
];

const MOBILE_MORE_TABS: NavTab[] = ['passwords', 'threats', 'stats', 'profile'];

function mergeById<T extends { id: string }>(primary: T[], secondary: T[], max: number): T[] {
  const seen = new Set<string>();
  const merged: T[] = [];
  for (const item of [...primary, ...secondary]) {
    if (!seen.has(item.id)) {
      seen.add(item.id);
      merged.push(item);
    }
    if (merged.length >= max) break;
  }
  return merged;
}

export default function App() {
  const [activeTab, setActiveTab] = useState<NavTab>('overview');
  const [pendingQuickUrl, setPendingQuickUrl] = useState<string | null>(null);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const [theme, setTheme] = useState<ThemeMode>(() => loadThemeMode());

  // Authentication state: Bearer token kept strictly in React memory (never persisted to browser storage)
  const [user, setUser] = useState<UserProfile | null>(null);
  const [authToken, setAuthToken] = useState<string | null>(null);
  const historyHydratedRef = useRef(false);

  const [urlScans, setUrlScans] = useState<UrlScanResult[]>(() => loadUrlScans());
  const [threatAnalyses, setThreatAnalyses] = useState<ThreatAnalysisResult[]>(() => loadThreatAnalyses());
  const [passwordAudits, setPasswordAudits] = useState<PasswordAuditSummary[]>(() => loadPasswordAudits());
  const [alerts, setAlerts] = useState<SecurityAlert[]>(() => loadSecurityAlerts());

  // Sync Tailwind .dark root class & mobile browser status-bar theme color
  useLayoutEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark');
    const metaTheme = document.querySelector('meta[name="theme-color"]');
    if (metaTheme) {
      metaTheme.setAttribute('content', theme === 'dark' ? '#060B14' : '#F8FAFC');
    }
  }, [theme]);

  useEffect(() => {
    saveThemeMode(theme);
  }, [theme]);

  useEffect(() => {
    saveUrlScans(urlScans);
  }, [urlScans]);

  useEffect(() => {
    saveThreatAnalyses(threatAnalyses);
  }, [threatAnalyses]);

  useEffect(() => {
    savePasswordAudits(passwordAudits);
  }, [passwordAudits]);

  useEffect(() => {
    saveSecurityAlerts(alerts);
  }, [alerts]);

  // Sync authenticated user's history with backend store (debounced)
  useEffect(() => {
    if (!user || !authToken || !historyHydratedRef.current) return;

    const timer = setTimeout(() => {
      void fetch('/api/user/history', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${authToken}`,
        },
        body: JSON.stringify({
          urlScans,
          threatAnalyses,
          passwordAudits,
          alerts,
        }),
      }).catch(() => {
        // Silent retry on next update; local cache remains intact
      });
    }, 500);

    return () => clearTimeout(timer);
  }, [urlScans, threatAnalyses, passwordAudits, alerts, user, authToken]);

  const handleToggleTheme = (next: ThemeMode) => {
    setTheme(next);
    if (user && authToken) {
      void fetch('/api/profile', {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${authToken}`,
        },
        body: JSON.stringify({ preferredTheme: next }),
      })
        .then((r) => (r.ok ? r.json() : null))
        .then((data) => {
          if (data?.user) setUser(data.user as UserProfile);
        })
        .catch(() => {
          // Non-fatal
        });
    }
  };

  const handleAuthSuccess = (session: AuthSessionResponse) => {
    historyHydratedRef.current = false;
    setAuthToken(session.token);
    setUser(session.user);
    if (session.user.preferredTheme === 'light' || session.user.preferredTheme === 'dark') {
      setTheme(session.user.preferredTheme);
    }

    void fetch('/api/user/history', {
      headers: { Authorization: `Bearer ${session.token}` },
    })
      .then((res) => (res.ok ? res.json() : null))
      .then((remote: UserHistoryPayload | null) => {
        if (remote) {
          setUrlScans((prev) => mergeById(remote.urlScans || [], prev, 25));
          setThreatAnalyses((prev) => mergeById(remote.threatAnalyses || [], prev, 25));
          setPasswordAudits((prev) => mergeById(remote.passwordAudits || [], prev, 25));
          setAlerts((prev) => mergeById(remote.alerts || [], prev, 50));
        }
      })
      .catch(() => {
        // Keep local data cleanly
      })
      .finally(() => {
        historyHydratedRef.current = true;
      });
  };

  const handleLogout = () => {
    const token = authToken;
    historyHydratedRef.current = false;
    setAuthToken(null);
    setUser(null);

    if (token) {
      void fetch('/api/auth/logout', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      }).catch(() => {
        // Token cleared client-side regardless
      });
    }
  };

  const openAlertsCount = alerts.filter((a) => a.status === 'Open').length;
  const activeNavLabel = SIDEBAR_ITEMS.find((item) => item.id === activeTab)?.label || 'Overview';

  const appendAlert = (alert: SecurityAlert) => {
    setAlerts((prev) => [alert, ...prev].slice(0, 50));
  };

  const handleUrlScanComplete = (result: UrlScanResult) => {
    setUrlScans((prev) => [result, ...prev.filter((s) => s.id !== result.id)].slice(0, 25));

    if (result.verdict === 'Malicious' || result.verdict === 'Suspicious') {
      appendAlert({
        id: crypto.randomUUID(),
        createdAt: result.scannedAt,
        source: 'Phishing Detector',
        severity: result.verdict === 'Malicious' ? 'Critical' : 'Medium',
        title: `${result.verdict} URL detected: ${result.signals.hostname}`,
        description: result.summary,
        target: result.signals.normalizedUrl,
        status: 'Open',
      });
    }
  };

  const handleBatchUrlScansComplete = (results: UrlScanResult[]) => {
    if (results.length === 0) return;
    setUrlScans((prev) => mergeById(results, prev, 25));

    const flagged = results.filter((r) => r.verdict === 'Malicious' || r.verdict === 'Suspicious');
    if (flagged.length > 0) {
      const newAlerts: SecurityAlert[] = flagged.map((r) => ({
        id: crypto.randomUUID(),
        createdAt: r.scannedAt,
        source: 'Multi-URL Scanner',
        severity: r.verdict === 'Malicious' ? 'Critical' : 'Medium',
        title: `Batch Scan ${r.verdict}: ${r.signals.hostname}`,
        description: r.summary,
        target: r.signals.normalizedUrl,
        status: 'Open',
      }));
      setAlerts((prev) => [...newAlerts, ...prev].slice(0, 50));
    }
  };

  const handleThreatAnalysisComplete = (result: ThreatAnalysisResult) => {
    setThreatAnalyses((prev) => [result, ...prev.filter((t) => t.id !== result.id)].slice(0, 25));

    if (result.severity === 'Critical' || result.severity === 'High' || result.severity === 'Medium') {
      appendAlert({
        id: crypto.randomUUID(),
        createdAt: result.analyzedAt,
        source: 'Threat Analyzer',
        severity: result.severity,
        title: `${result.threatCategory} (${result.severity})`,
        description: result.summary,
        target: result.attackVector,
        status: 'Open',
      });
    }
  };

  const handlePasswordAuditRecorded = (summary: PasswordAuditSummary) => {
    setPasswordAudits((prev) => [summary, ...prev].slice(0, 25));

    if ((summary.breachCount ?? 0) > 0) {
      appendAlert({
        id: crypto.randomUUID(),
        createdAt: summary.auditedAt,
        source: 'Password Auditor',
        severity: 'Critical',
        title: `Breached credential pattern detected (${summary.breachCount?.toLocaleString()} exposures)`,
        description:
          'An audited password matched public credential breach records via k-anonymity lookup. Rotate immediately on any matching accounts.',
        target: summary.label,
        status: 'Open',
      });
    } else if (summary.score < 35) {
      appendAlert({
        id: crypto.randomUUID(),
        createdAt: summary.auditedAt,
        source: 'Password Auditor',
        severity: 'Medium',
        title: 'Weak password entropy flagged during audit',
        description: `Audited credential scored ${summary.score}/100 (${summary.entropyBits} bits). Replace with a 14+ character passphrase.`,
        target: summary.label,
        status: 'Open',
      });
    }
  };

  const handleQuickScanUrl = (url: string) => {
    setPendingQuickUrl(url);
    setActiveTab('phishing');
  };

  const handleUpdateAlertStatus = (id: string, status: SecurityAlert['status']) => {
    setAlerts((prev) => prev.map((a) => (a.id === id ? { ...a, status } : a)));
  };

  const handleDeleteAlert = (id: string) => {
    setAlerts((prev) => prev.filter((a) => a.id !== id));
  };

  const handleClearResolvedAlerts = () => {
    setAlerts((prev) => prev.filter((a) => a.status !== 'Resolved'));
  };

  const navigateAndCloseSheet = (tab: NavTab) => {
    setActiveTab(tab);
    setMobileMenuOpen(false);
  };

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-[#060B14] text-slate-900 dark:text-slate-100 flex flex-col lg:flex-row transition-colors duration-200">
      {/* Desktop Sidebar */}
      <aside className="hidden lg:flex lg:flex-col lg:w-64 lg:shrink-0 lg:sticky lg:top-0 lg:h-screen bg-white dark:bg-[#080F1D] border-r border-slate-200 dark:border-sky-500/15 transition-colors duration-200">
        <div className="h-16 px-5 flex items-center gap-3 border-b border-slate-200 dark:border-slate-800/80">
          <div className="w-8 h-8 rounded-lg bg-sky-500/15 border border-sky-500/35 flex items-center justify-center shadow-[0_0_15px_rgba(14,165,233,0.22)]">
            <Shield className="w-4 h-4 text-sky-600 dark:text-sky-400" aria-hidden="true" />
          </div>
          <span className="font-display font-bold text-base tracking-tight text-slate-900 dark:text-slate-50 whitespace-nowrap">
            AI CyberShield
          </span>
        </div>

        <nav className="flex-1 p-3 space-y-1 overflow-y-auto" aria-label="Primary navigation">
          {SIDEBAR_ITEMS.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setActiveTab(item.id)}
                className={`w-full min-h-[44px] px-3.5 py-2.5 rounded-xl flex items-center justify-between gap-3 text-sm font-medium transition-colors cursor-pointer whitespace-nowrap ${
                  isActive
                    ? 'bg-sky-50 dark:bg-sky-500/15 text-sky-700 dark:text-sky-300 border border-sky-300 dark:border-sky-400/30 shadow-[0_0_16px_-6px_rgba(56,189,248,0.35)]'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 hover:bg-slate-100 dark:hover:bg-slate-900/80 border border-transparent'
                }`}
              >
                <span className="flex items-center gap-3 min-w-0">
                  <Icon className="w-4 h-4 shrink-0" aria-hidden="true" />
                  <span className="truncate">
                    {item.id === 'profile' && user ? user.name : item.label}
                  </span>
                </span>
                {item.id === 'alerts' && openAlertsCount > 0 && (
                  <span className="font-mono text-xs tabular-nums text-amber-600 dark:text-amber-400 font-semibold">
                    {openAlertsCount}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        <div className="p-4 border-t border-slate-200 dark:border-slate-800/80 text-xs text-slate-500 dark:text-slate-400 space-y-3">
          <button
            type="button"
            onClick={() => handleToggleTheme(theme === 'dark' ? 'light' : 'dark')}
            className="w-full min-h-[40px] px-3 py-2 rounded-xl bg-slate-100 dark:bg-slate-900 hover:bg-slate-200 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-200 font-medium flex items-center justify-between cursor-pointer"
          >
            <span className="flex items-center gap-2">
              {theme === 'dark' ? (
                <Sun className="w-4 h-4 text-amber-400" aria-hidden="true" />
              ) : (
                <Moon className="w-4 h-4 text-sky-600" aria-hidden="true" />
              )}
              <span>{theme === 'dark' ? 'Light Mode' : 'Dark Mode'}</span>
            </span>
            <span className="font-mono text-[11px] uppercase text-slate-500 dark:text-slate-400">
              {theme}
            </span>
          </button>

          <div className="space-y-0.5">
            <p className="font-medium text-slate-700 dark:text-slate-300">Session Telemetry</p>
            <p className="tabular-nums">
              {urlScans.length} URLs · {passwordAudits.length} audits · {threatAnalyses.length} reports
            </p>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 min-w-0 flex flex-col">
        {/* Top Header */}
        <header className="h-14 lg:h-16 px-4 sm:px-6 lg:px-8 border-b border-slate-200 dark:border-slate-800/80 bg-white/90 dark:bg-[#070D19]/90 flex items-center justify-between gap-3 transition-colors duration-200">
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="lg:hidden w-7 h-7 rounded-lg bg-sky-500/15 border border-sky-500/35 flex items-center justify-center shrink-0">
              <Shield className="w-3.5 h-3.5 text-sky-600 dark:text-sky-400" aria-hidden="true" />
            </div>
            <span className="lg:hidden font-display font-bold text-sm text-slate-900 dark:text-slate-50 whitespace-nowrap shrink-0">
              AI CyberShield
            </span>
            <span className="hidden lg:inline text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap">
              AI CyberShield / <span className="text-slate-900 dark:text-slate-100 font-medium">{activeNavLabel}</span>
            </span>
          </div>

          <div className="flex items-center gap-2 sm:gap-2.5 shrink-0">
            <button
              type="button"
              onClick={() => handleToggleTheme(theme === 'dark' ? 'light' : 'dark')}
              aria-label={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
              className="min-h-[40px] min-w-[40px] px-2.5 rounded-xl bg-slate-100 dark:bg-slate-900 hover:bg-slate-200 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-200 inline-flex items-center justify-center gap-1.5 cursor-pointer"
            >
              {theme === 'dark' ? (
                <Sun className="w-4 h-4 text-amber-400" aria-hidden="true" />
              ) : (
                <Moon className="w-4 h-4 text-sky-600" aria-hidden="true" />
              )}
              <span className="hidden md:inline text-xs font-medium whitespace-nowrap">
                {theme === 'dark' ? 'Light' : 'Dark'}
              </span>
            </button>

            <button
              type="button"
              onClick={() => navigateAndCloseSheet('profile')}
              className={`min-h-[40px] px-3 py-1.5 rounded-xl border text-xs font-medium inline-flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer transition-colors ${
                activeTab === 'profile'
                  ? 'bg-sky-50 dark:bg-sky-500/15 border-sky-300 dark:border-sky-400/35 text-sky-700 dark:text-sky-300'
                  : 'bg-slate-100 dark:bg-slate-900 hover:bg-slate-200 dark:hover:bg-slate-800 border-slate-200 dark:border-slate-800 text-slate-800 dark:text-slate-200'
              }`}
            >
              {user ? (
                <UserCheck className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" aria-hidden="true" />
              ) : (
                <UserCircle2 className="w-4 h-4 text-sky-600 dark:text-sky-400 shrink-0" aria-hidden="true" />
              )}
              <span className="max-w-[110px] truncate">{user ? user.name.split(' ')[0] : 'Sign In'}</span>
            </button>

            <button
              type="button"
              onClick={() => navigateAndCloseSheet(activeTab === 'phishing' ? 'multiurl' : 'phishing')}
              className="hidden sm:inline-flex min-h-[40px] px-4 py-1.5 rounded-xl bg-sky-600 hover:bg-sky-500 text-xs font-semibold text-white whitespace-nowrap shrink-0 items-center transition-colors cursor-pointer"
            >
              {activeTab === 'phishing' ? 'Multi-URL Scan' : 'Scan URL'}
            </button>
          </div>
        </header>

        {/* Active Module Viewport (bottom padding on mobile clears the fixed thumb tab bar) */}
        <main className="flex-1 w-full max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-5 sm:py-7 pb-24 lg:pb-10">
          {activeTab === 'overview' && (
            <DashboardOverview
              user={user}
              urlScans={urlScans}
              threatAnalyses={threatAnalyses}
              passwordAudits={passwordAudits}
              alerts={alerts}
              onNavigate={setActiveTab}
              onQuickScanUrl={handleQuickScanUrl}
              onAcknowledgeAlert={(id) => handleUpdateAlertStatus(id, 'Acknowledged')}
            />
          )}

          {activeTab === 'phishing' && (
            <PhishingDetector
              scans={urlScans}
              analyst={user}
              pendingQuickUrl={pendingQuickUrl}
              onClearPendingQuickUrl={() => setPendingQuickUrl(null)}
              onScanComplete={handleUrlScanComplete}
              onClearHistory={() => setUrlScans([])}
            />
          )}

          {activeTab === 'multiurl' && (
            <MultiUrlScanner
              analyst={user}
              onBatchComplete={handleBatchUrlScansComplete}
            />
          )}

          {activeTab === 'passwords' && (
            <PasswordAuditor
              audits={passwordAudits}
              onAuditRecorded={handlePasswordAuditRecorded}
            />
          )}

          {activeTab === 'threats' && (
            <ThreatAnalyzer
              analyses={threatAnalyses}
              analyst={user}
              onAnalysisComplete={handleThreatAnalysisComplete}
              onClearHistory={() => setThreatAnalyses([])}
            />
          )}

          {activeTab === 'stats' && (
            <SecurityStats
              urlScans={urlScans}
              threatAnalyses={threatAnalyses}
              passwordAudits={passwordAudits}
              alerts={alerts}
              analyst={user}
            />
          )}

          {activeTab === 'alerts' && (
            <SecurityAlerts
              alerts={alerts}
              onUpdateAlertStatus={handleUpdateAlertStatus}
              onDeleteAlert={handleDeleteAlert}
              onClearResolved={handleClearResolvedAlerts}
            />
          )}

          {activeTab === 'profile' && (
            <UserProfileDashboard
              user={user}
              authToken={authToken}
              theme={theme}
              onToggleTheme={handleToggleTheme}
              onAuthSuccess={handleAuthSuccess}
              onProfileUpdated={setUser}
              onLogout={handleLogout}
              urlScans={urlScans}
              threatAnalyses={threatAnalyses}
              passwordAudits={passwordAudits}
              alerts={alerts}
            />
          )}
        </main>
      </div>

      {/* Android Mobile "More Tools" Bottom Sheet Drawer */}
      {mobileMenuOpen && (
        <div
          className="lg:hidden fixed inset-0 z-40 bg-slate-950/60 backdrop-blur-xs flex flex-col justify-end"
          onClick={() => setMobileMenuOpen(false)}
        >
          <div
            className="mb-14 bg-white dark:bg-[#0B1426] border-t border-slate-200 dark:border-sky-500/25 rounded-t-3xl p-4 space-y-2 shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-2 pb-2 border-b border-slate-200 dark:border-slate-800">
              <span className="text-sm font-bold text-slate-900 dark:text-slate-100">Security Modules &amp; Account</span>
              <button
                type="button"
                onClick={() => setMobileMenuOpen(false)}
                aria-label="Close tools menu"
                className="min-h-[40px] min-w-[40px] flex items-center justify-center rounded-xl text-slate-500 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer"
              >
                <X className="w-5 h-5" aria-hidden="true" />
              </button>
            </div>

            <div className="grid grid-cols-1 gap-1.5">
              {[
                { id: 'passwords' as NavTab, label: 'Password Strength & Breach Auditor', icon: KeyRound },
                { id: 'threats' as NavTab, label: 'Cyber Threat Analyzer', icon: Radar },
                { id: 'stats' as NavTab, label: 'Advanced Security Statistics', icon: BarChart3 },
                {
                  id: 'profile' as NavTab,
                  label: user ? `Profile · ${user.name}` : 'Sign In / Create Account',
                  icon: user ? UserCheck : UserCircle2,
                },
              ].map((item) => {
                const Icon = item.icon;
                const isActive = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => navigateAndCloseSheet(item.id)}
                    className={`w-full min-h-[48px] px-4 py-3 rounded-xl flex items-center gap-3 text-sm font-medium cursor-pointer transition-colors ${
                      isActive
                        ? 'bg-sky-50 dark:bg-sky-500/15 text-sky-700 dark:text-sky-300 border border-sky-300 dark:border-sky-400/30'
                        : 'text-slate-800 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-900'
                    }`}
                  >
                    <Icon className="w-5 h-5 shrink-0 text-sky-600 dark:text-sky-400" aria-hidden="true" />
                    <span className="truncate">{item.label}</span>
                  </button>
                );
              })}

              <button
                type="button"
                onClick={() => {
                  handleToggleTheme(theme === 'dark' ? 'light' : 'dark');
                  setMobileMenuOpen(false);
                }}
                className="w-full min-h-[48px] px-4 py-3 rounded-xl flex items-center justify-between text-sm font-medium text-slate-800 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-900 cursor-pointer border-t border-slate-200 dark:border-slate-800/80 mt-1"
              >
                <span className="flex items-center gap-3">
                  {theme === 'dark' ? (
                    <Sun className="w-5 h-5 text-amber-500" aria-hidden="true" />
                  ) : (
                    <Moon className="w-5 h-5 text-sky-600" aria-hidden="true" />
                  )}
                  <span>{theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}</span>
                </span>
                <span className="font-mono text-xs uppercase text-slate-500 dark:text-slate-400">{theme}</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Android Mobile Fixed Bottom Thumb Navigation Bar */}
      <nav
        aria-label="Mobile navigation"
        className="lg:hidden fixed bottom-0 left-0 right-0 z-50 bg-white/95 dark:bg-[#070D19]/95 backdrop-blur-md border-t border-slate-200 dark:border-sky-500/20 pb-safe transition-colors duration-200"
      >
        <div className="grid grid-cols-5 h-14 items-center">
          {[
            { id: 'overview' as NavTab, shortLabel: 'Home', icon: LayoutDashboard },
            { id: 'phishing' as NavTab, shortLabel: 'URLs', icon: Globe },
            { id: 'multiurl' as NavTab, shortLabel: 'Batch', icon: Layers },
            { id: 'alerts' as NavTab, shortLabel: 'Alerts', icon: BellRing },
          ].map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id && !mobileMenuOpen;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => navigateAndCloseSheet(item.id)}
                className={`h-full flex flex-col items-center justify-center gap-0.5 relative cursor-pointer transition-colors ${
                  isActive
                    ? 'text-sky-600 dark:text-sky-400'
                    : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                }`}
              >
                <div className="relative">
                  <Icon className="w-5 h-5" aria-hidden="true" />
                  {item.id === 'alerts' && openAlertsCount > 0 && (
                    <span className="absolute -top-1 -right-2 min-w-[14px] h-[14px] px-0.5 rounded-full bg-amber-500 text-[#060B14] font-mono text-[9px] font-bold flex items-center justify-center tabular-nums">
                      {openAlertsCount > 9 ? '9+' : openAlertsCount}
                    </span>
                  )}
                </div>
                <span className="text-[10px] font-medium tracking-tight whitespace-nowrap">
                  {item.shortLabel}
                </span>
              </button>
            );
          })}

          <button
            type="button"
            onClick={() => setMobileMenuOpen((prev) => !prev)}
            className={`h-full flex flex-col items-center justify-center gap-0.5 relative cursor-pointer transition-colors ${
              mobileMenuOpen || MOBILE_MORE_TABS.includes(activeTab)
                ? 'text-sky-600 dark:text-sky-400'
                : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
            }`}
          >
            <Menu className="w-5 h-5" aria-hidden="true" />
            <span className="text-[10px] font-medium tracking-tight whitespace-nowrap">More</span>
          </button>
        </div>
      </nav>
    </div>
  );
}
