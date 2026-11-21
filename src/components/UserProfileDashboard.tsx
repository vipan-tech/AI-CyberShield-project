import { useMemo, useState, type FormEvent } from 'react';
import {
  CheckCircle2,
  Download,
  Eye,
  EyeOff,
  KeyRound,
  Loader2,
  LogIn,
  LogOut,
  Moon,
  ShieldAlert,
  Sun,
  UserCheck,
  UserPlus,
} from 'lucide-react';
import type {
  AuthSessionResponse,
  PasswordAuditSummary,
  SecurityAlert,
  ThemeMode,
  ThreatAnalysisResult,
  UrlScanResult,
  UserProfile,
} from '../types/security';
import { analyzePasswordStrength } from '../utils/passwordAudit';

interface UserProfileDashboardProps {
  user: UserProfile | null;
  authToken: string | null;
  theme: ThemeMode;
  onToggleTheme: (next: ThemeMode) => void;
  onAuthSuccess: (session: AuthSessionResponse) => void;
  onProfileUpdated: (user: UserProfile) => void;
  onLogout: () => void;
  urlScans: UrlScanResult[];
  threatAnalyses: ThreatAnalysisResult[];
  passwordAudits: PasswordAuditSummary[];
  alerts: SecurityAlert[];
}

export function UserProfileDashboard({
  user,
  authToken,
  theme,
  onToggleTheme,
  onAuthSuccess,
  onProfileUpdated,
  onLogout,
  urlScans,
  threatAnalyses,
  passwordAudits,
  alerts,
}: UserProfileDashboardProps) {
  const [authMode, setAuthMode] = useState<'login' | 'signup'>('login');
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [organization, setOrganization] = useState('');
  const [roleTitle, setRoleTitle] = useState('');
  const [authLoading, setAuthLoading] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);

  // Profile edit state
  const [editName, setEditName] = useState(user?.name || '');
  const [editOrg, setEditOrg] = useState(user?.organization || '');
  const [editRole, setEditRole] = useState(user?.roleTitle || '');
  const [profileSaving, setProfileSaving] = useState(false);
  const [profileMsg, setProfileMsg] = useState<string | null>(null);

  // Change password state
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [pwSaving, setPwSaving] = useState(false);
  const [pwMsg, setPwMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const signupPwCheck = useMemo(() => analyzePasswordStrength(password), [password]);

  const handleAuthSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setAuthLoading(true);
    setAuthError(null);

    const endpoint = authMode === 'signup' ? '/api/auth/signup' : '/api/auth/login';
    const payload =
      authMode === 'signup'
        ? {
            name: name.trim(),
            email: email.trim(),
            password,
            organization: organization.trim() || 'College Cybersecurity Lab',
            roleTitle: roleTitle.trim() || 'Security Analyst',
            preferredTheme: theme,
          }
        : {
            email: email.trim(),
            password,
          };

    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await response.json();
      if (!response.ok) {
        setAuthError(data.error || 'Authentication failed.');
        return;
      }

      const session = data as AuthSessionResponse;
      setEditName(session.user.name);
      setEditOrg(session.user.organization);
      setEditRole(session.user.roleTitle);
      setPassword('');
      onAuthSuccess(session);
    } catch (err) {
      setAuthError(err instanceof Error ? err.message : 'Network error during authentication.');
    } finally {
      setAuthLoading(false);
    }
  };

  const handleSaveProfile = async (e: FormEvent) => {
    e.preventDefault();
    if (!authToken) return;
    setProfileSaving(true);
    setProfileMsg(null);

    try {
      const response = await fetch('/api/profile', {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${authToken}`,
        },
        body: JSON.stringify({
          name: editName.trim(),
          organization: editOrg.trim(),
          roleTitle: editRole.trim(),
          preferredTheme: theme,
        }),
      });
      const data = await response.json();
      if (!response.ok) {
        setProfileMsg(data.error || 'Unable to update profile.');
        return;
      }
      onProfileUpdated(data.user as UserProfile);
      setProfileMsg('Profile saved to your account.');
    } catch (err) {
      setProfileMsg(err instanceof Error ? err.message : 'Network error saving profile.');
    } finally {
      setProfileSaving(false);
    }
  };

  const handleChangePassword = async (e: FormEvent) => {
    e.preventDefault();
    if (!authToken) return;
    setPwSaving(true);
    setPwMsg(null);

    try {
      const response = await fetch('/api/auth/change-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${authToken}`,
        },
        body: JSON.stringify({ currentPassword, newPassword }),
      });
      const data = await response.json();
      if (!response.ok) {
        setPwMsg({ ok: false, text: data.error || 'Password update failed.' });
        return;
      }
      setCurrentPassword('');
      setNewPassword('');
      setPwMsg({ ok: true, text: 'Password updated securely with salted scrypt hashing.' });
    } catch (err) {
      setPwMsg({ ok: false, text: err instanceof Error ? err.message : 'Network error updating password.' });
    } finally {
      setPwSaving(false);
    }
  };

  const handleExportAccountData = () => {
    const bundle = {
      exportedAt: new Date().toISOString(),
      profile: user,
      stats: {
        urlScans: urlScans.length,
        threatAnalyses: threatAnalyses.length,
        passwordAudits: passwordAudits.length,
        alerts: alerts.length,
      },
      urlScans,
      threatAnalyses,
      alerts,
    };
    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `AICyberShield-Account-Backup-${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  // --- Signed Out: Secure Login & Signup View ---
  if (!user || !authToken) {
    return (
      <div className="max-w-xl mx-auto space-y-6">
        <section className="neon-panel rounded-2xl p-5 sm:p-7 space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h1 className="text-xl sm:text-2xl font-bold text-slate-900 dark:text-slate-50">
                {authMode === 'login' ? 'Sign In to AI CyberShield' : 'Create Analyst Account'}
              </h1>
              <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400 mt-1">
                Sync your scan reports, threat analyses, and theme preference securely across sessions.
              </p>
            </div>

            <div className="inline-flex p-1 rounded-xl bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 self-start shrink-0">
              <button
                type="button"
                onClick={() => {
                  setAuthMode('login');
                  setAuthError(null);
                }}
                className={`min-h-[38px] px-3.5 py-1.5 rounded-lg text-xs font-medium cursor-pointer ${
                  authMode === 'login' ? 'bg-sky-600 text-white' : 'text-slate-600 dark:text-slate-400'
                }`}
              >
                Login
              </button>
              <button
                type="button"
                onClick={() => {
                  setAuthMode('signup');
                  setAuthError(null);
                }}
                className={`min-h-[38px] px-3.5 py-1.5 rounded-lg text-xs font-medium cursor-pointer ${
                  authMode === 'signup' ? 'bg-sky-600 text-white' : 'text-slate-600 dark:text-slate-400'
                }`}
              >
                Sign Up
              </button>
            </div>
          </div>

          <form onSubmit={handleAuthSubmit} className="space-y-4">
            {authMode === 'signup' && (
              <div>
                <label htmlFor="auth-name" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                  Full Name
                </label>
                <input
                  id="auth-name"
                  type="text"
                  required
                  minLength={2}
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Aarav Sharma"
                  className="w-full min-h-[44px] px-3.5 py-2.5 rounded-xl bg-slate-50 dark:bg-slate-950/90 border border-slate-300 dark:border-sky-500/25 text-sm text-slate-900 dark:text-slate-100 focus:outline-none focus:border-sky-500"
                />
              </div>
            )}

            <div>
              <label htmlFor="auth-email" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                Email Address
              </label>
              <input
                id="auth-email"
                type="email"
                inputMode="email"
                autoCapitalize="none"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@college.edu"
                className="w-full min-h-[44px] px-3.5 py-2.5 rounded-xl bg-slate-50 dark:bg-slate-950/90 border border-slate-300 dark:border-sky-500/25 text-sm text-slate-900 dark:text-slate-100 focus:outline-none focus:border-sky-500"
              />
            </div>

            <div>
              <label htmlFor="auth-password" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                Password {authMode === 'signup' && <span className="text-slate-400">(minimum 8 characters)</span>}
              </label>
              <div className="relative">
                <input
                  id="auth-password"
                  type={showPw ? 'text' : 'password'}
                  required
                  minLength={authMode === 'signup' ? 8 : 1}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full min-h-[44px] pl-3.5 pr-11 py-2.5 rounded-xl bg-slate-50 dark:bg-slate-950/90 border border-slate-300 dark:border-sky-500/25 text-sm font-mono text-slate-900 dark:text-slate-100 focus:outline-none focus:border-sky-500"
                />
                <button
                  type="button"
                  onClick={() => setShowPw((v) => !v)}
                  aria-label={showPw ? 'Hide password' : 'Show password'}
                  className="absolute right-1.5 top-1/2 -translate-y-1/2 min-w-[38px] min-h-[38px] flex items-center justify-center rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer"
                >
                  {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              {authMode === 'signup' && password.length > 0 && (
                <p className="mt-1.5 text-xs text-slate-500 dark:text-slate-400">
                  Strength: <strong className="text-sky-600 dark:text-sky-400">{signupPwCheck.strengthLabel}</strong> ({signupPwCheck.entropyBits} bits)
                </p>
              )}
            </div>

            {authMode === 'signup' && (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label htmlFor="auth-org" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                    College / Organization
                  </label>
                  <input
                    id="auth-org"
                    type="text"
                    value={organization}
                    onChange={(e) => setOrganization(e.target.value)}
                    placeholder="Department of CSE"
                    className="w-full min-h-[44px] px-3.5 py-2.5 rounded-xl bg-slate-50 dark:bg-slate-950/90 border border-slate-300 dark:border-sky-500/25 text-sm text-slate-900 dark:text-slate-100 focus:outline-none focus:border-sky-500"
                  />
                </div>
                <div>
                  <label htmlFor="auth-role" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                    Role Title
                  </label>
                  <input
                    id="auth-role"
                    type="text"
                    value={roleTitle}
                    onChange={(e) => setRoleTitle(e.target.value)}
                    placeholder="Security Researcher"
                    className="w-full min-h-[44px] px-3.5 py-2.5 rounded-xl bg-slate-50 dark:bg-slate-950/90 border border-slate-300 dark:border-sky-500/25 text-sm text-slate-900 dark:text-slate-100 focus:outline-none focus:border-sky-500"
                  />
                </div>
              </div>
            )}

            {authError && (
              <div role="alert" className="p-3.5 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-500/35 text-xs text-rose-700 dark:text-rose-200 flex items-start gap-2.5">
                <ShieldAlert className="w-4 h-4 text-rose-500 shrink-0 mt-0.5" aria-hidden="true" />
                <span>{authError}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={authLoading}
              className="neon-btn-primary w-full min-h-[46px] px-5 py-2.5 rounded-xl text-sm font-semibold text-white inline-flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
            >
              {authLoading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" />
                  <span>{authMode === 'signup' ? 'Creating Account...' : 'Signing In...'}</span>
                </>
              ) : authMode === 'signup' ? (
                <>
                  <UserPlus className="w-4 h-4" aria-hidden="true" />
                  <span>Create Account</span>
                </>
              ) : (
                <>
                  <LogIn className="w-4 h-4" aria-hidden="true" />
                  <span>Sign In</span>
                </>
              )}
            </button>
          </form>

          <p className="text-xs text-slate-500 dark:text-slate-400 pt-2 border-t border-slate-200 dark:border-slate-800/80">
            Passwords are salted and hashed on the server with Node <code className="font-mono">scrypt</code>; session tokens use HMAC-SHA256 verification and remain strictly in memory.
          </p>
        </section>
      </div>
    );
  }

  // --- Signed In: User Profile Dashboard ---
  return (
    <div className="space-y-6">
      {/* Profile Hero Card */}
      <section className="neon-panel rounded-2xl p-5 sm:p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-4 min-w-0">
          <div className="w-12 h-12 rounded-2xl bg-sky-500/15 border border-sky-400/35 flex items-center justify-center text-sky-600 dark:text-sky-400 font-display font-bold text-lg shrink-0">
            {user.name.slice(0, 2).toUpperCase()}
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2 text-xs text-emerald-600 dark:text-emerald-400 font-medium">
              <UserCheck className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
              <span>Authenticated Analyst Session</span>
            </div>
            <h1 className="text-lg sm:text-xl font-bold text-slate-900 dark:text-slate-50 truncate mt-0.5">
              {user.name}
            </h1>
            <p className="text-xs text-slate-600 dark:text-slate-400 truncate">
              {user.roleTitle} · {user.organization} · {user.email}
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={handleExportAccountData}
            className="min-h-[42px] px-3.5 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 dark:bg-slate-900 dark:hover:bg-slate-800 border border-slate-300 dark:border-slate-700 text-xs font-medium text-slate-800 dark:text-slate-200 inline-flex items-center gap-1.5 cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" aria-hidden="true" />
            <span>Backup JSON</span>
          </button>
          <button
            type="button"
            onClick={onLogout}
            className="min-h-[42px] px-3.5 py-2 rounded-xl bg-rose-50 hover:bg-rose-100 dark:bg-rose-950/50 dark:hover:bg-rose-950 border border-rose-200 dark:border-rose-500/30 text-xs font-semibold text-rose-700 dark:text-rose-300 inline-flex items-center gap-1.5 cursor-pointer"
          >
            <LogOut className="w-3.5 h-3.5" aria-hidden="true" />
            <span>Sign Out</span>
          </button>
        </div>
      </section>

      {/* Account Activity Metrics */}
      <section className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
        <div className="neon-panel rounded-2xl p-4">
          <p className="text-xs text-slate-500 dark:text-slate-400">Saved URL Scans</p>
          <p className="mt-1.5 text-2xl font-bold font-mono tabular-nums text-slate-900 dark:text-slate-50">
            {urlScans.length}
          </p>
        </div>
        <div className="neon-panel rounded-2xl p-4">
          <p className="text-xs text-slate-500 dark:text-slate-400">Threat Reports</p>
          <p className="mt-1.5 text-2xl font-bold font-mono tabular-nums text-slate-900 dark:text-slate-50">
            {threatAnalyses.length}
          </p>
        </div>
        <div className="neon-panel rounded-2xl p-4">
          <p className="text-xs text-slate-500 dark:text-slate-400">Password Audits</p>
          <p className="mt-1.5 text-2xl font-bold font-mono tabular-nums text-slate-900 dark:text-slate-50">
            {passwordAudits.length}
          </p>
        </div>
        <div className="neon-panel rounded-2xl p-4">
          <p className="text-xs text-slate-500 dark:text-slate-400">Member Since</p>
          <p className="mt-1.5 text-sm font-mono tabular-nums font-semibold text-slate-900 dark:text-slate-50">
            {new Date(user.createdAt).toLocaleDateString()}
          </p>
        </div>
      </section>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Edit Profile & Theme */}
        <section className="neon-panel rounded-2xl p-5 sm:p-6 space-y-4">
          <h2 className="text-base font-semibold text-slate-900 dark:text-slate-50">Profile &amp; Appearance</h2>

          <form onSubmit={handleSaveProfile} className="space-y-3.5">
            <div>
              <label htmlFor="prof-name" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                Full Name
              </label>
              <input
                id="prof-name"
                type="text"
                required
                value={editName}
                onChange={(e) => setEditName(e.target.value)}
                className="w-full min-h-[42px] px-3.5 py-2 rounded-xl bg-slate-50 dark:bg-slate-950/90 border border-slate-300 dark:border-slate-800 text-sm text-slate-900 dark:text-slate-100 focus:outline-none focus:border-sky-500"
              />
            </div>

            <div>
              <label htmlFor="prof-org" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                College / Organization
              </label>
              <input
                id="prof-org"
                type="text"
                value={editOrg}
                onChange={(e) => setEditOrg(e.target.value)}
                className="w-full min-h-[42px] px-3.5 py-2 rounded-xl bg-slate-50 dark:bg-slate-950/90 border border-slate-300 dark:border-slate-800 text-sm text-slate-900 dark:text-slate-100 focus:outline-none focus:border-sky-500"
              />
            </div>

            <div>
              <label htmlFor="prof-role" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                Role Title
              </label>
              <input
                id="prof-role"
                type="text"
                value={editRole}
                onChange={(e) => setEditRole(e.target.value)}
                className="w-full min-h-[42px] px-3.5 py-2 rounded-xl bg-slate-50 dark:bg-slate-950/90 border border-slate-300 dark:border-slate-800 text-sm text-slate-900 dark:text-slate-100 focus:outline-none focus:border-sky-500"
              />
            </div>

            <div>
              <span className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">Theme Mode</span>
              <div className="inline-flex p-1 rounded-xl bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                <button
                  type="button"
                  onClick={() => onToggleTheme('dark')}
                  className={`min-h-[38px] px-3.5 py-1.5 rounded-lg text-xs font-medium inline-flex items-center gap-1.5 cursor-pointer ${
                    theme === 'dark' ? 'bg-sky-600 text-white' : 'text-slate-600 dark:text-slate-400'
                  }`}
                >
                  <Moon className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>Dark Neon</span>
                </button>
                <button
                  type="button"
                  onClick={() => onToggleTheme('light')}
                  className={`min-h-[38px] px-3.5 py-1.5 rounded-lg text-xs font-medium inline-flex items-center gap-1.5 cursor-pointer ${
                    theme === 'light' ? 'bg-sky-600 text-white' : 'text-slate-600 dark:text-slate-400'
                  }`}
                >
                  <Sun className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>Light Clean</span>
                </button>
              </div>
            </div>

            {profileMsg && (
              <p className="text-xs text-emerald-600 dark:text-emerald-400 flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
                <span>{profileMsg}</span>
              </p>
            )}

            <button
              type="submit"
              disabled={profileSaving}
              className="neon-btn-primary min-h-[44px] px-5 py-2 rounded-xl text-xs sm:text-sm font-semibold text-white cursor-pointer disabled:opacity-50"
            >
              {profileSaving ? 'Saving...' : 'Save Profile'}
            </button>
          </form>
        </section>

        {/* Change Password */}
        <section className="neon-panel rounded-2xl p-5 sm:p-6 space-y-4">
          <div className="flex items-center gap-2">
            <KeyRound className="w-4 h-4 text-sky-500" aria-hidden="true" />
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-50">Update Account Password</h2>
          </div>

          <form onSubmit={handleChangePassword} className="space-y-3.5">
            <div>
              <label htmlFor="cur-pw" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                Current Password
              </label>
              <input
                id="cur-pw"
                type="password"
                required
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                className="w-full min-h-[42px] px-3.5 py-2 rounded-xl bg-slate-50 dark:bg-slate-950/90 border border-slate-300 dark:border-slate-800 text-sm font-mono text-slate-900 dark:text-slate-100 focus:outline-none focus:border-sky-500"
              />
            </div>

            <div>
              <label htmlFor="new-pw" className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                New Password (min 8 chars)
              </label>
              <input
                id="new-pw"
                type="password"
                required
                minLength={8}
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="w-full min-h-[42px] px-3.5 py-2 rounded-xl bg-slate-50 dark:bg-slate-950/90 border border-slate-300 dark:border-slate-800 text-sm font-mono text-slate-900 dark:text-slate-100 focus:outline-none focus:border-sky-500"
              />
            </div>

            {pwMsg && (
              <p className={`text-xs ${pwMsg.ok ? 'text-emerald-600 dark:text-emerald-400' : 'text-rose-600 dark:text-rose-400'}`}>
                {pwMsg.text}
              </p>
            )}

            <button
              type="submit"
              disabled={pwSaving || !currentPassword || newPassword.length < 8}
              className="min-h-[44px] px-5 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 dark:bg-slate-800 dark:hover:bg-slate-700 text-xs sm:text-sm font-semibold text-white cursor-pointer disabled:opacity-45"
            >
              {pwSaving ? 'Updating...' : 'Change Password'}
            </button>
          </form>
        </section>
      </div>
    </div>
  );
}
