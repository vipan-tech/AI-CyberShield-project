import { AlertOctagon, AlertTriangle, CheckCircle2, Info, ShieldAlert } from 'lucide-react';

interface SeverityIndicatorProps {
  level: 'Safe' | 'Benign' | 'Low' | 'Medium' | 'Suspicious' | 'High' | 'Malicious' | 'Critical';
  className?: string;
}

export function SeverityIndicator({ level, className = '' }: SeverityIndicatorProps) {
  switch (level) {
    case 'Safe':
    case 'Benign':
      return (
        <span className={`inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-600 dark:text-emerald-400 ${className}`}>
          <CheckCircle2 className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
          <span>{level}</span>
        </span>
      );
    case 'Low':
      return (
        <span className={`inline-flex items-center gap-1.5 text-xs font-semibold text-sky-600 dark:text-sky-400 ${className}`}>
          <Info className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
          <span>{level}</span>
        </span>
      );
    case 'Medium':
    case 'Suspicious':
      return (
        <span className={`inline-flex items-center gap-1.5 text-xs font-semibold text-amber-600 dark:text-amber-400 ${className}`}>
          <AlertTriangle className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
          <span>{level}</span>
        </span>
      );
    case 'High':
      return (
        <span className={`inline-flex items-center gap-1.5 text-xs font-semibold text-orange-600 dark:text-orange-400 ${className}`}>
          <ShieldAlert className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
          <span>{level}</span>
        </span>
      );
    case 'Malicious':
    case 'Critical':
      return (
        <span className={`inline-flex items-center gap-1.5 text-xs font-semibold text-rose-600 dark:text-rose-400 ${className}`}>
          <AlertOctagon className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
          <span>{level}</span>
        </span>
      );
  }
}

export function getScoreAccentClass(score: number): string {
  if (score >= 65) return 'text-rose-600 dark:text-rose-400';
  if (score >= 30) return 'text-amber-600 dark:text-amber-400';
  return 'text-emerald-600 dark:text-emerald-400';
}

export function getProgressBarClass(score: number): string {
  if (score >= 65) return 'bg-rose-500';
  if (score >= 30) return 'bg-amber-500';
  return 'bg-emerald-500';
}
