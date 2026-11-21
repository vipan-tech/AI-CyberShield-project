import { jsPDF } from 'jspdf';
import type {
  BatchUrlScanResponse,
  PasswordAuditSummary,
  SecurityAlert,
  ThreatAnalysisResult,
  UrlScanResult,
  UserProfile,
} from '../types/security';

function addHeaderBanner(doc: jsPDF, title: string, subtitle: string, analyst?: UserProfile | null): number {
  const pageWidth = doc.internal.pageSize.getWidth();
  doc.setFillColor(10, 18, 35);
  doc.rect(0, 0, pageWidth, 34, 'F');

  doc.setTextColor(56, 189, 248);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.text('AI CYBERSHIELD SECURITY REPORT', 14, 12);

  doc.setTextColor(248, 250, 252);
  doc.setFontSize(16);
  doc.text(title, 14, 21);

  doc.setTextColor(148, 163, 184);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  const analystLine = analyst ? `Analyst: ${analyst.name} (${analyst.organization})` : 'Analyst: Local Session';
  doc.text(`${subtitle}  |  ${analystLine}`, 14, 28);

  return 44;
}

function ensureSpace(doc: jsPDF, currentY: number, needed = 20): number {
  const pageHeight = doc.internal.pageSize.getHeight();
  if (currentY + needed > pageHeight - 16) {
    doc.addPage();
    return 18;
  }
  return currentY;
}

function writeWrappedSection(doc: jsPDF, heading: string, lines: string[], startY: number): number {
  const pageWidth = doc.internal.pageSize.getWidth();
  const maxWidth = pageWidth - 28;
  let y = ensureSpace(doc, startY, 18);

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text(heading, 14, y);
  y += 2;
  doc.setDrawColor(203, 213, 225);
  doc.line(14, y, pageWidth - 14, y);
  y += 6;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9.5);
  doc.setTextColor(51, 65, 85);

  for (const rawLine of lines) {
    const wrapped = doc.splitTextToSize(rawLine, maxWidth) as string[];
    for (const part of wrapped) {
      y = ensureSpace(doc, y, 7);
      doc.text(part, 14, y);
      y += 5;
    }
    y += 1.5;
  }

  return y + 4;
}

export function downloadUrlScanPdf(scan: UrlScanResult, analyst?: UserProfile | null): void {
  const doc = new jsPDF({ unit: 'mm', format: 'a4' });
  let y = addHeaderBanner(
    doc,
    'Phishing URL Inspection Report',
    `Generated: ${new Date(scan.scannedAt).toLocaleString()}`,
    analyst,
  );

  y = writeWrappedSection(
    doc,
    'Executive Verdict',
    [
      `Target URL: ${scan.signals.normalizedUrl}`,
      `Verdict: ${scan.verdict.toUpperCase()}  |  Risk Score: ${scan.riskScore}/100  |  Duration: ${scan.durationMs} ms`,
      `Classification: ${scan.threatCategory}`,
      `Summary: ${scan.summary}`,
    ],
    y,
  );

  y = writeWrappedSection(
    doc,
    'DNS & Domain Registration Evidence',
    [
      `Registrable Domain: ${scan.signals.registrableDomain}`,
      `IPv4 (A): ${scan.dns.ipv4.length ? scan.dns.ipv4.join(', ') : 'None'}`,
      `IPv6 (AAAA): ${scan.dns.ipv6.length ? scan.dns.ipv6.join(', ') : 'None'}`,
      `Nameservers: ${scan.dns.nameservers?.length ? scan.dns.nameservers.join(', ') : 'None'}`,
      `SPF Record: ${scan.dns.spfRecord || 'Not Configured'}`,
      `DMARC Policy: ${scan.dns.dmarcRecord || 'Not Configured'}`,
      `Registrar: ${scan.rdap?.registrar || 'Unavailable'}  |  Domain Age: ${
        scan.rdap?.domainAgeDays !== null && scan.rdap?.domainAgeDays !== undefined
          ? `${scan.rdap.domainAgeDays} days (Created ${scan.rdap.createdAt?.slice(0, 10)})`
          : scan.rdap?.error || 'Unavailable'
      }`,
    ],
    y,
  );

  y = writeWrappedSection(
    doc,
    'SSL/TLS & HTTP Telemetry',
    [
      `TLS Trusted: ${scan.tls.checked ? (scan.tls.authorized ? 'Yes (Root CA Verified)' : `No (${scan.tls.authorizationError || 'Untrusted'})`) : scan.tls.error || 'Not Checked'}`,
      `Issuer: ${scan.tls.issuer || '—'}  |  Protocol: ${scan.tls.protocol || '—'}  |  Days Remaining: ${scan.tls.daysRemaining ?? '—'}`,
      `SHA-256 Fingerprint: ${scan.tls.fingerprint256 || 'Unavailable'}`,
      `HTTP Status: ${scan.http.statusCode ?? 'No Response'}  |  Final URL: ${scan.http.finalUrl || scan.signals.normalizedUrl}`,
      `Security Headers: HSTS=${scan.http.securityHeaders.hsts ? 'Yes' : 'No'}, CSP=${scan.http.securityHeaders.csp ? 'Yes' : 'No'}, X-Frame=${scan.http.securityHeaders.xFrameOptions ? 'Yes' : 'No'}`,
      `Page Signals: ${scan.http.passwordInputCount} password input(s), External Form Action=${scan.http.externalFormAction || 'None'}`,
    ],
    y,
  );

  y = writeWrappedSection(
    doc,
    'Verified Phishing & Risk Indicators',
    scan.evidenceItems.map(
      (item, idx) => `${idx + 1}. [${item.severity}] ${item.title} (+${item.riskPoints} pts) — ${item.evidence}`,
    ),
    y,
  );

  writeWrappedSection(
    doc,
    'Recommended Actions',
    scan.recommendations.map((rec, idx) => `${idx + 1}. ${rec}`),
    y,
  );

  const safeHost = scan.signals.hostname.replace(/[^a-zA-Z0-9.-]/g, '_').slice(0, 40);
  doc.save(`AICyberShield-URL-${safeHost}.pdf`);
}

export function downloadBatchScanPdf(batch: BatchUrlScanResponse, analyst?: UserProfile | null): void {
  const doc = new jsPDF({ unit: 'mm', format: 'a4' });
  let y = addHeaderBanner(
    doc,
    'Multi-URL Batch Security Report',
    `Scanned: ${new Date(batch.scannedAt).toLocaleString()}  |  Duration: ${batch.totalDurationMs} ms`,
    analyst,
  );

  y = writeWrappedSection(
    doc,
    'Batch Summary',
    [
      `Total Targets: ${batch.summary.total}  |  Completed: ${batch.summary.completed}  |  Failed: ${batch.summary.failed}`,
      `Verdicts: Safe=${batch.summary.safe}  |  Suspicious=${batch.summary.suspicious}  |  Malicious=${batch.summary.malicious}`,
    ],
    y,
  );

  const itemLines = batch.items.map((item, idx) => {
    if (!item.ok || !item.result) {
      return `${idx + 1}. [ERROR] ${item.inputUrl} — ${item.error || 'Scan failed'}`;
    }
    const r = item.result;
    return `${idx + 1}. [${r.verdict.toUpperCase()} · ${r.riskScore}/100] ${r.signals.normalizedUrl} — ${r.threatCategory} (TLS: ${
      r.tls.authorized ? 'Trusted' : r.tls.checked ? 'Untrusted' : 'None'
    }, DNS: ${r.dns.resolved ? 'OK' : 'NXDOMAIN'})`;
  });

  writeWrappedSection(doc, 'Per-Target Inspection Results', itemLines, y);
  doc.save(`AICyberShield-Batch-${batch.scannedAt.slice(0, 10)}.pdf`);
}

export function downloadThreatAnalysisPdf(report: ThreatAnalysisResult, analyst?: UserProfile | null): void {
  const doc = new jsPDF({ unit: 'mm', format: 'a4' });
  let y = addHeaderBanner(
    doc,
    'Cyber Threat Analysis Report',
    `Analyzed: ${new Date(report.analyzedAt).toLocaleString()}  |  Context: ${report.contextType}`,
    analyst,
  );

  y = writeWrappedSection(
    doc,
    'Threat Assessment Summary',
    [
      `Severity: ${report.severity.toUpperCase()}  |  Risk Score: ${report.riskScore}/100`,
      `Category: ${report.threatCategory}  |  Attack Vector: ${report.attackVector}`,
      `Summary: ${report.summary}`,
    ],
    y,
  );

  if (report.indicators.length > 0) {
    y = writeWrappedSection(
      doc,
      'Extracted Indicators of Compromise (IOCs)',
      report.indicators.map(
        (ioc, idx) => `${idx + 1}. [${ioc.riskLevel}] ${ioc.type}: ${ioc.value} — ${ioc.note}`,
      ),
      y,
    );
  }

  if (report.mitreTechniques.length > 0) {
    y = writeWrappedSection(
      doc,
      'MITRE ATT&CK Technique Mapping',
      report.mitreTechniques.map((m) => `• ${m.id} (${m.tactic}): ${m.name}`),
      y,
    );
  }

  writeWrappedSection(
    doc,
    'Containment & Remediation Playbook',
    report.remediationSteps.map((step, idx) => `${idx + 1}. ${step}`),
    y,
  );

  doc.save(`AICyberShield-Threat-${report.analyzedAt.slice(0, 10)}.pdf`);
}

export function downloadExecutiveStatsPdf(params: {
  urlScans: UrlScanResult[];
  threatAnalyses: ThreatAnalysisResult[];
  passwordAudits: PasswordAuditSummary[];
  alerts: SecurityAlert[];
  analyst?: UserProfile | null;
}): void {
  const { urlScans, threatAnalyses, passwordAudits, alerts, analyst } = params;
  const doc = new jsPDF({ unit: 'mm', format: 'a4' });
  let y = addHeaderBanner(
    doc,
    'Executive Security Statistics Summary',
    `Exported: ${new Date().toLocaleString()}`,
    analyst,
  );

  const safeCount = urlScans.filter((s) => s.verdict === 'Safe').length;
  const suspCount = urlScans.filter((s) => s.verdict === 'Suspicious').length;
  const malCount = urlScans.filter((s) => s.verdict === 'Malicious').length;
  const avgRisk =
    urlScans.length > 0
      ? Math.round(urlScans.reduce((acc, s) => acc + s.riskScore, 0) / urlScans.length)
      : 0;
  const openAlerts = alerts.filter((a) => a.status === 'Open').length;
  const breachedPws = passwordAudits.filter((p) => (p.breachCount ?? 0) > 0).length;

  y = writeWrappedSection(
    doc,
    'Workspace Posture Metrics',
    [
      `Total URL Scans: ${urlScans.length} (Safe: ${safeCount}, Suspicious: ${suspCount}, Malicious: ${malCount})`,
      `Average URL Risk Score: ${avgRisk}/100`,
      `Threat Intelligence Reports: ${threatAnalyses.length}`,
      `Password Audits: ${passwordAudits.length} (Exposed in Breaches: ${breachedPws})`,
      `Security Alerts: ${alerts.length} total (${openAlerts} currently open)`,
    ],
    y,
  );

  if (urlScans.length > 0) {
    y = writeWrappedSection(
      doc,
      'Recent URL Scans',
      urlScans.slice(0, 10).map(
        (s, idx) => `${idx + 1}. [${s.verdict} · ${s.riskScore}/100] ${s.signals.normalizedUrl} (${s.scannedAt.slice(0, 10)})`,
      ),
      y,
    );
  }

  if (alerts.length > 0) {
    writeWrappedSection(
      doc,
      'Recent Security Alerts',
      alerts.slice(0, 10).map(
        (a, idx) => `${idx + 1}. [${a.severity} · ${a.status}] ${a.title} — ${a.target}`,
      ),
      y,
    );
  }

  doc.save(`AICyberShield-Executive-Summary-${new Date().toISOString().slice(0, 10)}.pdf`);
}
