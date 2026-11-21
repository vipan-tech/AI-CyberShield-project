import 'dotenv/config';
import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import fs from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import tls from 'node:tls';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { GoogleGenAI, ThinkingLevel, Type } from '@google/genai';
import { createServer as createViteServer } from 'vite';
import type {
  AiSynthesisInfo,
  BatchUrlScanItem,
  BatchUrlScanResponse,
  DnsIntel,
  ExtractedIoc,
  HttpIntel,
  HttpRedirectHop,
  KevEntry,
  KevFeedResponse,
  PhishingEvidenceItem,
  PhishingVerdict,
  RdapIntel,
  ThemeMode,
  ThreatAnalysisResult,
  TlsIntel,
  UrlScanResult,
  UrlSignalBreakdown,
  UserHistoryPayload,
  UserProfile,
} from './src/types/security.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT) || 3000;

function createAiClient(): GoogleGenAI | null {
  const apiKey = process.env.GEMINI_API_KEY?.trim();
  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY') {
    return null;
  }
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
}

// --- SSRF & IP Validation Guards ---

function isPrivateOrReservedIpv4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    return true;
  }
  const [a, b, c] = parts;
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64.0.0/10
  if (a === 127) return true; // Loopback 127.0.0.0/8
  if (a === 169 && b === 254) return true; // Link-local / Cloud Metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // Private 172.16.0.0/12
  if (a === 192 && b === 0 && c === 0) return true; // 192.0.0.0/24
  if (a === 192 && b === 0 && c === 2) return true; // TEST-NET-1
  if (a === 192 && b === 168) return true; // Private 192.168.0.0/16
  if (a === 198 && (b === 18 || b === 19)) return true; // Benchmarking
  if (a === 198 && b === 51 && c === 100) return true; // TEST-NET-2
  if (a === 203 && b === 0 && c === 113) return true; // TEST-NET-3
  if (a >= 224) return true; // Multicast & Reserved
  return false;
}

function isPrivateOrReservedIpv6(ip: string): boolean {
  const lower = ip.toLowerCase();
  if (lower === '::' || lower === '::1') return true;
  if (lower.startsWith('::ffff:')) {
    const mappedV4 = lower.slice(7);
    if (net.isIPv4(mappedV4)) {
      return isPrivateOrReservedIpv4(mappedV4);
    }
  }
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
  if (lower.startsWith('fe8') || lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb')) {
    return true;
  }
  if (lower.startsWith('ff')) return true;
  return false;
}

function isPrivateOrReservedIp(ip: string): boolean {
  const version = net.isIP(ip);
  if (version === 4) return isPrivateOrReservedIpv4(ip);
  if (version === 6) return isPrivateOrReservedIpv6(ip);
  return true;
}

function isRestrictedHostname(hostname: string): boolean {
  const lower = hostname.toLowerCase().replace(/\.$/, '');
  if (
    !lower ||
    lower === 'localhost' ||
    lower.endsWith('.localhost') ||
    lower.endsWith('.local') ||
    lower.endsWith('.internal') ||
    lower.endsWith('.lan') ||
    lower.endsWith('.home')
  ) {
    return true;
  }
  if (net.isIP(lower)) {
    return isPrivateOrReservedIp(lower);
  }
  return false;
}

async function resolveAndVerifyPublicTarget(hostname: string): Promise<{ safe: boolean; ips: string[]; reason?: string }> {
  if (isRestrictedHostname(hostname)) {
    return { safe: false, ips: [], reason: 'Restricted localhost, loopback, or private address.' };
  }
  if (net.isIP(hostname)) {
    return isPrivateOrReservedIp(hostname)
      ? { safe: false, ips: [], reason: 'Target IP belongs to a private or reserved range.' }
      : { safe: true, ips: [hostname] };
  }

  try {
    const records = await dns.lookup(hostname, { all: true });
    const ips = records.map((r) => r.address);
    if (ips.some((ip) => isPrivateOrReservedIp(ip))) {
      return { safe: false, ips: [], reason: 'Hostname resolved to a private or reserved IP address.' };
    }
    return { safe: true, ips };
  } catch {
    return { safe: true, ips: [] };
  }
}

// --- Lexical Phishing Indicator Engine ---

const SUSPICIOUS_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'click', 'link', 'zip', 'mov',
  'work', 'buzz', 'icu', 'cam', 'rest', 'fit', 'loan', 'monster', 'cfd', 'sbs', 'quest',
]);

const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
  'rb.gy', 'cutt.ly', 'shorturl.at', 'rebrand.ly', 'tiny.cc', 'lnkd.in',
]);

const TARGETED_BRANDS = [
  'paypal', 'google', 'microsoft', 'apple', 'amazon', 'netflix', 'chase',
  'bankofamerica', 'wellsfargo', 'citibank', 'coinbase', 'binance', 'metamask',
  'instagram', 'facebook', 'linkedin', 'github', 'dropbox', 'docusign', 'adobe',
  'whatsapp', 'telegram', 'stripe', 'icloud', 'outlook', 'office365',
];

const PHISHING_KEYWORDS = [
  'login', 'signin', 'verify', 'verification', 'update', 'secure', 'security',
  'account', 'billing', 'suspend', 'suspended', 'confirm', 'wallet', 'unlock',
  'recovery', 'password', 'credential', 'auth', 'webscr', 'invoice', 'payroll',
];

function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[m][n];
}

function getRegistrableDomain(hostname: string): string {
  const clean = hostname.toLowerCase().replace(/\.$/, '');
  if (net.isIP(clean)) return clean;
  const parts = clean.split('.').filter(Boolean);
  if (parts.length <= 2) return parts.join('.');
  const secondLast = parts[parts.length - 2];
  const last = parts[parts.length - 1];
  const commonSecondLevel = new Set(['co', 'com', 'org', 'net', 'gov', 'edu', 'ac']);
  if (last.length === 2 && commonSecondLevel.has(secondLast) && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

function analyzeUrlLexicalSignals(parsed: URL): UrlSignalBreakdown {
  const hostname = parsed.hostname.toLowerCase();
  const labels = hostname.split('.').filter(Boolean);
  const tld = labels.length > 0 ? labels[labels.length - 1] : '';
  const registrableDomain = getRegistrableDomain(hostname);
  const sld = registrableDomain.split('.')[0] ?? '';

  const isIpLiteral = net.isIP(hostname.replace(/^\[|\]$/g, '')) !== 0;
  const hasCredentialTrap = Boolean(parsed.username || parsed.password || parsed.href.includes('@'));
  const isPunycodeOrHomoglyph = hostname.includes('xn--') || /[^\x00-\x7F]/.test(parsed.href);
  const isUrlShortener = URL_SHORTENERS.has(hostname) || URL_SHORTENERS.has(registrableDomain);
  const suspiciousTld = SUSPICIOUS_TLDS.has(tld) ? `.${tld}` : null;
  const subdomainCount = isIpLiteral ? 0 : Math.max(0, labels.length - 2);
  const urlLength = parsed.href.length;

  let impersonatedBrand: string | null = null;
  const normalizedSld = sld
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/5/g, 's')
    .replace(/rn/g, 'm');

  for (const brand of TARGETED_BRANDS) {
    if (sld === brand) continue;
    const dist = levenshtein(normalizedSld, brand);
    const hyphenatedSpoof = hostname.includes(brand) && !registrableDomain.startsWith(`${brand}.`);
    const containsTyposquatToken = normalizedSld.includes(brand) && sld !== brand;
    if ((dist > 0 && dist <= 2) || hyphenatedSpoof || containsTyposquatToken) {
      impersonatedBrand = brand;
      break;
    }
  }

  const lowerFull = `${hostname}${parsed.pathname}${parsed.search}`.toLowerCase();
  const matchedKeywords = PHISHING_KEYWORDS.filter((kw) => lowerFull.includes(kw));

  return {
    normalizedUrl: parsed.href,
    hostname,
    registrableDomain,
    protocol: parsed.protocol.replace(':', '').toUpperCase(),
    port: parsed.port || (parsed.protocol === 'https:' ? '443' : '80'),
    pathAndQuery: `${parsed.pathname}${parsed.search}`,
    isIpLiteral,
    hasCredentialTrap,
    isPunycodeOrHomoglyph,
    isUrlShortener,
    suspiciousTld,
    subdomainCount,
    urlLength,
    impersonatedBrand,
    matchedKeywords,
  };
}

// --- Real DNS Verification ---

async function inspectDns(hostname: string, registrableDomain: string): Promise<DnsIntel> {
  if (net.isIP(hostname)) {
    const version = net.isIP(hostname);
    return {
      resolved: true,
      ipv4: version === 4 ? [hostname] : [],
      ipv6: version === 6 ? [hostname] : [],
      cname: [],
      nameservers: [],
      mxRecords: [],
      spfRecord: null,
      dmarcRecord: null,
      hasSpf: false,
      hasDmarc: false,
    };
  }

  const [v4Res, v6Res, cnameRes, nsRes, mxRes, txtRes, dmarcRes] = await Promise.allSettled([
    dns.resolve4(hostname),
    dns.resolve6(hostname),
    dns.resolveCname(hostname),
    dns.resolveNs(registrableDomain),
    dns.resolveMx(registrableDomain),
    dns.resolveTxt(registrableDomain),
    dns.resolveTxt(`_dmarc.${registrableDomain}`),
  ]);

  const ipv4 = v4Res.status === 'fulfilled' ? v4Res.value.slice(0, 6) : [];
  const ipv6 = v6Res.status === 'fulfilled' ? v6Res.value.slice(0, 4) : [];
  const cname = cnameRes.status === 'fulfilled' ? cnameRes.value.slice(0, 3) : [];
  const nameservers = nsRes.status === 'fulfilled' ? nsRes.value.slice(0, 4) : [];
  const mxRecords =
    mxRes.status === 'fulfilled'
      ? mxRes.value.sort((a, b) => a.priority - b.priority).slice(0, 4).map((m) => `${m.priority} ${m.exchange}`)
      : [];

  const txtEntries = txtRes.status === 'fulfilled' ? txtRes.value.map((chunks) => chunks.join('')) : [];
  const dmarcEntries = dmarcRes.status === 'fulfilled' ? dmarcRes.value.map((chunks) => chunks.join('')) : [];

  const spfRecord = txtEntries.find((t) => /^v=spf1\b/i.test(t.trim())) || null;
  const dmarcRecord = dmarcEntries.find((t) => /^v=dmarc1\b/i.test(t.trim())) || null;

  if (ipv4.length === 0 && ipv6.length === 0) {
    try {
      const lookups = await dns.lookup(hostname, { all: true });
      for (const entry of lookups) {
        if (entry.family === 4 && !ipv4.includes(entry.address)) ipv4.push(entry.address);
        if (entry.family === 6 && !ipv6.includes(entry.address)) ipv6.push(entry.address);
      }
    } catch (err) {
      return {
        resolved: false,
        ipv4: [],
        ipv6: [],
        cname,
        nameservers,
        mxRecords,
        spfRecord,
        dmarcRecord,
        hasSpf: Boolean(spfRecord),
        hasDmarc: Boolean(dmarcRecord),
        error: err instanceof Error ? err.message : 'Host did not resolve in DNS (NXDOMAIN)',
      };
    }
  }

  return {
    resolved: ipv4.length > 0 || ipv6.length > 0,
    ipv4,
    ipv6,
    cname,
    nameservers,
    mxRecords,
    spfRecord,
    dmarcRecord,
    hasSpf: Boolean(spfRecord),
    hasDmarc: Boolean(dmarcRecord),
  };
}

// --- Real RDAP Domain Registration & Age Lookup ---

async function inspectRdap(registrableDomain: string): Promise<RdapIntel> {
  if (net.isIP(registrableDomain)) {
    return {
      checked: false,
      registrar: null,
      createdAt: null,
      updatedAt: null,
      expiresAt: null,
      domainAgeDays: null,
      dnssecSigned: null,
      error: 'RDAP domain age is not applicable to IP literals',
    };
  }

  try {
    const tld = registrableDomain.split('.').pop()?.toLowerCase();
    const rdapUrl =
      tld === 'com' || tld === 'net'
        ? `https://rdap.verisign.com/${tld}/v1/domain/${encodeURIComponent(registrableDomain)}`
        : `https://rdap.org/domain/${encodeURIComponent(registrableDomain)}`;

    const res = await fetch(rdapUrl, {
      signal: AbortSignal.timeout(3500),
      headers: { Accept: 'application/rdap+json, application/json', 'User-Agent': 'AICyberShield/1.0' },
    });

    if (!res.ok) {
      return {
        checked: true,
        registrar: null,
        createdAt: null,
        updatedAt: null,
        expiresAt: null,
        domainAgeDays: null,
        dnssecSigned: null,
        error: `RDAP registry returned HTTP ${res.status}`,
      };
    }

    const ct = res.headers.get('content-type') || '';
    if (!ct.toLowerCase().includes('json')) {
      return {
        checked: true,
        registrar: null,
        createdAt: null,
        updatedAt: null,
        expiresAt: null,
        domainAgeDays: null,
        dnssecSigned: null,
        error: 'RDAP registry returned a non-JSON response',
      };
    }

    const data = (await res.json()) as {
      events?: Array<{ eventAction?: string; eventDate?: string }>;
      entities?: Array<{ roles?: string[]; vcardArray?: unknown[] }>;
      secureDNS?: { delegationSigned?: boolean };
    };

    const events = Array.isArray(data.events) ? data.events : [];
    const createdAt = events.find((e) => e.eventAction === 'registration')?.eventDate || null;
    const updatedAt = events.find((e) => e.eventAction === 'last changed')?.eventDate || null;
    const expiresAt = events.find((e) => e.eventAction === 'expiration')?.eventDate || null;

    let domainAgeDays: number | null = null;
    if (createdAt) {
      const createdMs = Date.parse(createdAt);
      if (!Number.isNaN(createdMs)) {
        domainAgeDays = Math.max(0, Math.floor((Date.now() - createdMs) / (1000 * 60 * 60 * 24)));
      }
    }

    let registrar: string | null = null;
    const regEntity = (Array.isArray(data.entities) ? data.entities : []).find(
      (ent) => Array.isArray(ent.roles) && ent.roles.includes('registrar'),
    );
    if (regEntity && Array.isArray(regEntity.vcardArray) && Array.isArray(regEntity.vcardArray[1])) {
      const fnProp = (regEntity.vcardArray[1] as unknown[][]).find((p) => Array.isArray(p) && p[0] === 'fn');
      if (fnProp && typeof fnProp[3] === 'string') {
        registrar = fnProp[3];
      }
    }

    return {
      checked: true,
      registrar,
      createdAt,
      updatedAt,
      expiresAt,
      domainAgeDays,
      dnssecSigned: typeof data.secureDNS?.delegationSigned === 'boolean' ? data.secureDNS.delegationSigned : null,
    };
  } catch (err) {
    return {
      checked: true,
      registrar: null,
      createdAt: null,
      updatedAt: null,
      expiresAt: null,
      domainAgeDays: null,
      dnssecSigned: null,
      error: err instanceof Error ? err.message : 'RDAP lookup timed out',
    };
  }
}

// --- Real SSL/TLS Certificate Verification ---

async function inspectTls(targetIp: string, hostname: string, port: number): Promise<TlsIntel> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (result: TlsIntel) => {
      if (settled) return;
      settled = true;
      clearTimeout(hardTimer);
      resolve(result);
    };

    const socket = tls.connect(
      {
        host: targetIp,
        port,
        servername: net.isIP(hostname) ? undefined : hostname,
        rejectUnauthorized: false,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate();
          const protocol = socket.getProtocol() || null;
          const cipherInfo = socket.getCipher();
          const cipher = cipherInfo ? cipherInfo.name : null;
          const authorized = socket.authorized;
          const authErr = socket.authorizationError ? String(socket.authorizationError) : null;

          let daysRemaining: number | null = null;
          if (cert.valid_to) {
            const expiryMs = Date.parse(cert.valid_to);
            if (!Number.isNaN(expiryMs)) {
              daysRemaining = Math.floor((expiryMs - Date.now()) / (1000 * 60 * 60 * 24));
            }
          }

          const pickCertField = (val: string | string[] | undefined): string | null =>
            Array.isArray(val) ? (val[0] ?? null) : val || null;

          const issuerStr = cert.issuer ? pickCertField(cert.issuer.O) || pickCertField(cert.issuer.CN) : null;
          const subjectStr = cert.subject ? pickCertField(cert.subject.CN) || pickCertField(cert.subject.O) : null;
          const issuerCn = cert.issuer ? pickCertField(cert.issuer.CN) : null;
          const subjectCn = cert.subject ? pickCertField(cert.subject.CN) : null;
          const selfSigned = Boolean(issuerCn && subjectCn && issuerCn === subjectCn && !authorized);

          const subjectAltNames = cert.subjectaltname
            ? cert.subjectaltname
                .split(',')
                .map((s) => s.trim().replace(/^DNS:|^IP Address:/i, ''))
                .filter(Boolean)
                .slice(0, 8)
            : [];

          socket.destroy();
          finish({
            checked: true,
            valid: Boolean(cert.valid_to) && (daysRemaining === null || daysRemaining > 0),
            authorized,
            authorizationError: authErr,
            protocol,
            cipher,
            issuer: issuerStr,
            subject: subjectStr,
            subjectAltNames,
            serialNumber: cert.serialNumber || null,
            fingerprint256: cert.fingerprint256 || null,
            validFrom: cert.valid_from || null,
            validTo: cert.valid_to || null,
            daysRemaining,
            selfSigned,
          });
        } catch (err) {
          socket.destroy();
          finish({
            checked: true,
            valid: false,
            authorized: false,
            authorizationError: null,
            protocol: null,
            cipher: null,
            issuer: null,
            subject: null,
            subjectAltNames: [],
            serialNumber: null,
            fingerprint256: null,
            validFrom: null,
            validTo: null,
            daysRemaining: null,
            selfSigned: false,
            error: err instanceof Error ? err.message : 'TLS inspection failed',
          });
        }
      },
    );

    const hardTimer = setTimeout(() => {
      socket.destroy();
      finish({
        checked: true,
        valid: false,
        authorized: false,
        authorizationError: 'TLS handshake timeout',
        protocol: null,
        cipher: null,
        issuer: null,
        subject: null,
        subjectAltNames: [],
        serialNumber: null,
        fingerprint256: null,
        validFrom: null,
        validTo: null,
        daysRemaining: null,
        selfSigned: false,
        error: 'TLS handshake timed out after 4.5s',
      });
    }, 4500);

    socket.on('error', (err) => {
      socket.destroy();
      finish({
        checked: true,
        valid: false,
        authorized: false,
        authorizationError: err.message,
        protocol: null,
        cipher: null,
        issuer: null,
        subject: null,
        subjectAltNames: [],
        serialNumber: null,
        fingerprint256: null,
        validFrom: null,
        validTo: null,
        daysRemaining: null,
        selfSigned: false,
        error: err.message,
      });
    });
  });
}

// --- Safe Multi-Hop HTTP & HTML Content Inspection ---

async function inspectHttpAndContent(startUrl: URL, startRegistrableDomain: string): Promise<HttpIntel> {
  const redirectChain: HttpRedirectHop[] = [];
  let currentUrl = new URL(startUrl.href);
  currentUrl.username = '';
  currentUrl.password = '';

  const emptyHeaders = {
    hsts: false,
    csp: false,
    xFrameOptions: false,
    xContentTypeOptions: false,
    referrerPolicy: false,
  };

  try {
    let response: Response | null = null;

    for (let hop = 0; hop <= 4; hop++) {
      const targetCheck = await resolveAndVerifyPublicTarget(currentUrl.hostname);
      if (!targetCheck.safe) {
        return {
          checked: true,
          finalUrl: currentUrl.href,
          statusCode: response?.status ?? null,
          redirectChain,
          crossDomainRedirect: getRegistrableDomain(currentUrl.hostname) !== startRegistrableDomain,
          serverHeader: null,
          contentType: null,
          pageTitle: null,
          passwordInputCount: 0,
          externalFormAction: null,
          hiddenIframeCount: 0,
          securityHeaders: emptyHeaders,
          error: `Blocked redirect hop to restricted address: ${currentUrl.hostname}`,
        };
      }

      response = await fetch(currentUrl.href, {
        method: 'GET',
        redirect: 'manual',
        signal: AbortSignal.timeout(4500),
        headers: {
          'User-Agent': 'AICyberShield-URL-Scanner/2.0',
          Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
      });

      const loc = response.headers.get('location');
      if (response.status >= 300 && response.status < 400 && loc) {
        const nextUrl = new URL(loc, currentUrl);
        if (nextUrl.protocol !== 'http:' && nextUrl.protocol !== 'https:') {
          redirectChain.push({ statusCode: response.status, url: nextUrl.href });
          break;
        }
        redirectChain.push({ statusCode: response.status, url: nextUrl.href });
        currentUrl = nextUrl;
        currentUrl.username = '';
        currentUrl.password = '';
        continue;
      }

      break;
    }

    if (!response) {
      throw new Error('No HTTP response received');
    }

    const finalDomain = getRegistrableDomain(currentUrl.hostname);
    const crossDomainRedirect = finalDomain !== startRegistrableDomain;
    const contentType = response.headers.get('content-type');

    let pageTitle: string | null = null;
    let passwordInputCount = 0;
    let externalFormAction: string | null = null;
    let hiddenIframeCount = 0;

    if (contentType && /text\/html|application\/xhtml/i.test(contentType)) {
      const reader = response.body?.getReader();
      let html = '';
      if (reader) {
        const decoder = new TextDecoder();
        let totalBytes = 0;
        while (totalBytes < 131072) {
          const { done, value } = await reader.read();
          if (done) break;
          totalBytes += value.byteLength;
          html += decoder.decode(value, { stream: true });
        }
        await reader.cancel().catch(() => undefined);
      }

      const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
      if (titleMatch && titleMatch[1]) {
        pageTitle = titleMatch[1].replace(/\s+/g, ' ').trim().slice(0, 120);
      }

      const pwInputs = html.match(/<input[^>]*type\s*=\s*["']?password["']?[^>]*>/gi);
      passwordInputCount = pwInputs ? pwInputs.length : 0;

      const formMatches = html.matchAll(/<form[^>]*action\s*=\s*["']([^"']+)["'][^>]*>/gi);
      for (const match of formMatches) {
        const actionRaw = match[1]?.trim();
        if (actionRaw && /^https?:\/\//i.test(actionRaw)) {
          try {
            const actionUrl = new URL(actionRaw);
            if (getRegistrableDomain(actionUrl.hostname) !== finalDomain) {
              externalFormAction = actionUrl.hostname;
              break;
            }
          } catch {
            // ignore invalid form URL
          }
        }
      }

      const hiddenIframes = html.match(
        /<iframe[^>]*(display\s*:\s*none|visibility\s*:\s*hidden|width\s*=\s*["']?0["']?|height\s*=\s*["']?0["']?)[^>]*>/gi,
      );
      hiddenIframeCount = hiddenIframes ? hiddenIframes.length : 0;
    }

    return {
      checked: true,
      finalUrl: currentUrl.href,
      statusCode: response.status,
      redirectChain,
      crossDomainRedirect,
      serverHeader: response.headers.get('server'),
      contentType,
      pageTitle,
      passwordInputCount,
      externalFormAction,
      hiddenIframeCount,
      securityHeaders: {
        hsts: response.headers.has('strict-transport-security'),
        csp: response.headers.has('content-security-policy'),
        xFrameOptions: response.headers.has('x-frame-options'),
        xContentTypeOptions: response.headers.has('x-content-type-options'),
        referrerPolicy: response.headers.has('referrer-policy'),
      },
    };
  } catch (err) {
    return {
      checked: true,
      finalUrl: currentUrl.href,
      statusCode: null,
      redirectChain,
      crossDomainRedirect: getRegistrableDomain(currentUrl.hostname) !== startRegistrableDomain,
      serverHeader: null,
      contentType: null,
      pageTitle: null,
      passwordInputCount: 0,
      externalFormAction: null,
      hiddenIframeCount: 0,
      securityHeaders: emptyHeaders,
      error: err instanceof Error ? err.message : 'HTTP probe did not receive a response',
    };
  }
}

// --- Deterministic Evidence Builder & Scoring ---

function buildEvidenceReport(
  signals: UrlSignalBreakdown,
  dnsIntel: DnsIntel,
  rdapIntel: RdapIntel,
  tlsIntel: TlsIntel,
  httpIntel: HttpIntel,
): {
  evidenceItems: PhishingEvidenceItem[];
  riskScore: number;
  verdict: PhishingVerdict;
  threatCategory: string;
  summary: string;
  recommendations: string[];
} {
  const items: PhishingEvidenceItem[] = [];

  // 1. Transport Protocol
  if (signals.protocol === 'HTTP') {
    items.push({
      id: 'proto-http',
      category: 'URL Structure',
      severity: 'Warning',
      title: 'Unencrypted HTTP Transport',
      evidence: `URL uses plaintext HTTP on port ${signals.port} without TLS encryption.`,
      riskPoints: 20,
    });
  } else {
    items.push({
      id: 'proto-https',
      category: 'URL Structure',
      severity: 'Pass',
      title: 'HTTPS Scheme Enforced',
      evidence: `URL requests encrypted HTTPS transport on port ${signals.port}.`,
      riskPoints: 0,
    });
  }

  // 2. IP Literal
  if (signals.isIpLiteral) {
    items.push({
      id: 'ip-literal',
      category: 'URL Structure',
      severity: 'Critical',
      title: 'Direct IP Address Hostname',
      evidence: `Host uses raw IP "${signals.hostname}" instead of a registered domain name.`,
      riskPoints: 32,
    });
  }

  // 3. Credential Trap
  if (signals.hasCredentialTrap) {
    items.push({
      id: 'cred-trap',
      category: 'URL Structure',
      severity: 'Critical',
      title: 'Embedded "@" Credential Obfuscation',
      evidence: 'URL contains "@" syntax commonly used to mask the true destination host.',
      riskPoints: 35,
    });
  }

  // 4. IDN / Homoglyph
  if (signals.isPunycodeOrHomoglyph) {
    items.push({
      id: 'homoglyph',
      category: 'URL Structure',
      severity: 'Critical',
      title: 'Punycode / Non-ASCII Homoglyph Characters',
      evidence: `Hostname "${signals.hostname}" contains punycode ("xn--") or non-ASCII characters.`,
      riskPoints: 28,
    });
  }

  // 5. Brand Impersonation
  if (signals.impersonatedBrand) {
    items.push({
      id: 'brand-spoof',
      category: 'URL Structure',
      severity: 'Critical',
      title: `Potential Brand Impersonation (${signals.impersonatedBrand})`,
      evidence: `Domain "${signals.registrableDomain}" closely resembles or embeds protected brand "${signals.impersonatedBrand}".`,
      riskPoints: 38,
    });
  }

  // 6. Suspicious TLD & Shortener
  if (signals.suspiciousTld) {
    items.push({
      id: 'suspicious-tld',
      category: 'URL Structure',
      severity: 'Warning',
      title: `High-Abuse Top-Level Domain (${signals.suspiciousTld})`,
      evidence: `TLD "${signals.suspiciousTld}" has elevated historical phishing registration abuse.`,
      riskPoints: 18,
    });
  }
  if (signals.isUrlShortener) {
    items.push({
      id: 'shortener',
      category: 'URL Structure',
      severity: 'Warning',
      title: 'URL Shortening Service Detected',
      evidence: `"${signals.registrableDomain}" obscures the ultimate landing destination.`,
      riskPoints: 18,
    });
  }

  // 7. Subdomain Depth & Keywords
  if (signals.subdomainCount >= 3) {
    items.push({
      id: 'subdomain-depth',
      category: 'URL Structure',
      severity: 'Warning',
      title: 'Excessive Subdomain Nesting',
      evidence: `Hostname contains ${signals.subdomainCount} subdomain levels (${signals.hostname}).`,
      riskPoints: 15,
    });
  }
  if (signals.matchedKeywords.length >= 2) {
    items.push({
      id: 'phish-keywords',
      category: 'URL Structure',
      severity: 'Warning',
      title: 'Credential-Harvesting URL Keywords',
      evidence: `Path/query includes ${signals.matchedKeywords.length} sensitive terms: ${signals.matchedKeywords.slice(0, 5).join(', ')}.`,
      riskPoints: 16,
    });
  }

  // 8. DNS Resolution & Email Auth
  if (!dnsIntel.resolved) {
    items.push({
      id: 'dns-nxdomain',
      category: 'DNS & Domain',
      severity: 'Warning',
      title: 'Domain Failed DNS Resolution',
      evidence: dnsIntel.error || `No active A or AAAA records returned for ${signals.hostname}.`,
      riskPoints: 20,
    });
  } else {
    items.push({
      id: 'dns-resolved',
      category: 'DNS & Domain',
      severity: 'Pass',
      title: 'Active DNS Records Verified',
      evidence: `Resolved to ${[...dnsIntel.ipv4, ...dnsIntel.ipv6].slice(0, 3).join(', ')} (${dnsIntel.nameservers.length} NS records).`,
      riskPoints: 0,
    });
  }

  if (dnsIntel.hasSpf && dnsIntel.hasDmarc) {
    items.push({
      id: 'dns-email-auth',
      category: 'DNS & Domain',
      severity: 'Pass',
      title: 'SPF & DMARC Policies Configured',
      evidence: `Both SPF and DMARC DNS policies verified on ${signals.registrableDomain}.`,
      riskPoints: 0,
    });
  } else if (!signals.isIpLiteral) {
    items.push({
      id: 'dns-missing-auth',
      category: 'DNS & Domain',
      severity: 'Info',
      title: 'Incomplete Email Authentication (SPF/DMARC)',
      evidence: `SPF: ${dnsIntel.hasSpf ? 'Present' : 'Missing'} · DMARC: ${dnsIntel.hasDmarc ? 'Present' : 'Missing'} on ${signals.registrableDomain}.`,
      riskPoints: 6,
    });
  }

  // 9. RDAP Domain Age
  if (rdapIntel.checked && rdapIntel.domainAgeDays !== null) {
    if (rdapIntel.domainAgeDays < 30) {
      items.push({
        id: 'rdap-new-domain',
        category: 'DNS & Domain',
        severity: 'Critical',
        title: 'Newly Registered Domain (< 30 Days)',
        evidence: `RDAP registration date is ${rdapIntel.createdAt?.slice(0, 10)} (${rdapIntel.domainAgeDays} days old${rdapIntel.registrar ? `, registrar: ${rdapIntel.registrar}` : ''}).`,
        riskPoints: 28,
      });
    } else if (rdapIntel.domainAgeDays < 90) {
      items.push({
        id: 'rdap-young-domain',
        category: 'DNS & Domain',
        severity: 'Warning',
        title: 'Recently Registered Domain (< 90 Days)',
        evidence: `Domain registered ${rdapIntel.domainAgeDays} days ago (${rdapIntel.createdAt?.slice(0, 10)}).`,
        riskPoints: 14,
      });
    } else {
      items.push({
        id: 'rdap-aged-domain',
        category: 'DNS & Domain',
        severity: 'Pass',
        title: 'Established Domain Registration Age',
        evidence: `Registered ${rdapIntel.domainAgeDays.toLocaleString()} days ago (${rdapIntel.createdAt?.slice(0, 10)}${rdapIntel.registrar ? `, ${rdapIntel.registrar}` : ''}).`,
        riskPoints: 0,
      });
    }
  }

  // 10. SSL/TLS Verification
  if (tlsIntel.checked) {
    if (tlsIntel.error) {
      items.push({
        id: 'tls-error',
        category: 'SSL/TLS',
        severity: 'Warning',
        title: 'SSL/TLS Handshake Failed',
        evidence: tlsIntel.error,
        riskPoints: 22,
      });
    } else if (tlsIntel.selfSigned) {
      items.push({
        id: 'tls-self-signed',
        category: 'SSL/TLS',
        severity: 'Critical',
        title: 'Self-Signed SSL/TLS Certificate',
        evidence: `Certificate issuer matches subject (${tlsIntel.subject || 'Unknown'}) and is not trusted by root CAs.`,
        riskPoints: 30,
      });
    } else if (!tlsIntel.authorized || !tlsIntel.valid) {
      items.push({
        id: 'tls-untrusted',
        category: 'SSL/TLS',
        severity: 'Critical',
        title: 'Invalid or Untrusted SSL/TLS Certificate',
        evidence: `TLS verification failed: ${tlsIntel.authorizationError || 'Expired or mismatched hostname'} (Issuer: ${tlsIntel.issuer || 'Unknown'}).`,
        riskPoints: 28,
      });
    } else {
      items.push({
        id: 'tls-verified',
        category: 'SSL/TLS',
        severity: 'Pass',
        title: 'Trusted SSL/TLS Certificate Verified',
        evidence: `${tlsIntel.protocol || 'TLS'} verified · Issuer: ${tlsIntel.issuer || 'Trusted CA'} · Valid for ${tlsIntel.daysRemaining ?? '?'} days.`,
        riskPoints: 0,
      });
    }
  }

  // 11. HTTP Redirects & HTML Content Signals
  if (httpIntel.checked) {
    if (httpIntel.crossDomainRedirect) {
      items.push({
        id: 'http-cross-redirect',
        category: 'HTTP & Content',
        severity: 'Warning',
        title: 'Cross-Domain Redirect Detected',
        evidence: `Target redirected across ${httpIntel.redirectChain.length} hop(s) to ${httpIntel.finalUrl}.`,
        riskPoints: 18,
      });
    }
    if (httpIntel.passwordInputCount > 0 && (signals.protocol === 'HTTP' || !tlsIntel.authorized || Boolean(signals.impersonatedBrand))) {
      items.push({
        id: 'http-untrusted-pw-form',
        category: 'HTTP & Content',
        severity: 'Critical',
        title: 'Password Input Form on Unverified / Risky Endpoint',
        evidence: `Page serves ${httpIntel.passwordInputCount} password input field(s) alongside transport or domain risk signals.`,
        riskPoints: 28,
      });
    }
    if (httpIntel.externalFormAction) {
      items.push({
        id: 'http-ext-form',
        category: 'HTTP & Content',
        severity: 'Critical',
        title: 'Form Submits Credentials to External Domain',
        evidence: `HTML <form> posts data externally to "${httpIntel.externalFormAction}".`,
        riskPoints: 30,
      });
    }
    if (httpIntel.hiddenIframeCount > 0) {
      items.push({
        id: 'http-hidden-iframe',
        category: 'HTTP & Content',
        severity: 'Warning',
        title: 'Hidden Iframe Elements Found',
        evidence: `Detected ${httpIntel.hiddenIframeCount} zero-size or hidden <iframe> element(s) in HTML response.`,
        riskPoints: 15,
      });
    }
    if (httpIntel.statusCode !== null && !httpIntel.securityHeaders.hsts && signals.protocol === 'HTTPS') {
      items.push({
        id: 'http-no-hsts',
        category: 'HTTP & Content',
        severity: 'Info',
        title: 'Missing Strict-Transport-Security (HSTS) Header',
        evidence: `Server responded with HTTP ${httpIntel.statusCode} without HSTS enforcement.`,
        riskPoints: 4,
      });
    }
  }

  const rawPoints = items.reduce((acc, item) => acc + item.riskPoints, 0);
  const riskScore = Math.max(0, Math.min(100, rawPoints));

  const verdict: PhishingVerdict =
    riskScore >= 60 ? 'Malicious' : riskScore >= 25 ? 'Suspicious' : 'Safe';

  let threatCategory = 'Verified Legitimate Endpoint';
  if (signals.impersonatedBrand) threatCategory = 'Brand Impersonation / Typosquatting';
  else if (signals.hasCredentialTrap) threatCategory = 'Credential Trap Obfuscation';
  else if (httpIntel.externalFormAction) threatCategory = 'External Credential Harvesting';
  else if (tlsIntel.checked && (tlsIntel.selfSigned || !tlsIntel.authorized)) threatCategory = 'Untrusted / Invalid TLS Endpoint';
  else if (verdict === 'Malicious') threatCategory = 'High-Risk Phishing Indicator Cluster';
  else if (verdict === 'Suspicious') threatCategory = 'Suspicious Domain or Transport Posture';

  const criticalCount = items.filter((i) => i.severity === 'Critical').length;
  const warningCount = items.filter((i) => i.severity === 'Warning').length;
  const passCount = items.filter((i) => i.severity === 'Pass').length;

  const summary =
    verdict === 'Safe'
      ? `Technical inspection verified ${passCount} security checks with no high-risk phishing indicators on ${signals.hostname}.`
      : `Detected ${criticalCount} critical and ${warningCount} warning indicator(s) during live URL, DNS, TLS, and HTTP inspection of ${signals.hostname}.`;

  const recommendations: string[] = [];
  if (verdict !== 'Safe') {
    recommendations.push('Do not enter account credentials, payment details, or MFA codes on this URL.');
  }
  if (signals.impersonatedBrand) {
    recommendations.push(`Navigate directly to the official ${signals.impersonatedBrand} website using a saved bookmark instead of this link.`);
  }
  if (signals.protocol === 'HTTP' || (tlsIntel.checked && !tlsIntel.authorized)) {
    recommendations.push('Avoid transmitting sensitive data where TLS encryption or certificate trust cannot be verified.');
  }
  if (httpIntel.crossDomainRedirect) {
    recommendations.push(`Verify the final redirected destination (${httpIntel.finalUrl}) before trusting any page content.`);
  }
  if (recommendations.length === 0) {
    recommendations.push('Certificate and DNS checks passed; still verify the exact domain spelling before entering credentials.');
  }

  return {
    evidenceItems: items,
    riskScore,
    verdict,
    threatCategory,
    summary,
    recommendations,
  };
}

// --- Deterministic IOC Extraction for Threat Analyzer ---

function extractDeterministicIocs(text: string): Array<{ value: string; type: ExtractedIoc['type'] }> {
  const found: Array<{ value: string; type: ExtractedIoc['type'] }> = [];
  const seen = new Set<string>();

  const add = (value: string, type: ExtractedIoc['type']) => {
    const key = `${type}:${value.toLowerCase()}`;
    if (!seen.has(key) && found.length < 25) {
      seen.add(key);
      found.push({ value, type });
    }
  };

  const cveMatches = text.match(/\bCVE-\d{4}-\d{4,7}\b/gi) || [];
  for (const m of cveMatches) add(m.toUpperCase(), 'CVE');

  const urlMatches = text.match(/\bhttps?:\/\/[^\s"'<>()]+/gi) || [];
  for (const m of urlMatches) add(m, 'URL');

  const emailMatches = text.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g) || [];
  for (const m of emailMatches) add(m, 'Email');

  const ipv4Matches = text.match(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g) || [];
  for (const m of ipv4Matches) add(m, 'IPv4');

  const hashMatches = text.match(/\b(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})\b/g) || [];
  for (const m of hashMatches) add(m.toLowerCase(), 'Hash');

  const domainMatches =
    text.match(/\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|tk|xyz|top|info|biz|co|uk|de|app|dev|site|online|click)\b/gi) || [];
  for (const m of domainMatches) {
    if (!emailMatches.some((e) => e.endsWith(m))) {
      add(m.toLowerCase(), 'Domain');
    }
  }

  return found;
}

// --- Confined User & History Store + Scrypt / HMAC Auth ---

interface StoredUser extends UserProfile {
  passwordHash: string;
}

interface CyberShieldStore {
  users: StoredUser[];
  histories: Record<string, UserHistoryPayload>;
}

const DATA_DIR = path.resolve(__dirname, 'data');
const STORE_PATH = path.resolve(DATA_DIR, 'cybershield-store.json');
if (!STORE_PATH.startsWith(DATA_DIR + path.sep)) {
  throw new Error('Invalid store path configuration');
}

const SESSION_SECRET = process.env.SESSION_SECRET?.trim() || crypto.randomBytes(32).toString('hex');
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const revokedTokenJtis = new Set<string>();
let storeWriteQueue: Promise<void> = Promise.resolve();

async function readStore(): Promise<CyberShieldStore> {
  try {
    const raw = await fs.readFile(STORE_PATH, 'utf8');
    const parsed = JSON.parse(raw) as Partial<CyberShieldStore>;
    return {
      users: Array.isArray(parsed.users) ? parsed.users : [],
      histories: parsed.histories && typeof parsed.histories === 'object' ? parsed.histories : {},
    };
  } catch {
    return { users: [], histories: {} };
  }
}

async function writeStore(store: CyberShieldStore): Promise<void> {
  storeWriteQueue = storeWriteQueue.then(async () => {
    await fs.mkdir(DATA_DIR, { recursive: true });
    const tmpPath = path.resolve(DATA_DIR, `cybershield-store.${crypto.randomUUID()}.tmp`);
    if (!tmpPath.startsWith(DATA_DIR + path.sep)) {
      throw new Error('Invalid temp store path');
    }
    await fs.writeFile(tmpPath, JSON.stringify(store, null, 2), 'utf8');
    await fs.rename(tmpPath, STORE_PATH);
  });
  await storeWriteQueue;
}

function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

function verifyPassword(password: string, storedHash: string): boolean {
  const parts = storedHash.split(':');
  if (parts.length !== 2) return false;
  const [salt, keyHex] = parts;
  if (!salt || !keyHex) return false;
  try {
    const derived = crypto.scryptSync(password, salt, 64);
    const keyBuf = Buffer.from(keyHex, 'hex');
    if (derived.length !== keyBuf.length) return false;
    return crypto.timingSafeEqual(derived, keyBuf);
  } catch {
    return false;
  }
}

function sanitizeUser(user: StoredUser): UserProfile {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    organization: user.organization,
    roleTitle: user.roleTitle,
    preferredTheme: user.preferredTheme,
    createdAt: user.createdAt,
    lastLoginAt: user.lastLoginAt,
  };
}

interface TokenPayload {
  sub: string;
  jti: string;
  iat: number;
  exp: number;
}

function issueAuthToken(userId: string): string {
  const now = Date.now();
  const payload: TokenPayload = {
    sub: userId,
    jti: crypto.randomUUID(),
    iat: now,
    exp: now + SESSION_TTL_MS,
  };
  const encodedPayload = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const signature = crypto.createHmac('sha256', SESSION_SECRET).update(encodedPayload).digest('base64url');
  return `${encodedPayload}.${signature}`;
}

function verifyAuthToken(token: string): TokenPayload | null {
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [encodedPayload, providedSig] = parts;
  if (!encodedPayload || !providedSig) return null;

  const expectedSig = crypto.createHmac('sha256', SESSION_SECRET).update(encodedPayload).digest('base64url');
  const providedBuf = Buffer.from(providedSig, 'utf8');
  const expectedBuf = Buffer.from(expectedSig, 'utf8');
  if (providedBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(providedBuf, expectedBuf)) {
    return null;
  }

  try {
    const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8')) as TokenPayload;
    if (!payload.sub || !payload.jti || typeof payload.exp !== 'number') return null;
    if (Date.now() > payload.exp) return null;
    if (revokedTokenJtis.has(payload.jti)) return null;
    return payload;
  } catch {
    return null;
  }
}

function extractBearerToken(req: express.Request): string | null {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) return null;
  const token = header.slice(7).trim();
  return token || null;
}

function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email) && email.length <= 160;
}

// --- Reusable Single URL Scan Engine ---

async function performSingleUrlScan(rawInput: string): Promise<{ status: number; error?: string; result?: UrlScanResult }> {
  const startedAt = Date.now();
  const trimmed = rawInput.trim();
  if (!trimmed || trimmed.length > 2048) {
    return { status: 400, error: 'Please provide a valid URL (between 1 and 2048 characters).' };
  }

  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  let parsed: URL;
  try {
    parsed = new URL(withScheme);
  } catch {
    return { status: 400, error: 'Malformed URL. Enter a valid domain or address such as https://example.com.' };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { status: 400, error: 'Only http:// and https:// URLs are supported for security scanning.' };
  }

  const ssrfCheck = await resolveAndVerifyPublicTarget(parsed.hostname);
  if (!ssrfCheck.safe) {
    return { status: 400, error: ssrfCheck.reason || 'Localhost and private network addresses cannot be scanned.' };
  }

  const signals = analyzeUrlLexicalSignals(parsed);

  const [dnsIntel, rdapIntel] = await Promise.all([
    inspectDns(parsed.hostname, signals.registrableDomain),
    inspectRdap(signals.registrableDomain),
  ]);

  const allResolvedIps = [...dnsIntel.ipv4, ...dnsIntel.ipv6];
  if (allResolvedIps.some((ip) => isPrivateOrReservedIp(ip))) {
    return { status: 400, error: 'Target hostname resolved to a restricted private or loopback IP address.' };
  }

  let tlsIntel: TlsIntel = {
    checked: false,
    valid: false,
    authorized: false,
    authorizationError: null,
    protocol: null,
    cipher: null,
    issuer: null,
    subject: null,
    subjectAltNames: [],
    serialNumber: null,
    fingerprint256: null,
    validFrom: null,
    validTo: null,
    daysRemaining: null,
    selfSigned: false,
    error: parsed.protocol === 'http:' ? 'Plaintext HTTP URL does not use TLS' : 'Host did not resolve in DNS',
  };

  let httpIntel: HttpIntel = {
    checked: false,
    finalUrl: null,
    statusCode: null,
    redirectChain: [],
    crossDomainRedirect: false,
    serverHeader: null,
    contentType: null,
    pageTitle: null,
    passwordInputCount: 0,
    externalFormAction: null,
    hiddenIframeCount: 0,
    securityHeaders: {
      hsts: false,
      csp: false,
      xFrameOptions: false,
      xContentTypeOptions: false,
      referrerPolicy: false,
    },
    error: 'Skipped HTTP probe because host did not resolve in DNS',
  };

  if (dnsIntel.resolved && allResolvedIps.length > 0) {
    const targetIp = dnsIntel.ipv4[0] || dnsIntel.ipv6[0];
    const portNum = Number(parsed.port) || (parsed.protocol === 'https:' ? 443 : 80);

    const [tlsResult, httpResult] = await Promise.all([
      parsed.protocol === 'https:' ? inspectTls(targetIp, parsed.hostname, portNum) : Promise.resolve(tlsIntel),
      inspectHttpAndContent(parsed, signals.registrableDomain),
    ]);
    tlsIntel = tlsResult;
    httpIntel = httpResult;
  }

  const report = buildEvidenceReport(signals, dnsIntel, rdapIntel, tlsIntel, httpIntel);

  let aiAssessment: AiSynthesisInfo;
  const ai = createAiClient();
  if (!ai) {
    aiAssessment = {
      status: 'unavailable',
      error: 'GEMINI_API_KEY is not configured; displaying verified deterministic DNS, RDAP, TLS, HTTP, and URL evidence.',
    };
  } else {
    try {
      const aiPayload = {
        url: signals.normalizedUrl,
        deterministicVerdict: report.verdict,
        deterministicRiskScore: report.riskScore,
        evidenceItems: report.evidenceItems,
        dns: {
          resolved: dnsIntel.resolved,
          hasSpf: dnsIntel.hasSpf,
          hasDmarc: dnsIntel.hasDmarc,
          nameservers: dnsIntel.nameservers,
        },
        rdap: {
          registrar: rdapIntel.registrar,
          domainAgeDays: rdapIntel.domainAgeDays,
        },
        tls: {
          checked: tlsIntel.checked,
          authorized: tlsIntel.authorized,
          issuer: tlsIntel.issuer,
          daysRemaining: tlsIntel.daysRemaining,
          selfSigned: tlsIntel.selfSigned,
        },
        http: {
          statusCode: httpIntel.statusCode,
          crossDomainRedirect: httpIntel.crossDomainRedirect,
          passwordInputCount: httpIntel.passwordInputCount,
          externalFormAction: httpIntel.externalFormAction,
        },
      };

      const aiResponse = await ai.models.generateContent({
        model: 'gemini-4-hydrogen',
        contents: `Review this verified URL security scan telemetry and write a concise 2-sentence analyst narrative and 2-3 tailored user recommendations.\n\n${JSON.stringify(aiPayload)}`,
        config: {
          abortSignal: AbortSignal.timeout(6000),
          thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
          systemInstruction:
            'You are a cybersecurity threat analyst for AI CyberShield. Summarize ONLY the verified facts present in the telemetry. Never invent indicators or scores.',
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              narrative: { type: Type.STRING },
              recommendations: { type: Type.ARRAY, items: { type: Type.STRING } },
            },
            required: ['narrative', 'recommendations'],
          },
        },
      });

      const parsedAi = JSON.parse((aiResponse.text ?? '{}').trim()) as {
        narrative?: string;
        recommendations?: string[];
      };

      aiAssessment = {
        status: 'completed',
        model: 'gemini-4-hydrogen',
        narrative: typeof parsedAi.narrative === 'string' ? parsedAi.narrative : undefined,
        recommendations: Array.isArray(parsedAi.recommendations) ? parsedAi.recommendations.map(String) : undefined,
      };
    } catch (err) {
      aiAssessment = {
        status: 'unavailable',
        error: err instanceof Error ? err.message : 'AI enrichment request failed',
      };
    }
  }

  return {
    status: 200,
    result: {
      id: crypto.randomUUID(),
      scannedAt: new Date().toISOString(),
      durationMs: Date.now() - startedAt,
      verdict: report.verdict,
      riskScore: report.riskScore,
      threatCategory: report.threatCategory,
      summary: aiAssessment.narrative || report.summary,
      evidenceItems: report.evidenceItems,
      recommendations:
        aiAssessment.recommendations && aiAssessment.recommendations.length > 0
          ? aiAssessment.recommendations
          : report.recommendations,
      signals,
      dns: dnsIntel,
      rdap: rdapIntel,
      tls: tlsIntel,
      http: httpIntel,
      aiAssessment,
    },
  };
}

// --- CISA KEV Cache ---

let kevCache: { fetchedAt: number; data: KevFeedResponse } | null = null;
const KEV_CACHE_TTL_MS = 15 * 60 * 1000;

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '512kb' }));

  app.get('/api/health', (_req, res) => {
    res.json({ ok: true, service: 'AI CyberShield' });
  });

  // --- Auth & User Profile Routes ---

  app.post('/api/auth/signup', async (req, res) => {
    const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
    const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    const organization = typeof req.body?.organization === 'string' ? req.body.organization.trim().slice(0, 80) : 'Independent Analyst';
    const roleTitle = typeof req.body?.roleTitle === 'string' ? req.body.roleTitle.trim().slice(0, 60) : 'Security Researcher';
    const preferredTheme: ThemeMode = req.body?.preferredTheme === 'light' ? 'light' : 'dark';

    if (name.length < 2 || name.length > 80) {
      res.status(400).json({ error: 'Full name must be between 2 and 80 characters.' });
      return;
    }
    if (!isValidEmail(email)) {
      res.status(400).json({ error: 'Please enter a valid email address.' });
      return;
    }
    if (password.length < 8 || password.length > 128) {
      res.status(400).json({ error: 'Password must be between 8 and 128 characters.' });
      return;
    }

    const store = await readStore();
    if (store.users.some((u) => u.email === email)) {
      res.status(409).json({ error: 'An account with this email already exists. Please log in instead.' });
      return;
    }

    const now = new Date().toISOString();
    const newUser: StoredUser = {
      id: crypto.randomUUID(),
      name,
      email,
      organization: organization || 'Independent Analyst',
      roleTitle: roleTitle || 'Security Researcher',
      preferredTheme,
      createdAt: now,
      lastLoginAt: now,
      passwordHash: hashPassword(password),
    };

    store.users.push(newUser);
    store.histories[newUser.id] = { urlScans: [], threatAnalyses: [], passwordAudits: [], alerts: [] };
    await writeStore(store);

    const token = issueAuthToken(newUser.id);
    res.status(201).json({ token, user: sanitizeUser(newUser) });
  });

  app.post('/api/auth/login', async (req, res) => {
    const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';

    if (!isValidEmail(email) || !password) {
      res.status(400).json({ error: 'Email and password are required.' });
      return;
    }

    const store = await readStore();
    const userIndex = store.users.findIndex((u) => u.email === email);
    if (userIndex === -1 || !verifyPassword(password, store.users[userIndex].passwordHash)) {
      res.status(401).json({ error: 'Invalid email or password.' });
      return;
    }

    store.users[userIndex].lastLoginAt = new Date().toISOString();
    await writeStore(store);

    const token = issueAuthToken(store.users[userIndex].id);
    res.json({ token, user: sanitizeUser(store.users[userIndex]) });
  });

  app.post('/api/auth/logout', (req, res) => {
    const token = extractBearerToken(req);
    if (token) {
      const payload = verifyAuthToken(token);
      if (payload) {
        revokedTokenJtis.add(payload.jti);
      }
    }
    res.json({ ok: true });
  });

  app.get('/api/auth/me', async (req, res) => {
    const token = extractBearerToken(req);
    const payload = token ? verifyAuthToken(token) : null;
    if (!payload) {
      res.status(401).json({ error: 'Authentication required.' });
      return;
    }

    const store = await readStore();
    const user = store.users.find((u) => u.id === payload.sub);
    if (!user) {
      res.status(401).json({ error: 'User session is no longer valid.' });
      return;
    }
    res.json({ user: sanitizeUser(user) });
  });

  app.patch('/api/profile', async (req, res) => {
    const token = extractBearerToken(req);
    const payload = token ? verifyAuthToken(token) : null;
    if (!payload) {
      res.status(401).json({ error: 'Authentication required.' });
      return;
    }

    const store = await readStore();
    const userIdx = store.users.findIndex((u) => u.id === payload.sub);
    if (userIdx === -1) {
      res.status(404).json({ error: 'User account not found.' });
      return;
    }

    const name = typeof req.body?.name === 'string' ? req.body.name.trim() : store.users[userIdx].name;
    const organization =
      typeof req.body?.organization === 'string'
        ? req.body.organization.trim().slice(0, 80)
        : store.users[userIdx].organization;
    const roleTitle =
      typeof req.body?.roleTitle === 'string'
        ? req.body.roleTitle.trim().slice(0, 60)
        : store.users[userIdx].roleTitle;
    const preferredTheme: ThemeMode =
      req.body?.preferredTheme === 'light' || req.body?.preferredTheme === 'dark'
        ? req.body.preferredTheme
        : store.users[userIdx].preferredTheme;

    if (name.length < 2 || name.length > 80) {
      res.status(400).json({ error: 'Full name must be between 2 and 80 characters.' });
      return;
    }

    store.users[userIdx] = {
      ...store.users[userIdx],
      name,
      organization: organization || 'Independent Analyst',
      roleTitle: roleTitle || 'Security Researcher',
      preferredTheme,
    };

    await writeStore(store);
    res.json({ user: sanitizeUser(store.users[userIdx]) });
  });

  app.post('/api/auth/change-password', async (req, res) => {
    const token = extractBearerToken(req);
    const payload = token ? verifyAuthToken(token) : null;
    if (!payload) {
      res.status(401).json({ error: 'Authentication required.' });
      return;
    }

    const currentPassword = typeof req.body?.currentPassword === 'string' ? req.body.currentPassword : '';
    const newPassword = typeof req.body?.newPassword === 'string' ? req.body.newPassword : '';

    if (!currentPassword || newPassword.length < 8 || newPassword.length > 128) {
      res.status(400).json({ error: 'Provide current password and a new password (8–128 characters).' });
      return;
    }

    const store = await readStore();
    const userIdx = store.users.findIndex((u) => u.id === payload.sub);
    if (userIdx === -1) {
      res.status(404).json({ error: 'Account not found.' });
      return;
    }

    if (!verifyPassword(currentPassword, store.users[userIdx].passwordHash)) {
      res.status(401).json({ error: 'Current password is incorrect.' });
      return;
    }

    store.users[userIdx].passwordHash = hashPassword(newPassword);
    await writeStore(store);
    res.json({ ok: true });
  });

  app.get('/api/user/history', async (req, res) => {
    const token = extractBearerToken(req);
    const payload = token ? verifyAuthToken(token) : null;
    if (!payload) {
      res.status(401).json({ error: 'Authentication required.' });
      return;
    }

    const store = await readStore();
    const history = store.histories[payload.sub] || {
      urlScans: [],
      threatAnalyses: [],
      passwordAudits: [],
      alerts: [],
    };
    res.json(history);
  });

  app.put('/api/user/history', async (req, res) => {
    const token = extractBearerToken(req);
    const payload = token ? verifyAuthToken(token) : null;
    if (!payload) {
      res.status(401).json({ error: 'Authentication required.' });
      return;
    }

    const store = await readStore();
    if (!store.users.some((u) => u.id === payload.sub)) {
      res.status(404).json({ error: 'User not found.' });
      return;
    }

    const body = req.body as Partial<UserHistoryPayload>;
    store.histories[payload.sub] = {
      urlScans: Array.isArray(body.urlScans) ? body.urlScans.slice(0, 25) : [],
      threatAnalyses: Array.isArray(body.threatAnalyses) ? body.threatAnalyses.slice(0, 25) : [],
      passwordAudits: Array.isArray(body.passwordAudits) ? body.passwordAudits.slice(0, 25) : [],
      alerts: Array.isArray(body.alerts) ? body.alerts.slice(0, 50) : [],
    };

    await writeStore(store);
    res.json({ ok: true });
  });

  // 1A. Real Single-URL Phishing Scanner
  app.post('/api/scan-url', async (req, res) => {
    const rawInput = typeof req.body?.url === 'string' ? req.body.url.trim() : '';
    const outcome = await performSingleUrlScan(rawInput);
    if (outcome.error || !outcome.result) {
      res.status(outcome.status).json({ error: outcome.error || 'URL scan failed.' });
      return;
    }
    res.json(outcome.result);
  });

  // 1B. Multi-URL Batch Scanner (up to 10 URLs, bounded concurrency)
  app.post('/api/scan-urls', async (req, res) => {
    const startedAt = Date.now();
    const rawList: unknown[] = Array.isArray(req.body?.urls) ? req.body.urls : [];
    const cleaned = Array.from(
      new Set<string>(
        rawList
          .filter((item: unknown): item is string => typeof item === 'string')
          .map((s: string) => s.trim())
          .filter(Boolean),
      ),
    ).slice(0, 10);

    if (cleaned.length === 0) {
      res.status(400).json({ error: 'Provide between 1 and 10 valid URLs to scan.' });
      return;
    }

    const items: BatchUrlScanItem[] = new Array(cleaned.length);
    const concurrency = 3;
    let cursor = 0;

    async function worker() {
      while (cursor < cleaned.length) {
        const index = cursor++;
        const target = cleaned[index];
        try {
          const outcome = await performSingleUrlScan(target);
          if (outcome.result) {
            items[index] = { inputUrl: target, ok: true, result: outcome.result };
          } else {
            items[index] = { inputUrl: target, ok: false, error: outcome.error || 'Scan failed.' };
          }
        } catch (err) {
          items[index] = {
            inputUrl: target,
            ok: false,
            error: err instanceof Error ? err.message : 'Unexpected scan error.',
          };
        }
      }
    }

    await Promise.all(Array.from({ length: Math.min(concurrency, cleaned.length) }, () => worker()));

    const completed = items.filter((i) => i.ok && i.result);
    const response: BatchUrlScanResponse = {
      batchId: crypto.randomUUID(),
      scannedAt: new Date().toISOString(),
      totalDurationMs: Date.now() - startedAt,
      summary: {
        total: items.length,
        completed: completed.length,
        failed: items.length - completed.length,
        safe: completed.filter((i) => i.result?.verdict === 'Safe').length,
        suspicious: completed.filter((i) => i.result?.verdict === 'Suspicious').length,
        malicious: completed.filter((i) => i.result?.verdict === 'Malicious').length,
      },
      items,
    };

    res.json(response);
  });

  // 2. Privacy-Preserving Password Breach Check (HIBP K-Anonymity Proxy)
  app.post('/api/check-password-breach', async (req, res) => {
    const prefix = typeof req.body?.prefix === 'string' ? req.body.prefix.trim().toUpperCase() : '';
    if (!/^[A-F0-9]{5}$/.test(prefix)) {
      res.status(400).json({ error: 'Invalid SHA-1 prefix. Must be exactly 5 hexadecimal characters.' });
      return;
    }

    try {
      const hibpRes = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
        method: 'GET',
        signal: AbortSignal.timeout(5000),
        headers: {
          'Add-Padding': 'true',
          'User-Agent': 'AICyberShield-PasswordAuditor',
        },
      });

      if (!hibpRes.ok) {
        res.status(502).json({ error: `Breach database returned status ${hibpRes.status}.` });
        return;
      }

      const text = await hibpRes.text();
      const suffixes = text
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean)
        .map((line) => {
          const [suffix, countStr] = line.split(':');
          return { suffix: (suffix || '').toUpperCase(), count: Number(countStr) || 0 };
        })
        .filter((entry) => entry.suffix.length === 35 && entry.count > 0);

      res.json({ prefix, suffixes });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Unable to reach breach lookup service';
      res.status(502).json({ error: `Breach check failed: ${msg}` });
    }
  });

  // 3. Cyber Threat Analysis Route
  app.post('/api/analyze-threat', async (req, res) => {
    const artifact = typeof req.body?.artifact === 'string' ? req.body.artifact.trim() : '';
    const contextType = typeof req.body?.contextType === 'string' ? req.body.contextType.trim() : 'General Artifact';

    if (!artifact || artifact.length < 6) {
      res.status(400).json({ error: 'Provide a suspicious message, log snippet, script, or indicator (minimum 6 characters).' });
      return;
    }
    if (artifact.length > 12000) {
      res.status(400).json({ error: 'Input exceeds maximum 12,000 character limit.' });
      return;
    }

    const ai = createAiClient();
    if (!ai) {
      res.status(503).json({
        error: 'GEMINI_API_KEY is not configured on the server. Add your key in Settings > Secrets to enable AI threat analysis.',
      });
      return;
    }

    const deterministicIocs = extractDeterministicIocs(artifact);

    try {
      const aiResponse = await ai.models.generateContent({
        model: 'gemini-4-hydrogen',
        contents: `Context Type: ${contextType}\nDeterministic Extracted IOCs: ${JSON.stringify(deterministicIocs)}\n\nArtifact to Analyze:\n"""\n${artifact}\n"""`,
        config: {
          abortSignal: AbortSignal.timeout(12000),
          thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
          systemInstruction:
            'You are a Principal SOC Threat Analyst inside AI CyberShield. Perform deep cybersecurity threat analysis on the submitted artifact (phishing email, smishing SMS, shell script, server log, or IOCs). Return valid JSON with: severity ("Benign" | "Low" | "Medium" | "High" | "Critical"), riskScore (0-100), threatCategory, attackVector, summary (2-3 crisp sentences), indicators (merge and evaluate the extracted IOCs plus any additional behavioral indicators found, assigning riskLevel "Informational" | "Suspicious" | "Malicious"), mitreTechniques (relevant MITRE ATT&CK techniques with id like T1566.001, tactic, and name), and remediationSteps (3-5 concrete containment and remediation actions).',
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              severity: { type: Type.STRING },
              riskScore: { type: Type.INTEGER },
              threatCategory: { type: Type.STRING },
              attackVector: { type: Type.STRING },
              summary: { type: Type.STRING },
              indicators: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    value: { type: Type.STRING },
                    type: { type: Type.STRING },
                    riskLevel: { type: Type.STRING },
                    note: { type: Type.STRING },
                  },
                  required: ['value', 'type', 'riskLevel', 'note'],
                },
              },
              mitreTechniques: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    id: { type: Type.STRING },
                    tactic: { type: Type.STRING },
                    name: { type: Type.STRING },
                  },
                  required: ['id', 'tactic', 'name'],
                },
              },
              remediationSteps: {
                type: Type.ARRAY,
                items: { type: Type.STRING },
              },
            },
            required: [
              'severity',
              'riskScore',
              'threatCategory',
              'attackVector',
              'summary',
              'indicators',
              'mitreTechniques',
              'remediationSteps',
            ],
          },
        },
      });

      const parsedAi = JSON.parse((aiResponse.text ?? '{}').trim());
      const validSeverities = new Set(['Benign', 'Low', 'Medium', 'High', 'Critical']);
      const severity = validSeverities.has(parsedAi.severity) ? parsedAi.severity : 'Medium';

      const result: ThreatAnalysisResult = {
        id: crypto.randomUUID(),
        analyzedAt: new Date().toISOString(),
        contextType,
        inputPreview: artifact.slice(0, 140) + (artifact.length > 140 ? '…' : ''),
        severity,
        riskScore: Math.max(0, Math.min(100, Number(parsedAi.riskScore) || 50)),
        threatCategory: String(parsedAi.threatCategory || 'Threat Assessment'),
        attackVector: String(parsedAi.attackVector || 'Unclassified'),
        summary: String(parsedAi.summary || 'Threat analysis completed.'),
        indicators: Array.isArray(parsedAi.indicators) ? parsedAi.indicators : [],
        mitreTechniques: Array.isArray(parsedAi.mitreTechniques) ? parsedAi.mitreTechniques : [],
        remediationSteps: Array.isArray(parsedAi.remediationSteps) ? parsedAi.remediationSteps.map(String) : [],
      };

      res.json(result);
    } catch (err) {
      let msg = err instanceof Error ? err.message : 'Threat analysis failed';
      try {
        const parsedErr = JSON.parse(msg) as { error?: { message?: string } };
        if (parsedErr?.error?.message) msg = parsedErr.error.message;
      } catch {
        // Keep original message if not JSON
      }
      res.status(502).json({ error: `AI threat analysis unavailable: ${msg}` });
    }
  });

  // 4. Live CISA Known Exploited Vulnerabilities (KEV) Security Advisories
  app.get('/api/alerts/kev', async (_req, res) => {
    if (kevCache && Date.now() - kevCache.fetchedAt < KEV_CACHE_TTL_MS) {
      res.json(kevCache.data);
      return;
    }

    try {
      const cisaRes = await fetch(
        'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        {
          signal: AbortSignal.timeout(7000),
          headers: {
            'User-Agent': 'AICyberShield-AlertFeed/1.0',
          },
        },
      );

      if (!cisaRes.ok) {
        res.status(502).json({ error: `CISA advisory feed returned HTTP ${cisaRes.status}.` });
        return;
      }

      const raw = (await cisaRes.json()) as {
        catalogVersion?: string;
        dateReleased?: string;
        count?: number;
        vulnerabilities?: KevEntry[];
      };

      const sorted = (Array.isArray(raw.vulnerabilities) ? raw.vulnerabilities : [])
        .slice()
        .sort((a, b) => (b.dateAdded || '').localeCompare(a.dateAdded || ''))
        .slice(0, 25);

      const payload: KevFeedResponse = {
        catalogVersion: raw.catalogVersion || 'Current',
        dateReleased: raw.dateReleased || new Date().toISOString(),
        totalCount: raw.count || sorted.length,
        vulnerabilities: sorted,
      };

      kevCache = { fetchedAt: Date.now(), data: payload };
      res.json(payload);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Network error';
      res.status(502).json({ error: `Unable to fetch live CISA advisories: ${msg}` });
    }
  });

  app.use('/api', (_req, res) => {
    res.status(404).json({ error: 'API endpoint not found.' });
  });

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(__dirname, 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`AI CyberShield server running at http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start AI CyberShield server:', err);
  process.exit(1);
});
