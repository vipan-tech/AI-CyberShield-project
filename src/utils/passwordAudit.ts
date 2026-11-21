export interface CrackTimeEstimate {
  onlineThrottled: string;
  offlineGpuRig: string;
  massiveCluster: string;
}

export interface PasswordAnalysis {
  length: number;
  entropyBits: number;
  shannonBits: number;
  score: number; // 0-100
  strengthLabel: 'Very Weak' | 'Weak' | 'Fair' | 'Strong' | 'Very Strong';
  charClasses: {
    lowercase: boolean;
    uppercase: boolean;
    numbers: boolean;
    symbols: boolean;
  };
  warnings: string[];
  suggestions: string[];
  crackTimes: CrackTimeEstimate;
  nistCompliant: boolean;
}

const COMMON_WEAK_TOKENS = [
  'password', 'passw0rd', 'admin', 'qwerty', 'azerty', 'letmein', 'welcome',
  'monkey', 'dragon', 'baseball', 'football', 'iloveyou', 'trustno1', 'sunshine',
  'princess', 'master', 'hello', 'freedom', 'whatever', 'shadow', 'superman',
  'batman', 'login', 'secret', 'system', 'default', 'changeme', '123456',
];

const KEYBOARD_ROWS = [
  '1234567890-=',
  'qwertyuiop[]\\',
  'asdfghjkl;\'',
  'zxcvbnm,./',
  'abcdefghijklmnopqrstuvwxyz',
  '0123456789',
];

function hasSequentialPattern(pw: string): boolean {
  const lower = pw.toLowerCase();
  if (lower.length < 4) return false;
  for (const row of KEYBOARD_ROWS) {
    const rev = row.split('').reverse().join('');
    for (let i = 0; i <= lower.length - 4; i++) {
      const slice = lower.slice(i, i + 4);
      if (row.includes(slice) || rev.includes(slice)) {
        return true;
      }
    }
  }
  return false;
}

function hasRepeatedRun(pw: string): boolean {
  return /(.)\1{2,}/.test(pw);
}

function computeShannonEntropy(pw: string): number {
  if (!pw.length) return 0;
  const freq = new Map<string, number>();
  for (const ch of pw) {
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }
  let entropyPerChar = 0;
  for (const count of freq.values()) {
    const p = count / pw.length;
    entropyPerChar -= p * Math.log2(p);
  }
  return Math.round(entropyPerChar * pw.length * 10) / 10;
}

export function formatDurationSeconds(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds >= 1e18) return 'Centuries+';
  if (seconds < 1) return 'Instant';
  if (seconds < 60) return `${Math.round(seconds)} sec`;
  const mins = seconds / 60;
  if (mins < 60) return `${Math.round(mins)} min`;
  const hours = mins / 60;
  if (hours < 24) return `${Math.round(hours)} hr`;
  const days = hours / 24;
  if (days < 30) return `${Math.round(days)} days`;
  const months = days / 30.44;
  if (months < 12) return `${Math.round(months)} mo`;
  const years = days / 365.25;
  if (years < 1000) return `${Math.round(years)} yr`;
  if (years < 1e6) return `${(years / 1000).toFixed(1)}k yr`;
  if (years < 1e9) return `${(years / 1e6).toFixed(1)}M yr`;
  if (years < 1e12) return `${(years / 1e9).toFixed(1)}B yr`;
  return 'Centuries+';
}

export function analyzePasswordStrength(password: string): PasswordAnalysis {
  const length = password.length;
  const charClasses = {
    lowercase: /[a-z]/.test(password),
    uppercase: /[A-Z]/.test(password),
    numbers: /[0-9]/.test(password),
    symbols: /[^A-Za-z0-9]/.test(password),
  };

  let poolSize = 0;
  if (charClasses.lowercase) poolSize += 26;
  if (charClasses.uppercase) poolSize += 26;
  if (charClasses.numbers) poolSize += 10;
  if (charClasses.symbols) poolSize += 33;
  if (poolSize === 0 && length > 0) poolSize = 26;

  const rawPoolBits = length > 0 ? length * Math.log2(poolSize) : 0;
  const shannonBits = computeShannonEntropy(password);

  const warnings: string[] = [];
  const suggestions: string[] = [];
  let penaltyBits = 0;

  const lower = password.toLowerCase();
  const matchedWord = COMMON_WEAK_TOKENS.find((w) => lower.includes(w));
  if (matchedWord) {
    warnings.push(`Contains predictable dictionary word or leaked token ("${matchedWord}")`);
    penaltyBits += 24;
  }

  if (hasSequentialPattern(password)) {
    warnings.push('Contains sequential characters or keyboard walk (e.g. "1234", "qwerty")');
    penaltyBits += 16;
  }

  if (hasRepeatedRun(password)) {
    warnings.push('Contains 3+ repeated identical characters in a row');
    penaltyBits += 10;
  }

  if (/(19\d\d|20[0-2]\d)/.test(password)) {
    warnings.push('Contains a common calendar year pattern');
    penaltyBits += 8;
  }

  const uniqueRatio = length > 0 ? new Set(password).size / length : 0;
  if (length >= 6 && uniqueRatio < 0.5) {
    warnings.push('Low character uniqueness across password length');
    penaltyBits += 10;
  }

  const effectiveBits = Math.max(0, Math.round((Math.min(rawPoolBits, shannonBits * 1.65 + 10) - penaltyBits) * 10) / 10);

  if (length < 8) {
    warnings.push('Below NIST SP 800-63B minimum length of 8 characters');
    suggestions.push('Increase length to at least 12–16 characters');
  } else if (length < 12) {
    suggestions.push('Use 14+ characters or a 4-word random passphrase for stronger resilience');
  }

  if (!charClasses.uppercase || !charClasses.lowercase) {
    suggestions.push('Mix both uppercase and lowercase letters');
  }
  if (!charClasses.numbers) {
    suggestions.push('Include non-sequential digits');
  }
  if (!charClasses.symbols) {
    suggestions.push('Add special characters (e.g., !, #, %, @, ^) or expand length');
  }
  if (matchedWord || hasSequentialPattern(password)) {
    suggestions.push('Replace common words and keyboard sequences with unrelated random words');
  }

  // Average guesses = 0.5 * 2^(effectiveBits)
  const combinations = Math.pow(2, Math.min(effectiveBits, 128));
  const avgGuesses = combinations * 0.5;

  const crackTimes: CrackTimeEstimate = {
    onlineThrottled: length === 0 ? '—' : formatDurationSeconds(avgGuesses / (100 / 3600)),
    offlineGpuRig: length === 0 ? '—' : formatDurationSeconds(avgGuesses / 1e10),
    massiveCluster: length === 0 ? '—' : formatDurationSeconds(avgGuesses / 1e12),
  };

  let score = 0;
  if (length > 0) {
    score = Math.min(100, Math.round((effectiveBits / 92) * 100));
    if (matchedWord && score > 35) score = 35;
    if (length < 8 && score > 28) score = 28;
  }

  let strengthLabel: PasswordAnalysis['strengthLabel'] = 'Very Weak';
  if (score >= 82) strengthLabel = 'Very Strong';
  else if (score >= 64) strengthLabel = 'Strong';
  else if (score >= 42) strengthLabel = 'Fair';
  else if (score >= 22) strengthLabel = 'Weak';

  return {
    length,
    entropyBits: effectiveBits,
    shannonBits,
    score,
    strengthLabel,
    charClasses,
    warnings,
    suggestions: Array.from(new Set(suggestions)),
    crackTimes,
    nistCompliant: length >= 8 && !matchedWord && effectiveBits >= 40,
  };
}

export async function computeSha1Parts(password: string): Promise<{ prefix: string; suffix: string }> {
  const data = new TextEncoder().encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-1', data);
  const hashHex = Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
  return {
    prefix: hashHex.slice(0, 5),
    suffix: hashHex.slice(5),
  };
}

function secureRandomInt(maxExclusive: number): number {
  const array = new Uint32Array(1);
  const limit = Math.floor(0x100000000 / maxExclusive) * maxExclusive;
  let value: number;
  do {
    crypto.getRandomValues(array);
    value = array[0];
  } while (value >= limit);
  return value % maxExclusive;
}

export function generateSecurePassword(options: {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
}): string {
  const pools: string[] = [];
  if (options.lowercase) pools.push('abcdefghijkmnopqrstuvwxyz');
  if (options.uppercase) pools.push('ABCDEFGHJKLMNPQRSTUVWXYZ');
  if (options.numbers) pools.push('23456789');
  if (options.symbols) pools.push('!@#$%^&*-_=+?');
  if (pools.length === 0) pools.push('abcdefghijkmnopqrstuvwxyz23456789');

  const combined = pools.join('');
  const targetLen = Math.max(8, Math.min(64, options.length));
  const chars: string[] = [];

  // Guarantee at least one char from each selected pool
  for (const pool of pools) {
    if (chars.length < targetLen) {
      chars.push(pool[secureRandomInt(pool.length)]);
    }
  }
  while (chars.length < targetLen) {
    chars.push(combined[secureRandomInt(combined.length)]);
  }

  // Fisher-Yates shuffle with CSPRNG
  for (let i = chars.length - 1; i > 0; i--) {
    const j = secureRandomInt(i + 1);
    const tmp = chars[i];
    chars[i] = chars[j];
    chars[j] = tmp;
  }
  return chars.join('');
}

const PASSPHRASE_WORDS = [
  'anchor', 'beacon', 'cobalt', 'cipher', 'delta', 'ember', 'falcon', 'granite',
  'harbor', 'indigo', 'jasper', 'kestrel', 'lantern', 'matrix', 'nebula', 'onyx',
  'paradox', 'quartz', 'raven', 'sentinel', 'tundra', 'uplink', 'vertex', 'warden',
  'zenith', 'aurora', 'bastion', 'canyon', 'dynamo', 'eclipse', 'fortress', 'glacier',
  'horizon', 'impulse', 'kinetic', 'labyrinth', 'monolith', 'neutron', 'obsidian', 'phantom',
  'quantum', 'reactor', 'spectrum', 'titan', 'vanguard', 'whisper', 'zephyr', 'archon',
];

export function generateSecurePassphrase(wordCount = 4): string {
  const words: string[] = [];
  for (let i = 0; i < wordCount; i++) {
    const w = PASSPHRASE_WORDS[secureRandomInt(PASSPHRASE_WORDS.length)];
    words.push(w.charAt(0).toUpperCase() + w.slice(1));
  }
  const num = secureRandomInt(90) + 10;
  return `${words.join('-')}-${num}`;
}
