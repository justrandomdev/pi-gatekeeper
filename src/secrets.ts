/**
 * Deterministic secrets detection: the gitleaks corpus compiled to JS
 * regexes and scanned before every rule and the model. Hits block, are
 * masked everywhere they are reported, and are overridable only by the
 * operator's secrets.toml. See docs/adr/0004.
 */

import { parse as parseToml } from "smol-toml";

export interface SecretsHit {
  ruleId: string;
  secret: string;
  masked: string;
}

interface CompiledRule {
  id: string;
  /** content regex; path-only rules (e.g. pkcs12-file) have none */
  regex?: RegExp;
  /** path regex, matched against the target path and path-shaped tokens */
  pathRegex?: RegExp;
  /** lowercase prefilter: the scanned text must contain one */
  keywords: string[];
  /** minimum Shannon entropy of the matched secret (0 = no check) */
  entropy: number;
  /** 1-based regex group that holds the secret */
  secretGroup?: number;
  allowSecret: RegExp[];
  allowPath: RegExp[];
  stopwords: string[];
}

export interface SecretsOverride {
  id: string;
  match?: RegExp;
  path?: RegExp;
}

export interface CompiledSecrets {
  rules: CompiledRule[];
  overrides: SecretsOverride[];
  globalAllowSecret: RegExp[];
  globalAllowPath: RegExp[];
  globalStopwords: string[];
  /** rules that failed RE2→JS translation and were skipped */
  skipped: number;
  total: number;
}

/** ReDoS bound on scanned input per call: a constant, not a knob (ADR-0004). */
export const MAX_SCAN_CHARS = 262_144;

/** RE2 → JS: inline `(?i)` becomes the `i` flag (slightly broader matching —
 *  the fail-closed direction) and `(?P<name>` becomes `(?<name>`. Returns
 *  undefined when the regex still fails to compile: the rule is skipped. */
function compileRegex(source: string): RegExp | undefined {
  try {
    const ci = source.includes("(?i)");
    const src = source.replace(/\(\?i\)/g, "").replace(/\(\?P</g, "(?<");
    return new RegExp(src, ci ? "ui" : "u");
  } catch {
    return undefined;
  }
}

function asStrings(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === "string");
  return typeof value === "string" ? [value] : [];
}

function asRegexes(value: unknown): RegExp[] {
  return asStrings(value)
    .map(compileRegex)
    .filter((r): r is RegExp => r !== undefined);
}

/** Shannon entropy over the characters of the secret, as gitleaks computes it. */
export function shannonEntropy(text: string): number {
  if (!text.length) return 0;
  const counts = new Map<string, number>();
  for (const ch of text) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / text.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** A matched secret is never reprinted: rule id plus a masked size peek. */
export function maskSecret(secret: string): string {
  return secret.length < 8 ? `(${secret.length} chars)` : `${secret.slice(0, 3)}…(${secret.length} chars)`;
}

interface RuleDoc {
  id?: unknown;
  regex?: unknown;
  path?: unknown;
  keywords?: unknown;
  entropy?: unknown;
  secretGroup?: unknown;
  allowlists?: unknown;
}

function compileRule(raw: RuleDoc, fallbackIndex: number): CompiledRule | undefined {
  const id = typeof raw.id === "string" ? raw.id : `rule-${fallbackIndex}`;
  let regex: RegExp | undefined;
  let pathRegex: RegExp | undefined;
  if (typeof raw.regex === "string") {
    regex = compileRegex(raw.regex);
    if (!regex) return undefined;
  }
  if (typeof raw.path === "string") {
    pathRegex = compileRegex(raw.path);
    if (!pathRegex) return undefined;
  }
  if (!regex && !pathRegex) return undefined;
  const allow = { secret: [] as RegExp[], path: [] as RegExp[], stopwords: [] as string[] };
  for (const entry of Array.isArray(raw.allowlists) ? (raw.allowlists as Record<string, unknown>[]) : []) {
    allow.secret.push(...asRegexes(entry.regexes ?? entry.regex));
    allow.path.push(...asRegexes(entry.paths ?? entry.path));
    allow.stopwords.push(...asStrings(entry.stopwords));
  }
  return {
    id,
    regex,
    pathRegex,
    keywords: asStrings(raw.keywords).map((k) => k.toLowerCase()),
    entropy: typeof raw.entropy === "number" ? raw.entropy : 0,
    secretGroup: typeof raw.secretGroup === "number" ? raw.secretGroup : undefined,
    allowSecret: allow.secret,
    allowPath: allow.path,
    stopwords: allow.stopwords,
  };
}

/** Compile a gitleaks-shaped TOML document: [[rules]] plus the top-level
 *  [allowlist]. Throws on invalid TOML — the caller keeps the previous
 *  snapshot (ADR-0004's sanity gate). */
export function compileSecrets(tomlText: string): CompiledSecrets {
  const doc = parseToml(tomlText) as Record<string, unknown>;
  const rawRules = Array.isArray(doc.rules) ? (doc.rules as RuleDoc[]) : [];
  const rules: CompiledRule[] = [];
  let skipped = 0;
  for (const raw of rawRules) {
    const rule = compileRule(raw, rules.length + skipped + 1);
    if (rule) rules.push(rule);
    else skipped++;
  }
  const global = (doc.allowlist ?? {}) as Record<string, unknown>;
  return {
    rules,
    overrides: [],
    globalAllowSecret: asRegexes(global.regexes),
    globalAllowPath: asRegexes(global.paths),
    globalStopwords: asStrings(global.stopwords),
    skipped,
    total: rawRules.length,
  };
}

/** Compile the operator's secrets.toml: [[rules]] in gitleaks shape, and
 *  [[allow]] suppressions (id plus optional match/path regexes). */
export function compileUserSecrets(tomlText: string): { rules: CompiledRule[]; overrides: SecretsOverride[] } {
  const doc = parseToml(tomlText) as Record<string, unknown>;
  const rules: CompiledRule[] = [];
  let skipped = 0;
  for (const raw of Array.isArray(doc.rules) ? (doc.rules as RuleDoc[]) : []) {
    const rule = compileRule(raw, rules.length + skipped + 1);
    if (rule) rules.push(rule);
    else skipped++;
  }
  const overrides: SecretsOverride[] = [];
  for (const raw of Array.isArray(doc.allow) ? (doc.allow as Record<string, unknown>[]) : []) {
    if (typeof raw.id !== "string") continue;
    overrides.push({
      id: raw.id,
      match: typeof raw.match === "string" ? compileRegex(raw.match) : undefined,
      path: typeof raw.path === "string" ? compileRegex(raw.path) : undefined,
    });
  }
  return { rules, overrides };
}

/** Does this override suppress the hit? id must match, and every present
 *  condition (match on the secret, path on the target) must hold. */
function suppressedByOverride(
  overrides: SecretsOverride[],
  ruleId: string,
  secret: string,
  targetPath: string | undefined,
): boolean {
  return overrides.some(
    (o) =>
      o.id === ruleId &&
      (o.match === undefined || o.match.test(secret)) &&
      (o.path === undefined || (targetPath !== undefined && o.path.test(targetPath))),
  );
}

/** Scan one call's text (and target path, for path rules and path
 *  allowlists). First hit wins; returns undefined when clean. */
export function scanSecrets(
  compiled: CompiledSecrets,
  text: string,
  targetPath?: string,
): SecretsHit | undefined {
  const capped = text.length > MAX_SCAN_CHARS ? text.slice(0, MAX_SCAN_CHARS) : text;
  const lower = capped.toLowerCase();
  const pathCandidates: string[] = targetPath !== undefined ? [targetPath] : [];
  for (const token of capped.split(/\s+/)) {
    if (token.includes("/")) pathCandidates.push(token.replace(/^["'([{]+|["',;|&)]+$/g, ""));
  }

  const check = (rule: CompiledRule, secret: string): SecretsHit | undefined => {
    if (rule.entropy > 0 && shannonEntropy(secret) < rule.entropy) return undefined;
    for (const re of rule.allowSecret) if (re.test(secret)) return undefined;
    if (targetPath !== undefined) for (const re of rule.allowPath) if (re.test(targetPath)) return undefined;
    for (const stopword of rule.stopwords) if (secret.toLowerCase().includes(stopword.toLowerCase())) return undefined;
    for (const re of compiled.globalAllowSecret) if (re.test(secret)) return undefined;
    if (targetPath !== undefined) for (const re of compiled.globalAllowPath) if (re.test(targetPath)) return undefined;
    for (const stopword of compiled.globalStopwords) if (secret.toLowerCase().includes(stopword.toLowerCase())) return undefined;
    if (suppressedByOverride(compiled.overrides, rule.id, secret, targetPath)) return undefined;
    return { ruleId: rule.id, secret, masked: maskSecret(secret) };
  };

  for (const rule of compiled.rules) {
    if (rule.regex) {
      if (rule.keywords.length && !rule.keywords.some((k) => lower.includes(k))) continue;
      const match = rule.regex.exec(capped);
      if (match) {
        const secret = rule.secretGroup !== undefined ? (match[rule.secretGroup] ?? match[0]) : match[0];
        const hit = check(rule, secret);
        if (hit) return hit;
      }
    }
    if (rule.pathRegex) {
      for (const candidate of pathCandidates) {
        if (rule.pathRegex.test(candidate)) {
          const hit = check(rule, candidate);
          if (hit) return hit;
        }
      }
    }
  }
  return undefined;
}
