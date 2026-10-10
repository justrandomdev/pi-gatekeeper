/**
 * Static rules: the fast layer of the gate. First hit wins; a rule hit
 * skips the decision model entirely. See docs/spec.md and GLOSSARY.md.
 */

import { realpath } from "node:fs/promises";
import { isAbsolute, join, normalize } from "node:path";

export interface Rule {
  /** allow or deny the call */
  action: "allow" | "deny";
  /** tool names this rule applies to; omit for any tool */
  tools?: string[];
  /** path/argument glob; omit for any arguments. `~` expands to home.
   *  File tools match against their path target (anchored, full match;
   *  a glob-free `deny` also covers everything beneath the pattern). Shell
   *  commands and other tools match over their text/serialized
   *  arguments, asymmetrically for safety: `allow` rules anchor to the
   *  start of the text (a leading `*` opts out; a glob-free `allow`
   *  matches exactly), and `*`/`**` cross everything; `deny` rules
   *  search the whole text so they catch exfiltration anywhere in a
   *  command. */
  pattern?: string;
  reason?: string;
}

/** Tools whose arguments carry a path target. */
const FILE_TOOLS = new Set(["read", "edit", "write"]);
/** Tools whose arguments carry arbitrary command text. */
const SHELL_TOOLS = new Set(["bash", "powershell"]);

function escapeRegex(text: string): string {
  return text.replace(/[.+^${}()|[\]\\]/g, "\\$&");
}

/** Convert a glob to a regex source. `**` matches anything, `*` matches
 *  within one path segment, `?` matches one character. */
function globToRegexSource(pattern: string): string {
  return pattern
    .split("**")
    .map((segment) =>
      segment
        .split("*")
        .map((piece) => piece.split("?").map(escapeRegex).join("."))
        .join("[^/]*"),
    )
    .join(".*");
}

function expandHome(text: string, home: string): string {
  return text.replace(/(^|[\s'"(=])~(?=$|[\/\s'"')])/g, (_m, lead: string) => lead + home);
}

/** Normalize a pattern: `~` expanded, trailing slash tolerated. */
function normalizePattern(pattern: string, home: string): string {
  return expandHome(pattern, home);
}

function matchesTarget(pattern: string, target: string, home: string): boolean {
  const source = globToRegexSource(normalizePattern(pattern, home));
  // Targets match fully: a pattern names the path it protects.
  return new RegExp(`^${source}$`).test(expandHome(target, home));
}

/** Content globs: `*` and `**` cross everything (spaces, slashes, &&). */
function contentGlobToRegexSource(pattern: string): string {
  return escapeRegex(pattern)
    .replace(/\*\*/g, ".*")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
}

function matchesContent(pattern: string, text: string, home: string, action: Rule["action"]): boolean {
  const source = contentGlobToRegexSource(normalizePattern(pattern, home));
  // Allows anchor to the start of the text (a leading * opts out); a
  // glob-free allow also anchors to the end — an exact-text match, so
  // `ls -la /tmp` cannot carry `ls -la /tmpsecrets` through. Denies
  // search anywhere so nothing hides mid-command.
  const anchored = action === "allow" && !pattern.startsWith("*");
  const exact = anchored && !/[*?]/.test(pattern);
  const regex = new RegExp(anchored ? `^${source}${exact ? "$" : ""}` : source);
  return regex.test(expandHome(text, home));
}

/** Split a shell chain into its component commands, respecting quotes.
 *  A heuristic splitter, not a shell parser: separators inside quotes are
 *  literal; command substitution stays inside a component (and defeats
 *  allow rules, see matchesShell). */
export function splitShellChain(command: string): string[] {
  const components: string[] = [];
  let current = "";
  let quote: "\"" | "'" | undefined;
  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    if (quote) {
      current += ch;
      if (ch === quote && command[i - 1] !== "\\") quote = undefined;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      current += ch;
      continue;
    }
    if (ch === "\\" && i + 1 < command.length) {
      current += ch + command[++i];
      continue;
    }
    const pair = command.slice(i, i + 2);
    if (pair === "&&" || pair === "||") {
      components.push(current);
      current = "";
      i++;
      continue;
    }
    // `&` separates (backgrounding) unless it is an fd duplication (2>&1):
    // a `>` still open at the end of the accumulated text means this `&`
    // belongs to the redirect, not the chain.
    if (ch === ";" || ch === "|" || ch === "\n" || (ch === "&" && !/>$/.test(current))) {
      components.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  components.push(current);
  return components.map((c) => c.trim()).filter(Boolean);
}

/** Command or process substitution inside a component. */
const SUBSTITUTION = /\$\(|`|<\(|>\(/;
/** Redirects to /dev/null: inert sinks, they write and leak nothing. */
const NULL_REDIRECT = /\d*(?:>>|>)\s*\/dev\/null/;
/** Fd duplication (2>&1): no new file target. */
const FD_DUP = /\d*(?:>>|>)\s*&\d+/;

/** Does this component contain something an allow rule must not silently pass? */
function defeatsAllow(component: string): boolean {
  if (SUBSTITUTION.test(component)) return true;
  const inert = component.replace(FD_DUP, "").replace(NULL_REDIRECT, "");
  // any remaining redirect operator (to a file or stdin) defeats the allow
  return />>|>/.test(inert) || /<(?!\()/.test(inert);
}

function matchesShell(rule: Rule, command: string, home: string): boolean {
  const components = splitShellChain(command);
  if (rule.action === "allow") {
    // Every component must match the pattern; substitution and file-target
    // redirects defeat the allow so the call falls to the model gate.
    return components.every(
      (c) => !defeatsAllow(c) && matchesContent(rule.pattern as string, c, home, "allow"),
    );
  }
  // A deny catches the chain if any component matches.
  return components.some((c) => matchesContent(rule.pattern as string, c, home, "deny"));
}

/** The text a rule (and the secrets engine) matches over: the shell
 *  command for shell tools, the serialized arguments otherwise. */
export function argsText(tool: string, args: Record<string, unknown>): string {
  if (SHELL_TOOLS.has(tool)) {
    const command = args?.command;
    if (typeof command === "string") return command;
  }
  return JSON.stringify(args ?? {});
}

/** Does this rule match the given call? File-tool targets also resolve
 *  against the cwd, so an absolute pattern (a grant) catches relative
 *  spellings of the same path. */
export function ruleMatches(rule: Rule, tool: string, args: Record<string, unknown>, home: string, cwd?: string): boolean {
  if (rule.tools && !rule.tools.includes(tool)) return false;
  if (!rule.pattern) return true;

  if (SHELL_TOOLS.has(tool)) {
    const command = args?.command;
    if (typeof command === "string" && rule.pattern) {
      return matchesShell(rule, command, home);
    }
  }
  if (FILE_TOOLS.has(tool)) {
    const target = args?.path;
    if (typeof target !== "string") return false;
    const raw = expandHome(target, home);
    const resolved = isAbsolute(raw) ? normalize(raw) : cwd ? normalize(join(cwd, raw)) : normalize(raw);
    // A glob-free deny also matches everything beneath the pattern: a file
    // target can never sit beneath a file, so this widens directories only.
    // Glob-bearing denies do exactly what their glob says.
    const widen = rule.action === "deny" && !/[*?]/.test(rule.pattern);
    const patterns = widen ? [rule.pattern, `${rule.pattern.replace(/\/+$/, "")}/**`] : [rule.pattern];
    return patterns.some((p) => matchesTarget(p, raw, home) || matchesTarget(p, resolved, home));
  }
  return matchesContent(rule.pattern, argsText(tool, args), home, rule.action);
}

/** First matching rule in order, or undefined. */
export function matchRules(
  rules: Rule[],
  tool: string,
  args: Record<string, unknown>,
  home: string,
  cwd?: string,
): Rule | undefined {
  return rules.find((rule) => ruleMatches(rule, tool, args, home, cwd));
}

/** Deny-rule patterns: the protected paths injected into model state. */
export function protectedPatterns(rules: Rule[]): string[] {
  return rules.filter((r) => r.action === "deny" && r.pattern).map((r) => r.pattern as string);
}

/** The directories the gate itself lives behind: config and decision log. */
export function gateDirs(home: string, cwd?: string): string[] {
  const dirs = [join(home, ".pi/agent/gate")];
  if (cwd) dirs.push(join(cwd, ".pi/gate"));
  return dirs.map((d) => normalize(d));
}

/** Self-protection: does this call touch the gate's own configuration,
 *  log, or secrets definitions? Checked before every rule, and
 *  overridable by none of them — an agent cannot neuter the gate through
 *  the gate. Every compared path is realpath'd best-effort, so a symlink
 *  chain into the gate dir is caught; realpath of a not-yet-existing
 *  target (a write creating a file) falls back to the lexical path. */
export async function touchesGatePaths(
  tool: string,
  args: Record<string, unknown>,
  home: string,
  cwd?: string,
): Promise<boolean> {
  const dirs = await Promise.all(gateDirs(home, cwd).map(real));
  if (FILE_TOOLS.has(tool)) {
    const raw = typeof args?.path === "string" ? expandHome(args.path, home) : undefined;
    if (raw === undefined) return false;
    const target = normalize(raw);
    // Resolve relative targets against the cwd before comparing with the
    // absolute gate dirs; a relative spelling that cannot resolve to one
    // (no cwd, or a dot-detour) still hits the literal gate-dir prefixes.
    const resolved = isAbsolute(target) ? target : cwd ? normalize(join(cwd, target)) : target;
    const realTarget = await real(resolved);
    if (dirs.some((d) => realTarget === d || realTarget.startsWith(`${d}/`))) return true;
    return [".pi/gate", ".pi/agent/gate"].some((p) => target === p || target.startsWith(`${p}/`));
  }
  const raw = expandHome(argsText(tool, args), home)
    .replace(/\$\{HOME\}/g, home)
    .replace(/\$HOME/g, home);
  // Normalize dot-segments inside path-looking tokens so
  // `.pi/agent/../agent/gate` cannot slip past a literal needle.
  const normalized = raw
    .split(/(\s+)/)
    .map((t) => (t.includes("/") && t.includes("..") ? normalize(t) : t))
    .join("");
  const needles = [...dirs.flatMap((d) => [`${d}/`, `${d} `]), ".pi/gate/", ".pi/agent/gate/"];
  if (needles.some((n) => raw.includes(n) || normalized.includes(n))) return true;
  // Symlink chains: realpath each path-shaped token (relative ones
  // resolve against the cwd) and flag any that lands inside a gate dir.
  const tokenTargets = raw
    .split(/\s+/)
    .map((t) => t.replace(/^["'([{]+|["',;|&)]+$/g, ""))
    .filter((t) => t.includes("/"))
    .map((t) => {
      const n = normalize(t);
      return isAbsolute(n) ? n : cwd ? join(cwd, n) : n;
    });
  const reals = await Promise.all(tokenTargets.map(real));
  if (reals.some((r) => dirs.some((d) => r === d || r.startsWith(`${d}/`)))) return true;
  // `cd` chains: track the virtual cwd across components and flag any cd
  // that lands inside a gate directory. Each relative cd resolves against
  // the previous cd's target, not the original cwd. Variables and dynamic
  // paths fall through to the model gate.
  let virtualCwd = cwd;
  for (const component of splitShellChain(raw)) {
    const match = /^cd\s+(.*)$/.exec(component);
    if (!match) continue;
    const target = normalize(expandHome(match[1], home).trim().replace(/^["']|["']$/g, ""));
    let next: string | undefined;
    if (target === "/" || target === "") {
      next = "/";
    } else if (target.startsWith("/")) {
      next = target;
    } else if (virtualCwd) {
      next = normalize(join(virtualCwd, target));
    } else {
      next = target;
    }
    if (next && dirs.some((d) => next === d || next.startsWith(`${d}/`))) return true;
    virtualCwd = next;
  }
  return false;
}

/** Best-effort realpath: resolves symlinks where the path exists, and
 *  returns the lexical path where it does not (a write creates files). */
async function real(target: string): Promise<string> {
  try {
    return await realpath(target);
  } catch {
    return target;
  }
}
