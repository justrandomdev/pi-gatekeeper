/**
 * Gatekeeper extension: wires the gate into pi's tool_call event and
 * exposes the /gate commands. See docs/spec.md.
 */

import os from "node:os";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { configPaths, DEFAULT_CONFIG, MULTI_ENDPOINT_MODES, resolveConfig, resolveEndpoints, resolveMode, selectEndpoint, type DeepPartial, type EndpointConfig, type GatekeeperConfig, type NamedEndpoint, type ScopedConfig } from "../src/config.js";
import { createSystemOneClassifier, type ClassifyInput } from "../src/classifier.js";
import { createGate, type GateDeps, type OperatorPromptInfo } from "../src/decision.js";
import { DecisionLog } from "../src/log.js";
import { createGatePrompt, type GatePromptResult } from "../src/prompt.js";
import { GateLogView } from "./log-view.js";
import { argsText, gateDirs, matchRules, protectedPatterns, type Rule } from "../src/rules.js";
import { compileSecrets, compileUserSecrets, scanSecrets, type CompiledSecrets, type SecretsHit, type SecretsOverride } from "../src/secrets.js";

export interface GatekeeperOptions {
  /** Overrides the home directory (config/log paths). Used by tests. */
  home?: string;
  /** Overrides fetch (the System One endpoint). Used by tests. */
  fetchFn?: typeof fetch;
}

type AnyCtx = ExtensionContext & {
  cwd: string;
  isProjectTrusted(): boolean;
};

/** `gate:config set` value validators: each returns an error message or
 *  undefined. Only whitelisted keys may be written. */
const isBoolean = (value: unknown): string | undefined =>
  typeof value === "boolean" ? undefined : "must be true or false";
const isString = (value: unknown): string | undefined =>
  typeof value === "string" ? undefined : "must be a string";
const isNonEmptyString = (value: unknown): string | undefined =>
  typeof value === "string" && value.trim() !== "" ? undefined : "must be a non-empty string";
const isPositiveInt = (value: unknown): string | undefined =>
  typeof value === "number" && Number.isInteger(value) && value > 0 ? undefined : "must be a positive integer";
const isNonNegativeInt = (value: unknown): string | undefined =>
  typeof value === "number" && Number.isInteger(value) && value >= 0 ? undefined : "must be zero or a positive integer";
const isPortion = (value: unknown): string | undefined =>
  typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1
    ? undefined
    : "must be a number between 0 and 1";
const isOneOf = (...options: string[]) =>
  (value: unknown): string | undefined =>
    options.includes(value as string) ? undefined : `must be one of ${options.map((o) => `"${o}"`).join(", ")}`;

const CONFIG_KEYS: Record<string, (value: unknown) => string | undefined> = {
  enabled: isBoolean,
  threshold: isPortion,
  policy: isNonEmptyString,
  failMode: isOneOf("ask", "block"),
  multiEndpointMode: isOneOf(...MULTI_ENDPOINT_MODES),
  selectedEndpoint: isNonEmptyString,
  notify: isOneOf("always", "summary", "off", "debug"),
  stateBudgetChars: isPositiveInt,
  "secrets.enabled": isBoolean,
  "secrets.autoUpdate": isBoolean,
  "secrets.source": isNonEmptyString,
  "endpoint.url": isNonEmptyString,
  "endpoint.model": isNonEmptyString,
  "endpoint.apiKey": isString,
  "endpoint.timeoutMs": isPositiveInt,
  "endpoint.keepAlive": isString,
  "log.level": isOneOf("user", "project"),
  "log.maxLines": isPositiveInt,
  "log.keepFiles": isNonNegativeInt,
  "log.retentionDays": isPositiveInt,
  "log.truncateArgsBytes": isPositiveInt,
};

export function createGatekeeper(pi: ExtensionAPI, options: GatekeeperOptions = {}): Promise<void> {
  const home = options.home ?? os.homedir();
  const fetchFn = options.fetchFn ?? fetch;

  let currentTask = "";
  let currentCtx: AnyCtx | undefined;
  let effective: GatekeeperConfig = resolveConfig({});
  const mtimeCache = new Map<string, number | undefined>();
  const stats = { allowed: 0, blocked: 0, asked: 0 };

  function userConfigPath(): string {
    return configPaths(home, "").user;
  }
  function projectConfigPath(cwd: string): string {
    return join(cwd, ".pi/gate/config.json");
  }

  async function readScoped(trusted: boolean, cwd: string): Promise<ScopedConfig> {
    const scoped: ScopedConfig = {};
    const candidates: [keyof ScopedConfig, string][] = [["user", userConfigPath()]];
    if (trusted) candidates.push(["project", projectConfigPath(cwd)]);
    for (const [key, path] of candidates) {
      try {
        scoped[key] = JSON.parse(await readFile(path, "utf8")) as Partial<GatekeeperConfig>;
      } catch {
        // absent or malformed: skip the level
      }
    }
    return scoped;
  }

  /** Hot reload: re-read config only when a file's mtime changed. */
  async function refreshConfig(ctx: AnyCtx): Promise<void> {
    const paths = [userConfigPath(), ctx.isProjectTrusted() ? projectConfigPath(ctx.cwd) : null].filter(
      (p): p is string => p !== null,
    );
    let changed = false;
    for (const path of paths) {
      let mtime: number | undefined;
      try {
        mtime = (await stat(path)).mtimeMs;
      } catch {
        mtime = undefined;
      }
      if (mtimeCache.get(path) !== mtime) {
        mtimeCache.set(path, mtime);
        changed = true;
      }
    }
    if (changed) {
      effective = resolveConfig(await readScoped(ctx.isProjectTrusted(), ctx.cwd));
    }
  }

  function logDir(cwd: string): string {
    return effective.log.level === "project" ? join(cwd, ".pi/gate") : join(home, ".pi/agent/gate");
  }

  /** The /gate status mode line (ADR-0007): the act and its effective
   *  selection. An invalid hand-edited mode is reported here too — the
   *  operator sees the posture is unreadable, never silently defaulted. */
  function modeLine(config: GatekeeperConfig, endpoints: NamedEndpoint[]): string {
    try {
      const mode = resolveMode(config);
      if (mode === "jury") return `jury › ${endpoints.length} endpoints`;
      if (mode === "fallback") return "fallback › first-hit";
      const { endpoint, warning } = selectEndpoint(endpoints, config);
      return `modelSelect › ${endpoint.name}${warning ? ` (selected "${config.selectedEndpoint}" not found)` : ""}`;
    } catch (error) {
      return (error as Error).message;
    }
  }

  let cachedLogger: { key: string; logger: DecisionLog } | undefined;
  function logger(cwd: string): DecisionLog {
    const key = [
      logDir(cwd),
      effective.log.maxLines,
      effective.log.keepFiles,
      effective.log.retentionDays,
    ].join("|");
    // One instance per resolved log config: the class caches its line
    // count, so a fresh instance per decision would re-read the whole
    // active log on every gated call (a multi-MB read at default maxLines).
    if (!cachedLogger || cachedLogger.key !== key) {
      cachedLogger = {
        key,
        logger: new DecisionLog({
          dir: logDir(cwd),
          maxLines: effective.log.maxLines,
          keepFiles: effective.log.keepFiles,
          retentionDays: effective.log.retentionDays,
        }),
      };
    }
    return cachedLogger.logger;
  }

  // ---- Deterministic secrets detection (ADR-0004) ----
  // The machine-managed snapshot (auto-updated) and the operator's override
  // file live in the gate dir — self-protection (ADR-0003) denies every
  // agent tool call touching either.
  const gateSecretsDir = join(home, ".pi/agent/gate");
  const snapshotPath = join(gateSecretsDir, "gitleaks.toml");
  const overridesPath = join(gateSecretsDir, "secrets.toml");
  const bundledSnapshotPath = join(dirname(fileURLToPath(import.meta.url)), "../gitleaks.toml");

  let snapshotRules: CompiledSecrets | undefined;
  let userPart: { rules: CompiledSecrets["rules"]; overrides: SecretsOverride[] } = { rules: [], overrides: [] };
  let overridesMtime: number | undefined;
  let secretsSnapshotText: string | undefined;
  let secretsLastUpdate = "not run yet";
  let secretsNotice: string | undefined;
  let secretsUpdating: Promise<UpdateResult> | undefined;

  function mergedSecrets(): CompiledSecrets | undefined {
    if (!snapshotRules) return undefined;
    // The operator's rules ride ahead of the snapshot's: first hit wins.
    return { ...snapshotRules, rules: [...userPart.rules, ...snapshotRules.rules], overrides: userPart.overrides };
  }

  /** Reload the operator's secrets.toml; absent or malformed clears it. */
  async function loadUserPart(): Promise<void> {
    try {
      overridesMtime = (await stat(overridesPath)).mtimeMs;
      userPart = compileUserSecrets(await readFile(overridesPath, "utf8"));
    } catch {
      overridesMtime = undefined;
      userPart = { rules: [], overrides: [] };
    }
  }

  /** The engine for this call, hot-reloading the override file on edit
   *  or removal. */
  async function currentSecrets(): Promise<CompiledSecrets | undefined> {
    try {
      if ((await stat(overridesPath)).mtimeMs !== overridesMtime) await loadUserPart();
    } catch {
      // absent now: clear any previously-loaded overrides
      if (overridesMtime !== undefined) await loadUserPart();
    }
    return mergedSecrets();
  }

  interface UpdateResult {
    kind: "updated" | "unchanged" | "failed";
    message: string;
  }

  /** Serialized: one update at a time, from start-up or /gate:secrets update.
   *  The config param carries the start-up-time user-level read (the
   *  effective config may not be resolved yet). */
  function runUpdate(config: GatekeeperConfig = effective): Promise<UpdateResult> {
    secretsUpdating ??= doUpdate(config).finally(() => {
      secretsUpdating = undefined;
    });
    return secretsUpdating;
  }

  async function doUpdate(config: GatekeeperConfig): Promise<UpdateResult> {
    const prevActive = snapshotRules?.rules.length;
    try {
      const response = await fetchFn(config.secrets.source, { signal: AbortSignal.timeout(30_000) });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const text = await response.text();
      const candidate = compileSecrets(text); // throws on invalid TOML
      // Sanity gate: an upstream reorg cannot silently empty the detector.
      const floor = Math.max(100, (prevActive ?? candidate.rules.length) - 25);
      if (candidate.rules.length < floor) {
        throw new Error(`sanity gate: only ${candidate.rules.length} rules compile (floor ${floor})`);
      }
      if (text === secretsSnapshotText) {
        secretsLastUpdate = `unchanged (${candidate.rules.length} rules active)`;
        return { kind: "unchanged", message: secretsLastUpdate };
      }
      await mkdir(gateSecretsDir, { recursive: true });
      await writeFile(snapshotPath, text, "utf8");
      snapshotRules = candidate;
      secretsSnapshotText = text;
      await loadUserPart();
      secretsLastUpdate = `updated: ${candidate.rules.length} rules active (was ${prevActive ?? candidate.rules.length})`;
      return { kind: "updated", message: secretsLastUpdate };
    } catch (error) {
      secretsLastUpdate = `failed: ${(error as Error).message}; keeping the current rules`;
      return { kind: "failed", message: secretsLastUpdate };
    }
  }

  /** Load the engine (gate-dir snapshot, else the bundled fallback) and
   *  run the background auto-update. Kicked off at load; the outcome is
   *  reported at the first before_agent_start/tool_call — only on change
   *  or failure (ADR-0004). */
  async function initSecrets(): Promise<void> {
    let text: string | undefined;
    try {
      text = await readFile(snapshotPath, "utf8");
    } catch {
      // no local snapshot yet: fall through to the bundled fallback
    }
    if (text === undefined) {
      try {
        text = await readFile(bundledSnapshotPath, "utf8");
      } catch (error) {
        secretsNotice = `gate › secrets: unavailable (no snapshot: ${(error as Error).message})`;
        return;
      }
    }
    try {
      snapshotRules = compileSecrets(text);
      secretsSnapshotText = text;
      await loadUserPart();
    } catch (error) {
      secretsNotice = `gate › secrets: unavailable (${(error as Error).message}); detection is off`;
      return;
    }
    // Read the user-level config early so secrets.enabled/autoUpdate/source
    // are honored on the very first start. Scoped to the auto-update decision
    // only: reassigning `effective` here could clobber a concurrent
    // user+project refresh (which re-reads only on mtime change, so the
    // clobber would stick for the session).
    const early = resolveConfig(await readScoped(false, ""));
    if (early.secrets.enabled && early.secrets.autoUpdate) {
      const result = await runUpdate(early);
      if (result.kind !== "unchanged") secretsNotice = `gate › secrets: ${result.message}`;
    }
  }

  function flushSecretsNotice(ctx: AnyCtx | undefined): void {
    if (!secretsNotice) return;
    ctx?.ui.notify(secretsNotice, secretsNotice.includes("failed") || secretsNotice.includes("unavailable") ? "warning" : "info");
    secretsNotice = undefined;
  }

  async function askOperator(
    prompt: OperatorPromptInfo,
  ): Promise<"allow" | "deny" | "no-ui"> {
    const ctx = currentCtx;
    if (!ctx || !ctx.hasUI) return "no-ui";
    stats.asked++;
    // The custom bordered prompt when the mode supports it (TUI)…
    if (typeof ctx.ui.custom === "function") {
      try {
        return await ctx.ui.custom<GatePromptResult>(
          createGatePrompt({
            tool: prompt.tool,
            classification: prompt.classification,
            confidence: prompt.confidence,
            probabilities: prompt.probabilities,
            jury: prompt.jury,
            reason: prompt.reason,
            argsSummary: prompt.argsSummary,
          }),
        );
      } catch {
        // fall through to the selector dialog below
      }
    }
    // …and the plain selector everywhere else (RPC, print).
    const verdictRows = prompt.jury?.map((v) =>
      v.choice === "unavailable" ? `  ${v.name}: unavailable` : `  ${v.name}: ${v.choice} ${(v.confidence ?? 0).toFixed(2)}`,
    );
    const detail =
      (prompt.classification
        ? `Classification: ${prompt.classification} (confidence ${prompt.confidence?.toFixed(2)})`
        : "") +
      (!prompt.jury?.length && prompt.probabilities && Object.keys(prompt.probabilities).length
        ? ` — probabilities: ${Object.entries(prompt.probabilities)
          .map(([k, v]) => `${k} ${v.toFixed(2)}`)
          .join(", ")}`
        : "") +
      (prompt.classification ? "\n" : "") +
      (verdictRows?.length ? [...verdictRows, ""].join("\n") : "") +
      `Reason: ${prompt.reason}\n` +
      `Arguments: ${prompt.argsSummary}`;
    ctx.ui.notify(`gate › ${prompt.tool}\n${detail}`, "warning");
    const choice = await ctx.ui.select(`gate › ${prompt.tool}`, ["Allow", "Deny"]);
    return choice === "Allow" ? "allow" : "deny";
  }

  /** Tokenize a slash-command argument string, quotes respected: a quoted
   *  token may contain spaces (`add allow "ls ?*"` is one pattern token),
   *  and an empty pair of quotes is an empty token (`set endpoint.keepAlive ""`).
   *  Surrounding quotes are stripped, so `add allow "*"` and `add allow *`
   *  produce the same pattern. */
  function tokenize(raw: string): string[] {
    const parts: string[] = [];
    let current = "";
    let quoted = false;
    let quote: "\"" | "'" | undefined;
    for (const ch of raw) {
      if (quote) {
        if (ch === quote) quote = undefined;
        else current += ch;
        continue;
      }
      if (ch === '"' || ch === "'") {
        quote = ch;
        quoted = true;
        continue;
      }
      if (/\s/.test(ch)) {
        if (current || quoted) {
          parts.push(current);
          current = "";
          quoted = false;
        }
        continue;
      }
      current += ch;
    }
    if (current || quoted) parts.push(current);
    return parts;
  }

  /** Parse a slash-command argument string: quote-aware tokens,
   *  `--project` recognized and removed, everything else left as-is. */
  function parseCmdArgs(raw: string): { level: "user" | "project"; parts: string[] } {
    const parts = tokenize(raw);
    const level: "user" | "project" = parts.includes("--project") ? "project" : "user";
    return {
      level,
      parts: parts.filter((p) => p !== "--project"),
    };
  }

  /** Write a scoped config file, creating it if needed. Project-level writes
   *  require trust; user-level writes don't. The ctx is supplied so the gate
   *  can check it (and report blocks) where the caller's ctx isn't available. */
  async function writeScoped(
    level: "user" | "project",
    mutate: (scoped: DeepPartial<GatekeeperConfig>) => void,
    cwd: string,
    ctx: AnyCtx | undefined,
  ): Promise<void> {
    const trusted = ctx?.isProjectTrusted() ?? currentCtx?.isProjectTrusted() ?? false;
    if (level === "project" && !trusted) {
      const notify = ctx?.ui.notify ?? currentCtx?.ui.notify;
      notify?.(
        "gate › --project writes are blocked until you grant project trust for the repo",
        "warning",
      );
      return;
    }
    const scoped = await readScoped(trusted, cwd);
    const target = scoped[level] ?? {};
    mutate(target);
    scoped[level] = target;
    const path = level === "user" ? userConfigPath() : projectConfigPath(cwd);
    await mkdir(join(path, ".."), { recursive: true });
    await writeFile(path, `${JSON.stringify(scoped[level], null, 2)}\n`, "utf8");
    mtimeCache.delete(path);
    // Re-resolve with the same trust the write just used (the caller's ctx
    // when supplied, else the session's) — `currentCtx` alone may be
    // undefined, which would drop a just-written project config from
    // `effective` until the next refresh.
    effective = resolveConfig(await readScoped(trusted, cwd));
  }

  // Load the secrets engine and run the background auto-update (ADR-0004).
  // The tool_call handler awaits this promise, so no gated call races the
  // load; after startup it is settled and free. Also returned so tests can
  // await readiness.
  const initDone = initSecrets().catch(() => {
    // initSecrets reports its own failures via secretsNotice
  });

  const deps: GateDeps = {
    home,
    getConfig: () => effective,
    classify: (input, endpoint) =>
      createSystemOneClassifier(endpoint, fetchFn, {
        // Debug (notify: "debug"): the exact request body posted and the
        // answer the gate acted on, one dump per classification, prefixed
        // with the endpoint's resolved name so jury exchanges stay
        // attributable (ADR-0006).
        onExchange: (request, answer) => {
          if (effective.notify !== "debug") return;
          currentCtx?.ui.notify(
            `gate › debug [${endpoint.name}] — model request: ${JSON.stringify(request)}\ngate › debug [${endpoint.name}] — model answer: ${JSON.stringify(answer)}`,
            "info",
          );
        },
      }).classify(input),
    askOperator,
    notify: (line) => {
      currentCtx?.ui.notify(line, line.includes("blocked") ? "warning" : "info");
    },
    writeLog: (record) => {
      const cwd = currentCtx?.cwd ?? process.cwd();
      logger(cwd)
        .append(record)
        .catch(() => {
          // logging must never break the gate
        });
    },
    // Secrets detection (ADR-0004): deterministic, before every rule and
    // the model; only the operator's override file suppresses a hit.
    scanSecrets: async (tool, args): Promise<SecretsHit | undefined> => {
      if (!effective.secrets.enabled) return undefined;
      const engine = await currentSecrets();
      if (!engine) return undefined;
      const targetPath = typeof args?.path === "string" ? args.path : undefined;
      return scanSecrets(engine, argsText(tool, args), targetPath);
    },
  };

  const gate = createGate(deps);

  pi.on("before_agent_start", (event: { prompt?: string }, ctx?: ExtensionContext) => {
    currentTask = event.prompt ?? "";
    flushSecretsNotice((ctx as AnyCtx | undefined) ?? currentCtx);
  });

  pi.on("tool_call", async (event: { toolName?: unknown; input?: unknown }, ctx: ExtensionContext) => {
    const toolName = event.toolName;
    if (typeof toolName !== "string") return;
    currentCtx = ctx as AnyCtx;
    // Await the secrets load: a call in the load window blocks after the
    // engine is ready, never falls through without detection (ADR-0004).
    await initDone;
    flushSecretsNotice(currentCtx);
    await refreshConfig(currentCtx);
    const decision = await gate.decide({
      tool: toolName,
      args: (event.input as Record<string, unknown>) ?? {},
      task: currentTask,
      cwd: currentCtx.cwd,
    });
    if (decision.action === "allow") {
      stats.allowed++;
    } else {
      stats.blocked++;
      return { block: true, reason: decision.reason };
    }
  });

  pi.registerCommand("gate", {
    description: "Gatekeeper status, or `model [name]` to select the endpoint modelSelect serves",
    handler: async (args: string, ctx: AnyCtx) => {
      await refreshConfig(ctx);
      const { level, parts } = parseCmdArgs(args);

      if (parts[0] === "model") {
        let endpoints: NamedEndpoint[];
        try {
          endpoints = resolveEndpoints(effective);
        } catch (error) {
          ctx.ui.notify(`gate › ${(error as Error).message}`, "error");
          return;
        }
        const name = parts[1];
        if (!name) {
          // List the candidates and who is serving, without changing anything.
          const { endpoint } = selectEndpoint(endpoints, effective);
          ctx.ui.notify([
            "gate › endpoints:",
            ...endpoints.map((e) => `  ${e.name} @ ${e.url}`),
            `serving: ${endpoint.name}`,
          ].join("\n"), "info");
          return;
        }
        const selected = endpoints.find((e) => e.name === name);
        if (!selected) {
          ctx.ui.notify(
            `gate › no endpoint named "${name}" (endpoints: ${endpoints.map((e) => e.name).join(", ")})`,
            "warning",
          );
          return;
        }
        await writeScoped(level, (scoped) => {
          scoped.selectedEndpoint = name;
        }, ctx.cwd, ctx);
        ctx.ui.notify(`gate › selected endpoint ${name} at ${level} level`, "info");
        return;
      }

      const secretsLine = snapshotRules
        ? `${snapshotRules.rules.length}/${snapshotRules.total} gitleaks rules active (${snapshotRules.skipped} skipped) + ${userPart.rules.length} user, last update: ${secretsLastUpdate}`
        : "unavailable";
      const endpoints = (() => {
        try {
          return resolveEndpoints(effective);
        } catch (error) {
          return [{ name: "(config error)", url: (error as Error).message, model: "", timeoutMs: 0, keepAlive: "" } as never];
        }
      })();
      const lines = [
        `Gatekeeper ${effective.enabled ? "enabled" : "disabled"}`,
        `Endpoints: ${endpoints.map((e) => `${e.name} @ ${e.url}`).join(", ")}`,
        // The multi-endpoint act (ADR-0007) — only meaningful with an
        // `endpoints` array; a single-endpoint config has no mode line.
        ...(effective.endpoints?.length ? [`Mode: ${modeLine(effective, endpoints)}`] : []),
        `Threshold: ${effective.threshold} | Fail mode: ${effective.failMode}`,
        `Secrets: ${effective.secrets.enabled ? secretsLine : "off"}`,
        `Rules: ${effective.rules.length} (incl. shipped defaults) | Log: ${logDir(ctx.cwd)}`,
        `Session: ${stats.allowed} allowed, ${stats.blocked} blocked, ${stats.asked} asked`,
      ];
      ctx.ui.notify(lines.join("\n"), "info");
    },
  });

  pi.registerCommand("gate:rules", {
    description: "Manage rules: list (default), add <allow|deny> <pattern> [--tool <t>] [--project], rm <u#|p#>, test <tool> [json-args]",
    handler: async (args: string, ctx: AnyCtx) => {
      await refreshConfig(ctx);
      const { level, parts: clean } = parseCmdArgs(args);

      if (clean[0] === "add" && (clean[1] === "allow" || clean[1] === "deny") && clean[2]) {
        const pattern = clean[2];
        // A bare `*` or `**` matches every argument — a wide-open rule. Warn
        // and require explicit confirmation, but allow it if the operator
        // confirms. The default confirm returns false.
        if (pattern === "*" || pattern === "**") {
          ctx.ui.notify(
            `gate › pattern "${pattern}" matches every argument — this is a wide-open ${clean[1]} rule`,
            "warning",
          );
          const proceed = await ctx.ui.confirm?.(
            `gate › write the ${clean[1]} rule with pattern "${pattern}"?`,
            "It matches every argument.",
          );
          if (!proceed) {
            ctx.ui.notify(`gate › rule add aborted`, "info");
            return;
          }
        }
        const rule: Rule = { action: clean[1], pattern };
        const toolFlag = clean.indexOf("--tool");
        if (toolFlag !== -1 && clean[toolFlag + 1]) rule.tools = [clean[toolFlag + 1]];
        await writeScoped(level, (scoped) => {
          scoped.rules = [...(scoped.rules ?? []), rule];
        }, ctx.cwd, ctx);
        ctx.ui.notify(`gate › added ${rule.action} rule at ${level} level: ${rule.pattern}`, "info");
        return;
      }

      if (clean[0] === "rm" && clean[1]) {
        const ref = clean[1];
        const rmLevel = ref.startsWith("p") ? "project" : "user";
        const index = (Number(ref.match(/\d+$/)?.[0] ?? 0) || 0) - 1;
        const scoped = await readScoped(ctx.isProjectTrusted(), ctx.cwd);
        const removed = scoped[rmLevel]?.rules?.[index];
        if (!removed) {
          ctx.ui.notify(`gate › no rule ${ref} at ${rmLevel} level`, "warning");
          return;
        }
        const signature = JSON.stringify(removed);
        await writeScoped(rmLevel, (s) => {
          // Remove by deep equality inside the read-modify-write, so a
          // rule added between listing and removal survives.
          const rules = s.rules ?? [];
          const at = rules.findIndex((r) => JSON.stringify(r) === signature);
          s.rules = at === -1 ? rules : rules.filter((_, i) => i !== at);
        }, ctx.cwd, ctx);
        ctx.ui.notify(`gate › removed ${removed.action} rule: ${removed.pattern ?? "(tool rule)"}`, "info");
        return;
      }

      if (clean[0] === "test" && clean[1]) {
        const tool = clean[1];
        let callArgs: Record<string, unknown> = {};
        try {
          callArgs = clean[2] ? (JSON.parse(clean[2]) as Record<string, unknown>) : {};
        } catch {
          ctx.ui.notify(`gate › arguments are not valid JSON: ${clean[2]}`, "error");
          return;
        }
        const rule = matchRules(effective.rules, tool, callArgs, home, ctx.cwd);
        ctx.ui.notify(
          rule
            ? `gate › ${tool} matches the ${rule.action} rule: ${rule.pattern ?? "(tool rule)"}`
            : `gate › ${tool} matches no rule; it would go to the model gate`,
          "info",
        );
        return;
      }

      // default: list
      const scoped = await readScoped(ctx.isProjectTrusted(), ctx.cwd);
      const listing = (["project", "user"] as const).flatMap((level) =>
        (scoped[level]?.rules ?? []).map(
          (rule, i) => `${level[0]}${i + 1}. ${rule.action} ${rule.pattern ?? ""} ${rule.tools?.join(",") ?? ""}`.trim(),
        ),
      );
      const defaults = DEFAULT_CONFIG.rules.map((rule) => `${rule.action} ${rule.tools?.join(",") ?? ""}`.trim());
      ctx.ui.notify(
        [`gate › rules (project p*, user u*, then shipped defaults):`, ...listing, ...defaults.map((d) => `d. ${d}`)].join("\n") || "gate › no rules",
        "info",
      );
    },
  });

  pi.registerCommand("gate:config", {
    description: "Show config, set <key> <value> [--project], or test <tool> [json-args] — jury comparison across all endpoints",
    handler: async (args: string, ctx: AnyCtx) => {
      await refreshConfig(ctx);
      const { level, parts: clean } = parseCmdArgs(args);

      if (clean[0] === "test" && clean[1]) {
        const tool = clean[1];
        let callArgs: Record<string, unknown> = {};
        try {
          callArgs = clean[2] ? (JSON.parse(clean[2]) as Record<string, unknown>) : {};
        } catch {
          ctx.ui.notify(`gate › arguments are not valid JSON: ${clean[2]}`, "error");
          return;
        }
        // Jury comparison (ADR-0006): fan the same sample call out to every
        // endpoint in parallel and print the verdicts side by side. Pure
        // classification — no gate decision, nothing logged.
        let endpoints: NamedEndpoint[];
        try {
          endpoints = resolveEndpoints(effective);
        } catch (error) {
          ctx.ui.notify(`gate › ${(error as Error).message}`, "error");
          return;
        }
        const input: ClassifyInput = {
          tool,
          args: JSON.stringify(callArgs).slice(0, 100),
          task: currentTask,
          cwd: ctx.cwd,
          protectedPaths: [...gateDirs(home, ctx.cwd), ...protectedPatterns(effective.rules)],
          policy: effective.policy,
        };
        const rows = await Promise.all(
          endpoints.map(async (endpoint) => {
            try {
              const r = await createSystemOneClassifier(endpoint, fetchFn).classify(input);
              const probabilities = Object.entries(r.probabilities).map(([k, v]) => `${k} ${v.toFixed(2)}`).join(", ");
              return `  ${endpoint.name}: ${r.choice} ${r.confidence.toFixed(2)}${probabilities ? ` (${probabilities})` : ""}`;
            } catch (error) {
              return `  ${endpoint.name}: unavailable (${(error as Error).message})`;
            }
          }),
        );
        ctx.ui.notify([`gate › jury test for ${tool}:`, ...rows].join("\n"), "info");
        return;
      }

      if (clean[0] === "set" && clean[1] && clean[2] !== undefined) {
        const [, key, ...rest] = clean;
        const value = rest.join(" ");
        // Validate before writing: an unknown key or a bad value must not
        // land in the file — a string `rules` or a NaN threshold used to
        // brick the gate until a manual edit.
        if (key === "rules") {
          ctx.ui.notify(`gate › rules cannot be set here — use gate:rules add/rm`, "warning");
          return;
        }
        // Endpoint-jury entries (ADR-0006): set endpoints.<name>.<field>.
        // Addressed by resolved name (the entry's `name`, or its `model`
        // when unnamed); the entry must already exist — the jury is
        // configured by a manual edit of the endpoints array.
        const entryMatch = key.match(/^endpoints\.(.+)\.(url|model|apiKey|timeoutMs|keepAlive)$/);
        if (entryMatch) {
          const [, entryName, field] = entryMatch;
          const scoped = await readScoped(ctx.isProjectTrusted(), ctx.cwd);
          const entry = (scoped[level]?.endpoints ?? []).find(
            (e) => (e.name ?? (e as EndpointConfig).model) === entryName,
          );
          if (!entry) {
            const known = resolveEndpoints(effective).map((e) => e.name).join(", ");
            ctx.ui.notify(`gate › no endpoint named "${entryName}" (endpoints: ${known || "none"})`, "warning");
            return;
          }
          const validators: Record<string, (v: unknown) => string | undefined> = {
            url: isNonEmptyString,
            model: isNonEmptyString,
            apiKey: isString,
            timeoutMs: isPositiveInt,
            keepAlive: isString,
          };
          const parsed = field === "timeoutMs" ? Number(value) : value;
          const invalid = validators[field](parsed);
          if (invalid) {
            ctx.ui.notify(`gate › ${key} ${invalid}, got "${value}"`, "warning");
            return;
          }
          await writeScoped(level, (s) => {
            // find inside the read-modify-write: writeScoped re-reads the
            // scoped config, so the outer reference would be stale
            const entry = (s.endpoints ?? []).find(
              (e) => (e.name ?? (e as EndpointConfig).model) === entryName,
            );
            // writing one whitelisted field of an entry; the field name is
            // validated against the regex above
            if (entry) (entry as unknown as Record<string, unknown>)[field] = parsed;
          }, ctx.cwd, ctx);
          const echo = field === "apiKey" ? "***" : value;
          ctx.ui.notify(`gate › set ${key} = ${echo} at ${level} level`, "info");
          return;
        }
        const validator = CONFIG_KEYS[key];
        if (!validator) {
          ctx.ui.notify(`gate › unknown key "${key}" — valid keys: ${Object.keys(CONFIG_KEYS).join(", ")}`, "warning");
          return;
        }
        const parse = (): unknown => {
          if (value === "true" || value === "false") return value === "true";
          if (
            key === "threshold" || key === "stateBudgetChars" || key === "endpoint.timeoutMs" ||
            (key.startsWith("log.") && key !== "log.level")
          ) return Number(value);
          if (
            key === "policy" || key === "failMode" || key === "log.level" ||
            key === "multiEndpointMode" || key === "selectedEndpoint" ||
            key.startsWith("endpoint.")
          ) return value;
          return Number.isNaN(Number(value)) ? value : Number(value);
        };
        const parsed = parse();
        const invalid = validator(parsed);
        if (invalid) {
          ctx.ui.notify(`gate › ${key} ${invalid}, got "${value}"`, "warning");
          return;
        }
        await writeScoped(level, (scoped) => {
          if (key === "log.level") {
            scoped.log = { ...DEFAULT_CONFIG.log, ...(scoped.log ?? {}), level: value as "user" | "project" };
          } else if (key.startsWith("log.")) {
            scoped.log = { ...DEFAULT_CONFIG.log, ...(scoped.log ?? {}), [key.slice("log.".length)]: parsed as number };
          } else if (key.startsWith("endpoint.")) {
            scoped.endpoint = {
              ...DEFAULT_CONFIG.endpoint,
              ...(scoped.endpoint ?? {}),
              [key.slice("endpoint.".length)]: parsed,
            };
          } else if (key.startsWith("secrets.")) {
            scoped.secrets = {
              ...DEFAULT_CONFIG.secrets,
              ...(scoped.secrets ?? {}),
              [key.slice("secrets.".length)]: parsed,
            };
          } else if (key === "stateBudgetChars") {
            scoped.stateBudgetChars = parsed as number;
          } else {
            (scoped as Record<string, unknown>)[key] = parsed;
          }
        }, ctx.cwd, ctx);
        // Redact secrets in the echo so apiKey doesn't leak into notifications
        // (which can persist in TUI history or breadcrumbs).
        const echo = key === "endpoint.apiKey" ? "***" : value;
        ctx.ui.notify(`gate › set ${key} = ${echo} at ${level} level`, "info");
        return;
      }

      ctx.ui.notify(
        [
          `gate › effective config (defaults < user < project):`,
          `enabled: ${effective.enabled}`,
          `threshold: ${effective.threshold}`,
          ...(effective.endpoints?.length
            ? effective.endpoints.map((e, i) => `endpoint ${i + 1}: ${e.name ?? e.model} @ ${e.url} (${e.model})`)
            : [`endpoint: ${effective.endpoint.url} (${effective.endpoint.model})`]),
          `failMode: ${effective.failMode} | notify: ${effective.notify}`,
          `multiEndpointMode: ${effective.multiEndpointMode ?? "modelSelect (default)"} | selectedEndpoint: ${effective.selectedEndpoint ?? "(none — first entry)"}`,
          `secrets: ${effective.secrets.enabled ? "enabled" : "off"} | autoUpdate: ${effective.secrets.autoUpdate}`,
          `log: level=${effective.log.level} maxLines=${effective.log.maxLines} keepFiles=${effective.log.keepFiles} retentionDays=${effective.log.retentionDays}`,
          `secrets source: ${effective.secrets.source}`,
        ].join("\n"),
        "info",
      );
    },
  });

  pi.registerCommand("gate:log", {
    description: "Tail the decision log: [n] [tool filter]",
    handler: async (args: string, ctx: AnyCtx) => {
      await refreshConfig(ctx);
      const parts = args.trim().split(/\s+/).filter(Boolean);
      const n = parts[0] && /^\d+$/.test(parts[0]) ? Number(parts[0]) : 20;
      const filter = parts[0] && /^\d+$/.test(parts[0]) ? parts[1] : parts[0];
      const records = await logger(ctx.cwd).tail(n * 4);
      const selected = records.filter((r) => !filter || r.tool.includes(filter)).slice(-n);
      if (ctx.mode === "tui" && typeof ctx.ui.custom === "function" && selected.length) {
        await ctx.ui.custom<void>(
          (tui, theme, _kb, done) => new GateLogView(tui, theme, selected, done, { n, filter }),
          { overlay: true, overlayOptions: { anchor: "center", width: "90%", maxHeight: "90%" } },
        );
        return;
      }
      const lines = selected.map(
        (r) => `${r.ts} ${r.tool} → ${r.action} (${r.source}${r.classification ? ` ${r.classification} ${r.confidence?.toFixed(2)}` : ""})`,
      );
      const body = lines.length ? lines : ["(none yet)"];
      ctx.ui.notify([`gate › last ${selected.length} decisions:`, ...body].join("\n"), "info");
    },
  });

  pi.registerCommand("gate:secrets", {
    description: 'Secrets engine: status (default), update, test "<text>"',
    handler: async (args: string, ctx: AnyCtx) => {
      await initDone;
      await refreshConfig(ctx);
      const { parts } = parseCmdArgs(args);

      if (parts[0] === "update") {
        const result = await runUpdate();
        ctx.ui.notify(`gate › secrets: ${result.message}`, result.kind === "failed" ? "warning" : "info");
        return;
      }

      if (parts[0] === "test" && parts[1] !== undefined) {
        const engine = await currentSecrets();
        if (!engine) {
          ctx.ui.notify("gate › secrets: engine unavailable", "warning");
          return;
        }
        const hit = scanSecrets(engine, parts[1]);
        ctx.ui.notify(
          hit
            ? `gate › secrets: hit — ${hit.ruleId}: ${hit.masked}`
            : "gate › secrets: no rule matches the text",
          hit ? "warning" : "info",
        );
        return;
      }

      const engine = await currentSecrets();
      const snapshotLine = snapshotRules
        ? `${snapshotRules.rules.length}/${snapshotRules.total} gitleaks rules active (${snapshotRules.skipped} skipped) + ${userPart.rules.length} user rules`
        : "unavailable";
      ctx.ui.notify(
        [
          `gate › secrets: ${effective.secrets.enabled ? engine ? snapshotLine : "engine unavailable" : "off"}`,
          `source: ${effective.secrets.source} (autoUpdate: ${effective.secrets.autoUpdate ? "on" : "off"})`,
          `last update: ${secretsLastUpdate}`,
          `snapshot: ${snapshotPath} (auto-updated — do not edit; pin via secrets.source)`,
          `overrides: ${overridesPath} (yours — [[rules]] and [[allow]], never touched by the updater)`,
        ].join("\n"),
        "info",
      );
    },
  });

  return initDone;
}

export default function gatekeeper(pi: ExtensionAPI): void {
  createGatekeeper(pi);
}
