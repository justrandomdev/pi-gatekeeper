/**
 * The gate: self-protection, deterministic secrets detection, rules, then
 * the model gate (the primary classifier, ADR-0005), then the operator.
 * See docs/spec.md.
 */

import type { ClassifyInput, Classification, ClassificationResult, ClassifierEndpoint } from "./classifier.js";
import { resolveEndpoints, resolveMode, selectEndpoint, type GatekeeperConfig, type MultiEndpointMode, type NamedEndpoint } from "./config.js";
import { gateDirs, matchRules, protectedPatterns, touchesGatePaths, type Rule } from "./rules.js";
import type { SecretsHit } from "./secrets.js";

export type DecisionSource = "disabled" | "protected" | "secrets" | "rule" | "model" | "operator" | "fail";

export interface Decision {
  action: "allow" | "block";
  source: DecisionSource;
  reason?: string;
  classification?: Classification;
  confidence?: number;
  probabilities?: Record<string, number>;
  /** Per-endpoint verdicts when the gate ran a jury (ADR-0006) or a
   *  fallback chain (the attempts that ran, in order — ADR-0007); absent
   *  for non-model sources. */
  jury?: JuryVerdict[];
  /** The serving judge's resolved name when modelSelect ran (ADR-0007). */
  endpoint?: string;
}

export interface LogRecord {
  tool: string;
  args: string;
  action: "allow" | "block";
  source: DecisionSource;
  classification?: Classification;
  confidence?: number;
  probabilities?: Record<string, number>;
  /** Per-endpoint verdicts when the gate ran a jury (ADR-0006) or a
   *  fallback chain's attempts (ADR-0007). */
  jury?: JuryVerdict[];
  /** The serving judge's resolved name when modelSelect ran (ADR-0007). */
  endpoint?: string;
  reason?: string;
}

export interface OperatorPromptInfo {
  tool: string;
  argsSummary: string;
  classification?: Classification;
  confidence?: number;
  probabilities?: Record<string, number>;
  /** Per-endpoint verdicts to display when a multi-endpoint act ran
   *  (ADR-0006): one row per jury endpoint, per fallback attempt, or the
   *  single modelSelect judge. */
  jury?: JuryVerdict[];
  /** Why this call reached the operator. */
  reason: string;
}

/** One endpoint's outcome in a jury run (ADR-0006): a classification, or
 *  `unavailable` — which counts as pessimistic. The gate waits for every
 *  endpoint before deciding. */
export interface JuryVerdict {
  name: string;
  choice: Classification | "unavailable";
  confidence?: number;
  probabilities?: Record<string, number>;
  /** Why the endpoint was unavailable (its error message). */
  error?: string;
}

export interface DecideInput {
  tool: string;
  args: Record<string, unknown>;
  task: string;
  /** Working directory, for project-level gate paths. */
  cwd?: string;
}

export interface GateDeps {
  home: string;
  getConfig(): GatekeeperConfig;
  /** Classify against one endpoint; the gate fans out over the resolved
   *  endpoints itself, per the multi-endpoint act (ADR-0006/0007). */
  classify(input: ClassifyInput, endpoint: NamedEndpoint): Promise<ClassificationResult>;
  askOperator(prompt: OperatorPromptInfo): Promise<"allow" | "deny" | "no-ui">;
  notify(line: string): void;
  writeLog(record: LogRecord): void;
  scanSecrets(tool: string, args: Record<string, unknown>): Promise<SecretsHit | undefined>;
}

export interface Gate {
  decide(input: DecideInput): Promise<Decision>;
}

/** The model never sees more than this many argument characters
 *  (ADR-0002/0005). A fixed constant, not a knob — knobs invite tuning a
 *  safety property. */
const MODEL_ARGS_CHARS = 100;

/** Auto-allow requires a negligible probability of harm: the model's
 *  `unsafe` probability must sit at or below this bound. A fixed constant,
 *  not a knob — same reasoning as MODEL_ARGS_CHARS. An answer without
 *  probabilities counts as unmet (fail-closed: the call asks). */
const MAX_UNSAFE_PROBABILITY = 0.15;

function cap(text: string, budget: number): string {
  return text.length <= budget ? text : `${text.slice(0, budget)}…`;
}

/** Is this verdict a confident auto-block? One knob for the whole jury. */
function confidentUnsafe(v: JuryVerdict, threshold: number): boolean {
  return v.choice === "unsafe" && (v.confidence ?? 0) >= threshold;
}

/** Is this verdict confident enough to auto-allow (ADR-0005/0006)? A
 *  negligible unsafe probability is required; missing probabilities
 *  count as unmet. */
function confidentSafe(v: JuryVerdict, threshold: number): boolean {
  return v.choice === "safe" && (v.confidence ?? 0) >= threshold && (v.probabilities?.unsafe ?? 1) <= MAX_UNSAFE_PROBABILITY;
}

/** Why a verdict cannot auto-allow, as a human-readable clause. With a
 *  jury the clause names the endpoint; legacy single-endpoint messages
 *  stay exactly as they were. */
function verdictObjection(v: JuryVerdict, threshold: number, withName: boolean): string {
  const who = withName ? `${v.name}: ` : "";
  if (v.choice === "unavailable") return `${who}unavailable (${v.error ?? "no answer"})`;
  if (v.choice === "unsure") return `${who}unsure (${(v.confidence ?? 0).toFixed(2)})`;
  if ((v.confidence ?? 0) < threshold) return `${who}confidence ${(v.confidence ?? 0).toFixed(2)} below threshold ${threshold}`;
  return `${who}unsafe probability ${(v.probabilities?.unsafe ?? 1).toFixed(2)} above the auto-allow bound ${MAX_UNSAFE_PROBABILITY}`;
}

export function createGate(deps: GateDeps): Gate {
  return {
    async decide({ tool, args, task, cwd }: DecideInput): Promise<Decision> {
      const config = deps.getConfig();
      // The multi-endpoint act is meaningful only with an `endpoints` array
      // (ADR-0007); the singular `endpoint` is one judge regardless of mode.
      const multi = (config.endpoints?.length ?? 0) > 0;
      let mode: MultiEndpointMode | undefined;

      const raw = JSON.stringify(args ?? {});
      // The operator prompt keeps a capped preview — the operator is human.
      // The model and the log see only the first 100 characters.
      const argsSummary = cap(raw, config.log.truncateArgsBytes);
      const modelArgs = raw.slice(0, MODEL_ARGS_CHARS);
      const logArgs = raw.length > MODEL_ARGS_CHARS ? `${modelArgs}… (${raw.length} chars)` : modelArgs;

      const finish = (decision: Decision): Decision => {
        const label =
          decision.classification !== undefined
            ? `${decision.classification}${decision.confidence !== undefined ? ` (${decision.confidence.toFixed(2)})` : ""}`
            : decision.source;
        // The notify knob: `off` skips every notification; `summary` keeps
        // blocks/asks and skips allows; `always` notifies every decision
        // (`debug` behaves like `always` here — the request/answer dump is
        // wired at the classifier).
        const skipNotify =
          config.notify === "off" || (config.notify === "summary" && decision.action === "allow");
        if (!skipNotify) {
          // A jury run names every verdict in the transparency line — the
          // operator sees the disagreement, not just the outcome. Every
          // multi-endpoint act is tagged with its mode (ADR-0007).
          const juryLine = decision.jury?.length && mode === "jury"
            ? ` (jury: ${decision.jury
              .map((v) => `${v.name} ${v.choice === "unavailable" ? "unavailable" : `${v.choice} ${(v.confidence ?? 0).toFixed(2)}`}`)
              .join(", ")})`
            : "";
          // A fallback chain names its attempts in order at the end of the
          // line — a sequence, not a simultaneous panel.
          const fallbackLine = decision.jury?.length && mode === "fallback"
            ? ` (fallback: ${decision.jury
              .map((v) => `${v.name} ${v.choice === "unavailable" ? `unavailable (${v.error ?? "no answer"})` : `${v.choice} ${(v.confidence ?? 0).toFixed(2)}`}`)
              .join(", ")})`
            : "";
          const tag = decision.jury?.length || decision.endpoint
            ? mode === "jury" && decision.jury?.length
              ? "[jury] "
              : mode === "fallback" && decision.jury?.length
                ? "[fallback] "
                : mode === "modelSelect" && decision.endpoint
                  ? "[modelSelect] "
                  : ""
            : "";
          const servingName = tag === "[modelSelect] " ? ` ${decision.endpoint}` : "";
          deps.notify(
            `gate › ${tag}${tool}: ${label}${juryLine}${servingName} → ${decision.action === "allow" ? "allowed" : "blocked"} (${decision.source})${fallbackLine}`,
          );
        }
        // A secrets hit can put the matched text inside the first 100
        // characters of the serialized args — exactly the view logArgs
        // captures — so logging it verbatim would copy the secret into
        // the decision log. The masked peek already rides in `reason`;
        // the args column becomes a constant for secrets decisions.
        // Other sources never carry their trigger inside the args view.
        const loggedArgs = decision.source === "secrets" ? "<blocked: secrets>" : logArgs;
        deps.writeLog({
          tool,
          args: loggedArgs,
          action: decision.action,
          source: decision.source,
          classification: decision.classification,
          confidence: decision.confidence,
          probabilities: decision.probabilities,
          jury: decision.jury,
          endpoint: decision.endpoint,
          reason: decision.reason,
        });
        return decision;
      };

      // Self-protection (ADR-0003): before the enabled check and every
      // layer, overridable by none — it holds even while the gate is
      // disabled, so a disabled gate cannot be used as a door.
      if (await touchesGatePaths(tool, args, deps.home, cwd)) {
        return finish({
          action: "block",
          source: "protected",
          reason:
            "the gate protects its own configuration, log, and secrets definitions; agent tool calls touching them are always denied. The operator configures the gate with /gate commands or a manual edit.",
        });
      }

      if (!config.enabled) {
        return finish({
          action: "allow",
          source: "disabled",
          reason: "gate is disabled; pass-through without detection, classification, or operator review",
        });
      }

      // Secrets detection (ADR-0004): deterministic, before every rule and
      // the model. A hit blocks; only the operator's override file
      // (secrets.toml) suppresses it — no rule, no model, no prompt.
      const hit = await deps.scanSecrets(tool, args);
      if (hit) {
        return finish({
          action: "block",
          source: "secrets",
          reason: `possible secret (${hit.ruleId}): ${hit.masked}; blocked before every rule and the model. False positive? Suppress it in ~/.pi/agent/gate/secrets.toml ([[allow]]) — see /gate:secrets.`,
        });
      }

      // Rules: a first-match fast-path for the obvious and the operator's
      // explicit intent (ADR-0005).
      const rule = matchRules(config.rules, tool, args, deps.home, cwd);
      if (rule) {
        return finish({
          action: rule.action === "allow" ? "allow" : "block",
          source: "rule",
          reason: rule.reason ?? (rule.pattern ? `matched ${rule.action} rule: ${rule.pattern}` : `${rule.action} rule for ${rule.tools?.join(", ") ?? "any tool"}`),
        });
      }

      // The model gate: the primary classifier (ADR-0005). With an
      // `endpoints` array the multi-endpoint act applies (ADR-0007):
      // `jury` — every endpoint classifies in parallel, the gate waits for
      // all of them, and the most pessimistic verdict wins (ADR-0006);
      // `fallback` — the entries are tried in array order until one
      // answers, then start over every call; `modelSelect` — the
      // operator's selected endpoint alone. Without the array the singular
      // `endpoint` runs as one judge, whatever the mode.
      let verdicts: JuryVerdict[];
      let configError: string | undefined;
      let staleWarning: string | undefined;
      let servingName: string | undefined; // modelSelect's judge, for the log
      try {
        mode = resolveMode(config);
        const input: ClassifyInput = {
          tool,
          args: modelArgs,
          task: cap(task, config.stateBudgetChars),
          // The working directory rides along so "writes outside the project"
          // in the policy is decidable; the gate's own dirs ride along as a
          // backstop for obfuscated spellings that slip past the layers above.
          cwd,
          protectedPaths: [...gateDirs(deps.home, cwd), ...protectedPatterns(config.rules)],
          policy: config.policy,
        };
        const runOne = async (endpoint: NamedEndpoint): Promise<JuryVerdict> => {
          try {
            const r = await deps.classify(input, endpoint);
            return { name: endpoint.name, choice: r.choice, confidence: r.confidence, probabilities: r.probabilities };
          } catch (error) {
            return { name: endpoint.name, choice: "unavailable", error: (error as Error).message };
          }
        };
        const endpoints = resolveEndpoints(config);
        if (multi && mode === "fallback") {
          // Availability, not pessimism: stop at the first endpoint that
          // answers. Transport failures here are never verdicts.
          verdicts = [];
          for (const endpoint of endpoints) {
            const verdict = await runOne(endpoint);
            verdicts.push(verdict);
            if (verdict.choice !== "unavailable") break;
          }
        } else if (multi && mode === "modelSelect") {
          const { endpoint, warning } = selectEndpoint(endpoints, config);
          staleWarning = warning;
          servingName = endpoint.name;
          verdicts = [await runOne(endpoint)];
        } else {
          verdicts = await Promise.all(endpoints.map((endpoint) => runOne(endpoint)));
        }
        if (staleWarning) deps.notify(staleWarning);
      } catch (error) {
        // Endpoint resolution itself failed (e.g. duplicate names, an
        // unknown mode): fail-closed.
        verdicts = [];
        configError = `gate config error: ${(error as Error).message}`;
      }

      // A config error means the posture is unreadable: refuse outright —
      // fail-closed, never operator-discretionary (ADR-0006/0007).
      if (configError) {
        return finish({ action: "block", source: "fail", reason: configError });
      }

      const isJury = multi && mode === "jury" && verdicts.length > 1;
      // Non-jury acts decide on the serving verdict only (ADR-0005's matrix
      // applied to one judge): failed fallback attempts never produced a
      // verdict, and modelSelect has exactly one.
      const serving = isJury ? verdicts : verdicts.filter((v) => v.choice !== "unavailable");
      const unavailable = verdicts.filter((v) => v.choice === "unavailable");
      // The model gate has nothing to decide on: every judge a jury needs
      // is in, or a fallback chain/modelSelect produced no verdict at all.
      const noVerdict = isJury ? unavailable.length > 0 : serving.length === 0 && unavailable.length > 0;
      // Log/prompt attachment per act (ADR-0007): the jury lists every
      // verdict, a fallback chain its attempts, modelSelect just the name.
      const recordVerdicts = isJury || (multi && mode === "fallback");
      const isModelSelect = multi && mode === "modelSelect";

      // Most pessimistic first: any confident unsafe auto-blocks, whoever
      // said it.
      const blocking = serving.find((v) => confidentUnsafe(v, config.threshold));
      if (blocking) {
        return finish({
          action: "block",
          source: "model",
          reason: isJury
            ? `${blocking.name} classified unsafe (${blocking.confidence!.toFixed(2)})`
            : `classified unsafe (${blocking.confidence!.toFixed(2)})`,
          classification: "unsafe",
          confidence: blocking.confidence,
          probabilities: blocking.probabilities,
          jury: recordVerdicts ? verdicts : undefined,
          endpoint: isModelSelect ? servingName : undefined,
        });
      }

      // An answer is unavailable, or every judge failed: with failMode
      // block it denies outright; with failMode ask it always asks.
      if (noVerdict && config.failMode === "block") {
        return finish({
          action: "block",
          source: "fail",
          reason: isJury
            ? unavailable.map((v) => verdictObjection(v, config.threshold, true)).join("; ")
            : `model unavailable: ${unavailable[0]?.error ?? "no answer"}`,
          jury: recordVerdicts ? verdicts : undefined,
          endpoint: isModelSelect ? servingName : undefined,
        });
      }

      // Auto-allow only on unanimity: every endpoint confident safe with a
      // negligible unsafe probability (ADR-0005/0006).
      const unanimousSafe = serving.length > 0 && serving.every((v) => confidentSafe(v, config.threshold));
      if (unanimousSafe) {
        const weakest = Math.min(...serving.map((v) => v.confidence ?? 0));
        return finish({
          action: "allow",
          source: "model",
          reason: isJury
            ? `jury classified safe (weakest confidence ${weakest.toFixed(2)})`
            : `classified safe (${serving[0].confidence!.toFixed(2)})`,
          classification: "safe",
          confidence: weakest,
          probabilities: serving[0].probabilities,
          jury: recordVerdicts ? verdicts : undefined,
          endpoint: isModelSelect ? servingName : undefined,
        });
      }

      // Everything the model cannot settle goes to the operator: allow or
      // deny, nothing persisted (ADR-0005). Legacy single-endpoint reasons
      // unchanged; a jury names every objection.
      const reason = configError
        ?? (isJury
          ? verdicts
            .filter((v) => !confidentSafe(v, config.threshold))
            .map((v) => verdictObjection(v, config.threshold, true))
            .join("; ")
          : serving.length
            ? serving[0].choice === "unsure"
              ? `model unsure (${serving[0].confidence!.toFixed(2)})`
              : (serving[0].confidence ?? 0) < config.threshold
                ? `confidence ${(serving[0].confidence ?? 0).toFixed(2)} below threshold ${config.threshold}`
                : `unsafe probability ${(serving[0].probabilities?.unsafe ?? 1).toFixed(2)} above the auto-allow bound ${MAX_UNSAFE_PROBABILITY}`
            : `model unavailable: ${unavailable[0]?.error ?? "no answer"}`);

      const aggregate = (): { classification?: Classification; confidence?: number; probabilities?: Record<string, number> } => {
        // The most pessimistic classification among the endpoints that
        // answered: unsafe > unsure > safe.
        for (const choice of ["unsafe", "unsure", "safe"] as const) {
          const v = serving.find((x) => x.choice === choice);
          if (v) return { classification: choice, confidence: v.confidence, probabilities: v.probabilities };
        }
        return {};
      };
      const shown = aggregate();

      const outcome = await deps.askOperator({
        tool,
        argsSummary,
        classification: shown.classification,
        confidence: shown.confidence,
        probabilities: shown.probabilities,
        jury: recordVerdicts || isModelSelect ? verdicts : undefined,
        reason,
      });

      const cause: DecisionSource = configError || noVerdict ? "fail" : "operator";
      if (outcome === "no-ui") {
        return finish({ action: "block", source: cause, reason: `${reason}; no UI available to confirm`, jury: recordVerdicts || isModelSelect ? verdicts : undefined, endpoint: isModelSelect ? servingName : undefined });
      }
      if (outcome === "deny") {
        return finish({ action: "block", source: cause, reason: `${reason}; operator denied`, jury: recordVerdicts || isModelSelect ? verdicts : undefined, endpoint: isModelSelect ? servingName : undefined });
      }
      return finish({ action: "allow", source: cause, reason: `${reason}; operator allowed`, jury: recordVerdicts || isModelSelect ? verdicts : undefined, endpoint: isModelSelect ? servingName : undefined });
    },
  };
}
