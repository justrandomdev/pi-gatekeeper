# Gatekeeper Spec

## Problem Statement

Static guardrails either nag the operator on every risky-looking call — which breeds rubber-stamping, itself a security failure — or rely on fixed path patterns that miss indirect threats: a glob protecting `~/.zshrc` stops nothing from `cat`ing the rest of the folder, or from a script that loops over it. And none of it sees content: an API key pasted into a `bash` command or buried in a written file is invisible to every path glob. Meanwhile, a decision model alone is steerable by the very text it judges and can be confidently wrong. The operator needs asks to be rare and high-signal, coverage that survives indirection, and the most dangerous case — secret exfiltration — never left to a probabilistic judge or a fatigued rubber stamp.

## Solution

Gatekeeper: a pi plugin that gates every tool call through deterministic layers followed by a decision model. Self-protection, deterministic secrets detection (the gitleaks corpus), and static rules act first, instantly and for free; a Jev/System One-compatible decision model (default: local Ollama `clef-flash`) classifies everything they don't settle as `safe`, `unsafe`, or `unsure` with a confidence score — the model is the primary classifier, and confident classifications act autonomously. Everything else — `unsure`, low confidence, model failure — goes to the operator with a prompt whose only outcomes are allow and deny. Every decision is shown to the operator and logged to a rotating, expiring JSONL decision log.

## User Stories

1. As an operator, I want every tool call to pass through the gate, so that nothing runs unexamined by default.
2. As an operator, I want `ls` and `find` allowed out of the box, so that routine exploration works without prompts.
3. As an operator, I want code execution (`bash`, `powershell`) classified by the model and auto-allowed when confident, so that routine scripts run without prompts — and that the rare prompt means genuine uncertainty.
4. As an operator, I want file mutation (`edit`, `write`) classified by the model and auto-allowed when confident, so that normal editing isn't interrupted.
5. As an operator, I want confident `safe` classifications to auto-allow any tool, so that normal work isn't interrupted; the tradeoff versus forced asks (fatigue) is mine and recorded in ADR-0005.
6. As an operator, I want confident `unsafe` classifications to auto-block, so that dangerous calls stop before running even when I'm not watching.
7. As an operator, I want auto-allows to require a negligible unsafe probability, so that a concentrated-but-risky model answer cannot silently allow harm.
8. As an operator, I want `unsure` classifications and low-confidence calls to ask me, so that judgment calls are mine.
9. As an operator, I want to set the confidence threshold, so that I control how much autonomy the model gets.
10. As an operator, I want static rules evaluated before the model, so that known decisions are instant, free, and express my explicit intent.
11. As an operator, I want to add, remove, view, and test rules via slash command, so that I manage the rule set without editing JSON by hand.
12. As an operator, I want the operator prompt to offer allow and deny only — nothing persisted implicitly from a prompt — so that repeated asks mean genuine uncertainty and persistent allows are explicit, auditable rules.
13. As an operator, I want protected paths to match anywhere in a shell command's text, so that `cat`, pipelines, and inline scripts referencing them are caught.
14. As an operator, I want protected paths to match file-tool targets, so that `read`/`edit`/`write` on protected files is denied statically.
15. As an operator, I want protected paths included in the state the model sees, so that indirect access attempts are judged with that knowledge.
16. As an operator, I want secret-bearing tool calls detected deterministically before every rule and the model, so that exfiltration never depends on a probabilistic judge or a rubber stamp.
17. As an operator, I want a secret hit to block with the rule id and a masked match, so that I learn what and roughly how big, without the secret being reprinted anywhere.
18. As an operator, I want the secrets corpus sourced from gitleaks and auto-updated on start, so that detection rules stay current without my maintenance.
19. As an operator, I want the auto-update sanity-gated — a fetched corpus that fails to parse or collapses in rule count keeps the previous one — so that an upstream change cannot silently empty the detector.
20. As an operator, I want a bundled fallback snapshot, so that the first run offline still detects.
21. As an operator, I want my own secrets rules and false-positive suppressions in an override file the updater never touches, so that my tuning survives updates.
22. As an operator, I want the secrets definitions (snapshot and override file) to live where agent tool calls are always denied, so that the agent cannot edit what the gate detects.
23. As an operator, I want secrets never sent to the decision model, so that the judge never reads what it must not see (blocked before it is invoked; arguments truncated to 100 characters regardless).
24. As an operator, I want a transparency line for every gated decision including auto-allows, so that I can audit what the gate silently permitted.
25. As an operator, I want every decision logged, so that I can review what the gate did and why.
26. As an operator, I want logs rotated after a configurable number of lines, so that the decision log never grows unbounded.
27. As an operator, I want rotated logs deleted after a configurable number of days, so that retention is bounded.
28. As an operator, I want to choose whether the log lives at user or project level, so that decisions land where I need them.
29. As an operator, I want the log to record the same 100-character argument view the model saw plus the total length, so that it never copies secret contents into its own records.
30. As an operator, I want user-level config carrying safe defaults, so that every project starts protected.
31. As an operator, I want project-level config to override user-level, so that trusted projects can deliberately loosen the defaults for practical reasons.
32. As an operator, I want to configure the model endpoint — local Ollama `clef-flash` by default; remote clef, remote Jev, or any compatible service — so that I choose where classification runs.
33. As an operator, I want remote endpoints to make their egress explicit, so that sending call data off-machine is a conscious choice.
34. As an operator, I want model failure or timeout to route to me (or fail-block in headless mode), so that the gate never silently opens.
35. As an operator, I want the operator prompt to show classification, confidence, the model's probability distribution, tool, argument summary, and the model's reason, so that I can decide quickly and correctly.
36. As an operator, I want to edit the policy text, so that "what counts as unsafe" fits my environment.
37. As an operator, I want status and session statistics via slash command, so that I can see the gate's posture and activity at a glance.
38. As an operator, I want secrets status, forced update, and a detection test via slash command, so that I can audit and refresh the secrets engine in-band.
39. As an operator, I want to tail and filter the decision log via slash command, so that incident review stays in-band.
40. As an operator, I want the state the model sees to contain only the tool name, the first 100 characters of the arguments, the working directory, and my current message, so that the judge cannot be steered by what it judges — while "outside the project" judgments stay decidable.
41. As an operator, I want config changes hot-reloaded, so that tuning the gate doesn't require restarting pi.
42. As an operator, I want to configure multiple endpoints with unique names and have them all classify each call in parallel while I work, so that I can compare candidate models on real calls.
43. As an operator, I want the jury to decide most-pessimistically — one confident `unsafe` blocks, auto-allow needs unanimity — so that a paranoid judge vetoes the others and I never silently accept the loosest one.
44. As an operator, I want the operator prompt to show a verdict row per endpoint, so that disagreement is visible, not buried.
45. As an operator, I want a slash command that fans one sample call out to every endpoint and lists the verdicts side by side, so that model comparison doesn't need a real gated call.

## Implementation Decisions

- Pipeline: self-protection → secrets detection → rules → model → operator. Self-protection acts before the `enabled` check (ADR-0003); secrets detection follows `enabled` — a disabled gate is ungated, one switch, no hidden always-on layers.
- The model is the primary classifier (ADR-0005): ask floors, the session cache, and grants are removed, with their config keys. Rules are a first-match fast-path (allow/deny, tool plus path/argument patterns, first hit wins, skipping the model), not a guard on the model.
- Self-protection (ADR-0003): agent tool calls touching the gate's own config, decision log, or secrets definitions are always denied, before the enabled check and every rule, overridable by none. File-tool targets resolve against the cwd and are `realpath`'d best-effort, as are the gate dirs and path-shaped tokens of shell text (symlink chains into the gate dir are caught); shell text is matched with `$HOME` expansion, dot-segment normalization, and `cd`-target resolution. Encoded spellings fall through to the model gate, which also sees the gate dirs as protected paths.
- Secrets detection (ADR-0004): the gitleaks corpus compiled to JS regexes (inline `(?i)` → global `i`, `(?P<` → `(?<`, uncompilable rules skipped and counted), keyword prefilters, Shannon entropy and `secretGroup` implemented, upstream and per-rule allowlists and stopwords honored. The scan covers the full shell command and full serialized arguments (write/edit content included), capped at 256KB per call. A hit blocks before every rule; the only override is the operator's `secrets.toml` (`[[rules]]` in gitleaks shape, `[[allow]]` by id + optional match/path). The snapshot (`gitleaks.toml`) and the override file live in the gate dir — agent tool calls touching them are always denied (ADR-0003).
- Secrets auto-update: fetches `secrets.source` (default: gitleaks master) in the background on start, only when `secrets.enabled` and `secrets.autoUpdate` are true; sanity gates (parses, and compiles within 25 rules — floor 100 — of the active count, else the previous snapshot is kept); reports only on change or failure; a bundled snapshot ships in the package as the offline fallback. The updater writes the snapshot only — never the override file.
- Decision matrix: `safe` at or above the threshold auto-allows only when the model's `unsafe` probability sits at or below a fixed 0.1 bound (a constant, not a knob, same as the 100-char model view; a missing `probabilities` counts as unmet — fail-closed to ask); `unsafe` at or above auto-blocks; explicit `unsure`, anything below the threshold, and a `safe` failing the bound converge on ask. The threshold defaults to 0.65 and is configurable. Choice order lists `safe` first so ties fail toward asking. With multiple `endpoints` configured (ADR-0006), the same matrix applies per endpoint and the most pessimistic verdict wins: any confident `unsafe` auto-blocks, auto-allow needs unanimity (every endpoint confident `safe` within the bound), and an unavailable endpoint counts as pessimistic — `failMode` decides ask vs block. The singular `endpoint` runs as a one-member jury when the array is absent; resolved names default to the model name and must be unique.
- Default posture: the shipped allow rules cover `ls` and `find` only; everything else rides on the model, the secrets engine, and self-protection.
- Protected-path matching is target-anchored for file tools (a glob-free deny also covers everything beneath the pattern); shell chains split into components (quotes respected): an allow rule must match every component (command substitution defeats an allow, falling to the model gate); a deny rule matches if any component matches; a glob-free allow matches exactly, not as a prefix. The protected-path list rides in the state sent to the model.
- State invariant (ADR-0002/0005): the state contains the tool name, the first 100 characters of the serialized arguments (a fixed constant, not a knob), the capped task text, and the working directory (path metadata, so out-of-scope judgments are decidable). Full file contents, fetched text, and conversation history are never included; the operator prompt keeps a capped (2KB) preview.
- Policy: default policy text covering destructive operations, secret exposure, exfiltration, and out-of-scope writes; configurable, with protected paths (deny-rule patterns plus the gate dirs) injected into state automatically.
- Endpoint: a single active endpoint (URL, model, optional API key, timeout defaulting to 30s — cold-start load of a large local model takes tens of seconds, warm calls are sub-second). Any Jev/System One-compatible service works; default is local Ollama `clef-flash` with `keep_alive` so the model stays warm. Failure or timeout routes to ask; a fail-block mode exists for headless use.
- Operator outcomes: allow / deny / no-UI; no implicit persistence. Model failure routes to the operator (or fail-block) with a model-unavailable reason.
- Transparency: one notify line per gated decision, including auto-allows. The notify knob has a `debug` level that additionally dumps the exact classifier request body and the answer it acted on, per classification.
- Decision log: JSONL, one active log at the level the effective config selects (default user-level); rotation after a configurable line count (default 10,000, keeping 10 files); deletion of rotated files after a configurable age (default 30 days); arguments recorded as the 100-character view the model saw plus the total length (a secrets block logs a constant in its place — the argument view never carries a detected secret) — file contents and full arguments never logged.
- Config: one config file per level; project overrides user per key (scalars) and in rule order (project rules evaluate before user rules, first hit wins). `secrets.{enabled,autoUpdate,source}` are the secrets knobs; the scan cap and the 100-char model view are constants, not config.
- Slash commands: `/gate` (status and session stats), `/gate:rules` (view/add/remove/test), `/gate:config` (threshold, model, retention, secrets, levels), `/gate:secrets` (status/update/test), `/gate:log` (tail/filter). All keys validated against a whitelist before writing.
- A `gatekeeper-config` skill ships with the package: it tells the agent it cannot configure the gate, and carries the slash-command reference and manual-config paths so the agent can explain configuration to the user.
- Scope: replaces pi-guardrails entirely except its herdr integration.

See the [ADR index](adr/) — 0001 (project overrides user), 0002 (a decision model in the gate path), 0003 (the gate protects itself), 0004 (deterministic secret detection), 0005 (the model is the primary classifier), 0006 (the endpoint jury runs most-pessimistic) — for the decisions that earned separate records.

## Testing Decisions

- Test external behavior only: what the gate decides for a call, not how it decides it.
- Primary seam (confirmed with the operator): the extension boundary — the tool-call handler exercised against a stubbed System One endpoint, asserting decisions (allow/block/ask), rule precedence, secrets hits (blocked, masked, never reprinted), state contents (100-char view), prompt payloads, and log records. Log rotation and retention assert against an injectable clock and line counts. Secrets compilation asserts against the bundled gitleaks snapshot (subset bounds, not exact counts — the corpus evolves upstream).
- One end-to-end smoke test loads the plugin via pi's single-run extension flag and exercises a gated call through the real runtime.
- Prior art: pi-guardrails ships extension tests alongside its source.

## Out of Scope

- Herdr integration (the one pi-guardrails piece not carried over).
- Onboarding wizard; the defaults are ready to run and tuned via `/gate`.
- Primary-plus-fallback endpoint arrangements; a single active endpoint, with failure routing to ask.
- Model fine-tuning or custom classification training.
- Gitleaks parity: a JS-regex subset of the corpus (uncompilable rules skipped, counts reported), not a RE2 engine.
- Gating human-issued slash commands or pi's own extension loading (pi's project-trust mechanism governs those).

## Further Notes

- Measure classification latency on the operator's actual hardware before release; the gate sits on the critical path of every tool call (a hosted clef-flash classifies in ~40ms).
- ADR-0002 names the accepted vulnerabilities: judge-steering (contained by the 100-char truncation and deterministic secrets blocking), silent false-allow (accepted versus operator fatigue, per ADR-0005, contained by the deterministic layers and the threshold), remote-endpoint egress, and the model-down ask storm.
- Residual: the decision log records the 100-character argument view — a short secret the corpus misses, inside the first 100 characters of a command, lands in it (detected secrets log a constant). Keep the log directory private.
- Residual: secrets past the 256KB per-call scan cap, and corpus obfuscations (base64-wrapped payloads), fall through to the model gate.
- Residual: two concurrent pi sessions share one user-level decision log and secrets snapshot; rotation and auto-update can race (fail-closed direction, at worst a lost log line, a late rotation — the memoized logger's line count is not refreshed by another session's appends — or a kept-older snapshot).
- The spec's end-to-end smoke test (`pi -e`) has been exercised manually; automating it remains open.
