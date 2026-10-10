---
name: gatekeeper-config
description: Explains how the operator configures the pi gatekeeper plugin — rules, threshold, model endpoint, decision log. Use when the user asks about configuring or tuning gatekeeper, asks why a call was gated or blocked, or wants a gate setting changed.
---

# Gatekeeper configuration guidance

You can never touch gatekeeper itself: every agent tool call on its config, decision log, or secrets rules is denied before any rule. Never attempt edits, reads, or shell workarounds. Your job is to tell the operator how to configure it.

Two ways to configure, both operator-only: **slash commands** (below — the agent cannot invoke them) and **manual JSON edits**.

## Slash commands

- `/gate` — status: endpoints, multi-endpoint mode, threshold, fail mode, rule count, log path, session stats.
  - `/gate model` — list endpoints and who the decision model (`modelSelect`) is serving.
  - `/gate model <name>` — select the endpoint `modelSelect` serves; persisted, user level (`--project` ok); unknown name → warning with the candidates.
- `/gate:rules` — list (project `p*`, user `u*`, then shipped defaults) / `add` / `rm` / `test`:
  - `add allow "ls ?*"`; `add deny "~/creds"`; `--tool bash` scopes to one tool; `--project` writes project level
  - `rm u2` = user rule #2 as listed; `rm p1` = project rule
  - `test bash '{"command":"ls /tmp"}'` — which rule a sample call hits
- `/gate:config` — show effective config; `set <key> <value> [--project]` (project overrides user per key):
  - `threshold 0.9` — confidence for autonomous allow/block (auto-allow also always requires unsafe probability ≤ 0.1, a fixed bound)
  - `endpoint.model/.url/.timeoutMs` — single endpoint (full request URL; e.g. local clef-flash vs remote Jev)
  - `endpoints.<name>.url/.model/.timeoutMs` — one jury member by resolved name; the `endpoints` array itself is manual-edit only
  - `multiEndpointMode` — `modelSelect` (default) | `jury` | `fallback` (ADR-0007); invalid value is a config error, never a silent default
  - `selectedEndpoint` — endpoint `modelSelect` serves (`/gate model <name>` is the friendlier path)
  - `notify` — `always` (default) | `summary` (blocks/asks only) | `off` | `debug` (also dumps the full model request/answer per classification); decision log unaffected
  - `secrets.enabled/.autoUpdate/.source` — secrets engine
  - `log.level/.maxLines/.keepFiles/.retentionDays` — decision log
  - `test bash '{"command":"ls /tmp"}'` — fan the sample out to every endpoint, verdicts side by side
  - `endpoint.apiKey` is settable; the echo is redacted (`***`)
- `/gate:secrets` — status (rules active, source, last update), `update` (force refresh), `test "<text>"` (matching rule, masked). False positive → operator adds `[[allow]]` (rule id + optional `path`) in `~/.pi/agent/gate/secrets.toml`; never weaken the rules.
- `/gate:log [n] [tool]` — tail recent decisions, e.g. `/gate:log 50 bash`.

When the user asks why a call was gated: point them to the session's transparency line and `/gate:log` — classification, confidence, and reason (below-threshold, unsafe-probability bound, deny rule, or model failure).

## Manual configuration

- `~/.pi/agent/gate/config.json` — user level.
- `.pi/gate/config.json` — project level; read only after project trust; overrides user per key.
- `~/.pi/agent/gate/gitleaks.toml` — machine-managed snapshot, never edit; `secrets.toml` — operator's own, the updater never touches it.
- Full schema, defaults, rule semantics: `gatekeeper/README.md` ("Manual configuration", "Rules").
