# The gate protects its own configuration

A steered or simply mistaken model reaches the gate's config through the very tool calls the gate judges — and with the model as the primary classifier (ADR-0005), a self-serving `safe` classification can auto-allow a config edit that neuters the gate. We deny every agent tool call touching the gate's config, log, or secrets definitions, checked before every rule and overridable by none of them.

## Considered Options

- **Ship deny rules for the gate paths as defaults**: rejected — rules evaluate project-first (ADR-0001), so a project or user rule could sit ahead of the deny, and that override would itself be written through the gate. A code-level check has no such window.
- **Rely on the decision model**: rejected — the model is the primary classifier and auto-allows confident `safe` calls by design (ADR-0005); it cannot be the guard for its own gate.

## Consequences

- Self-protection precedes the `enabled` check: it holds even while the gate is disabled, so a disabled gate cannot be used as a door to re-enable the gate with weakened rules. Only a human edit can disable the gate.
- File-tool targets resolve against the working directory before comparison with the gate dirs, so a relative spelling (`.pi/gate/config.json`, or a `.pi/agent/../agent/gate` dot-detour) is caught like an absolute one. Relative spellings that cannot resolve to a gate dir still match the literal gate-dir prefixes.
- Every compared path is `realpath`'d best-effort — the gate dirs, file-tool targets, and path-shaped tokens of shell text — so a symlink chain into the gate dir (`ln -s ~/.pi/agent/gate ~/notes; cat ~/notes/config.json`) is caught. `realpath` of a not-yet-existing target (a write creating a file) falls back to the lexical path.
- The secrets definitions share the protection: the auto-updated gitleaks snapshot and the operator's override file live in the gate dir (ADR-0004), so every path that defines what the gate detects is itself undetectable-to-modify by the agent.
- The extension's own writes (the secrets snapshot auto-update) are extension code, not agent tool calls — the gate judges tool calls, not its own operator-configured housekeeping.
- Deliberate tension with ADR-0001: project-level config cannot loosen self-protection. ADR-0001 governs the operator's choices about their repos; this is an invariant of the tool itself. The distinction holds because the operator never needs an agent tool call to configure the gate — slash commands are operator-run, and a manual edit happens outside the gate entirely.
- The operator can still disable the gate by hand: editing the config to `enabled: false` is a human action, not an agent tool call. The human's hands are outside the gate by construction.
- Residual: editing the extension's source in a development repo is not covered — source edits rely on the decision model and operator review (see the README's security section).
