# Deterministic secret detection, before everything

Secret exfiltration is the highest-stakes failure: a leaked credential cannot be undone, and the leak vector is content-shaped — an API key pasted into a `bash` command, a token at byte 90,000 of a written file, a header inside a `curl`. The first design had only static rules (path globs) and the decision model for this; rules cannot see content, and the model is steerable by the very text it judges, plus it routes catches to a tired operator. Exfiltration must not depend on a probabilistic judge or a rubber-stamping hand: we put a deterministic secrets engine ahead of every rule and the model, it blocks on hit, and nothing overrides it except the operator's own override file.

## Considered Options

- **Let the decision model catch secrets**: rejected — the judge can be steered by what it judges (ADR-0002), and a confident-but-wrong `safe` silently auto-allows the leak. The most dangerous case gets the least trustworthy layer.
- **Hand-curated prefix list** (`sk-`, `ghp_`, `AKIA`, …): rejected — a second corpus to maintain by hand, forever behind, and each prefix is a rule upstream already maintains better.
- **The gitleaks corpus** (`gitleaks.toml`, upstream-maintained, ~220 rules with keyword prefilters, entropy thresholds, and allowlists): chosen. One source of truth, maintained by people whose job is secret detection.

## Consequences

- The engine compiles gitleaks rules to JS regexes: inline `(?i)` flags become the global `i` flag (slightly broader matching — the fail-closed direction), `(?P<name>` becomes `(?<name>`, and rules that still fail to compile are skipped and counted. A subset (~211 of 222), not parity; the active count is reported in `/gate:secrets`.
- Shannon entropy and `secretGroup` are implemented, not dropped: 130 of 222 rules are calibrated as regex + entropy, and running them without the entropy check would block on every `api_key = "value"` line.
- The scan covers the full `bash`/`powershell` command, the full serialized arguments of other tools (write/edit content included), capped at 256KB per call — a ReDoS bound, not a tuning knob.
- A hit blocks before every rule: not even an operator allow rule bypasses detection. The only override is `[[allow]]` in the operator's `secrets.toml` — one auditable file, never touched by the updater.
- The operator's custom rules and `[[allow]]` entries live in `~/.pi/agent/gate/secrets.toml`; the auto-updated upstream snapshot lives in `~/.pi/agent/gate/gitleaks.toml`. Two files, because one file means the updater clobbers hand edits. Both sit in the gate directory, which ADR-0003 self-protection already denies to every agent tool call — the secrets definitions are protected by the same invariant they enforce.
- Auto-update fetches the source URL on start, in the background, and reports only on change or failure. Sanity gates: the fetched file must parse and compile within 25 rules (floor 100) of the active count, or the previous snapshot is kept and the failure is reported. `secrets.source` (pin a tag by changing the URL) and `secrets.autoUpdate: false` are the operator's controls.
- Network on start is a recorded exception to the local-first posture: the fetch is operator-configured, failure keeps the last snapshot, and a bundled fallback snapshot ships in the package so the first run offline still detects.
- Notifications and the decision log never reprint a matched secret: hits are masked (`sk-…(51 chars)`). The engine reports the rule id and the mask, nothing more.
- Residual: secrets past the 256KB cap in a single call, regex-incompatible rules (11 of 222), and obfuscation the corpus doesn't cover (base64-wrapped payloads) fall to the decision model — the designed fallback for everything the deterministic layers miss.
- Residual: agents legitimately write fake secrets (test fixtures, documentation examples) and will be blocked; that is fail-closed by design, and the escape is a `[[allow]]` path override, not a weakened rule.
