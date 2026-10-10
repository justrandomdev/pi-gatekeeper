# Multi-endpoint modes: the jury becomes one act among three

## Status

Accepted (amends ADR-0006: the jury is no longer the implicit posture for
multiple endpoints; it becomes the explicit opt-in evaluation rig it was
always meant to be).

## Context

ADR-0006 added the `endpoints` array as an evaluation rig: every endpoint
classifies in parallel and the most pessimistic verdict wins. It shipped as
the *implicit* default — any multi-endpoint config ran the jury, paying its
per-call cost (N classifications, wall time = the slowest) permanently.
The rig was never intended as the permanent posture; availability instead
of pessimism, or a single deliberately chosen judge, are the postures an
operator actually lives in.

## Decision

The config gains `multiEndpointMode`: `modelSelect` (default) | `jury` |
`fallback`. Only the `endpoints` entries are affected; the singular legacy
`endpoint` runs as one judge whatever the mode, and the mode is meaningless
without the array. Every multi-endpoint decision, prompt, and log line
carries the mode.

- **`modelSelect`** (default) — one endpoint runs: the `selectedEndpoint`
  name (`/gate model <name>`), else the first entry. The operator chooses
  the judge; nothing runs short of or beyond that choice. A selection that
  no longer resolves to a configured name is announced (`not found —
  serving "<first>" instead`) and the first entry serves — the gate never
  refuses to run over a cosmetic mismatch. Failing or timing out will not
  silently substitute another model: the operator picked this judge.
- **`jury`** — exactly ADR-0006: parallel, wait-for-all, most pessimistic
  verdict, unavailable counts as pessimistic.
- **`fallback`** — availability, not pessimism: the entries are tried in
  array order until one *answers*, and every call starts over from the
  first entry (no circuit breaker, no loops). A "failure" is a transport
  failure (error, timeout, unparseable answer) — never a verdict; any
  classification, including `unsure`, ends the chain. The surviving
  verdict decides alone under ADR-0005's single-judge matrix; only if
  *every* endpoint fails does `failMode` decide ask vs block.
- **default `modelSelect` is a deliberate break**: a multi-endpoint config
  that silently ran the jury now serves its first entry. The jury's cost
  model was never the standing posture; resuming an evaluation is one
  command: `/gate:config set multiEndpointMode jury`.
- **Invalid mode value is a config error** (fail-closed like duplicate
  endpoint names): reported in `/gate` status, the model gate refuses.
  Silently defaulting would run one judge while the operator believes
  they configured a jury.
- **Observability**: the transparency line carries a mode tag
  (`[jury]` / `[fallback]` / `[modelSelect]`); a jury names every verdict,
  a fallback names every attempt in order, modelSelect names the serving
  judge. The ask prompt shows matching rows. The log: `jury` holds every
  jury verdict or fallback attempt; a new `endpoint` field names the
  modelSelect judge. `/gate:config test` keeps fanning out to every
  endpoint regardless of mode — comparison without a real call.

## Consequences

- Per-call cost and latency return to operator-chosen levels: one
  classification by default, N in parallel only while evaluating, up to N
  sequential (sum of the failed endpoints' timeouts) only while a fallback
  chain is actually degraded.
- The operator can switch judges live (`/gate model hermes`) — model
  comparison is now two commands and one config key, not hand edits.
- `/gate model` writes `selectedEndpoint` at user level by default
  (`--project` supported), merged per key like everything else; selecting
  the first entry by name restores the default.
- The pessimism of ADR-0006 survives only in `jury` mode — a fallback
  chain's dead judges don't veto anything, because they never spoke.
