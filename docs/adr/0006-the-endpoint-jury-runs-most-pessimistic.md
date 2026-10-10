# The endpoint jury: most-pessimistic aggregation

## Status

Accepted (amendment to ADR-0005's single-endpoint matrix). A deliberate,
temporary setup for evaluating candidate decision models against real
traffic; not intended as the permanent posture.

## Context

ADR-0005 made the decision model the primary classifier: one endpoint,
one judge, confident classifications act autonomously. Evaluating a new
model against that setup meant swapping endpoints one at a time and
remembering what each said about each call. Comparing models on the same
call, while working, needs several endpoints answering together.

## Decision

The config gains an `endpoints` array; the singular `endpoint` remains as
a one-member jury when the array is absent. Every endpoint classifies the
same state, in parallel; the gate waits for all of them (wall time = the
slowest, each with its own `timeoutMs`). Names default to the model name
and must be unique — they appear in the TUI, log, and notify line, and a
duplicate is a config error, never an auto-rename.

The most pessimistic verdict wins:

- any endpoint confidently `unsafe` (confidence ≥ threshold) → auto-block;
- every endpoint confidently `safe` **and** every unsafe probability ≤ 0.1
  → auto-allow;
- everything else — disagreement, any `unsure`, any below-threshold,
  any endpoint failing the probability bound — asks the operator.

An unavailable endpoint (error, timeout) counts as pessimistic: under
`failMode: ask` it forces the ask, under `failMode: block` it denies.
The gate never runs short-handed without saying so.

## Consequences

- Latency and cost scale with the jury: every gated call costs N
  classifications and waits for the slowest endpoint. Accepted because
  this is an evaluation rig, not the permanent posture.
- The accepted silent false-allow (ADR-0005) narrows: one paranoid judge
  vetoes the others. Symmetrically, ask rates rise — one hair-trigger
  judge needles the operator on every call the rest would settle.
- The operator prompt shows a verdict row per endpoint (name, choice,
  confidence, probabilities), so disagreement is visible, not buried.
- `/gate:config test` fans one sample call out to every endpoint and
  lists the verdicts side by side — comparison without a real call.
- The decision log keeps one record per decision with the per-endpoint
  verdicts attached; the log stays a sequence of decisions.
- The state each endpoint sees is unchanged (ADR-0002): same 100-char
  argument view, same task, same policy, same protected paths.
