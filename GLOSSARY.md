# Gatekeeper

A pi plugin that gates every tool call through static rules and a decision model, so destructive, secret-exposing, or out-of-scope actions stop before they run.

## Language

**Gate**:
The decision layer every tool call passes through: rules first, then the model, then the operator if neither settles it.
_Avoid_: guardrail, filter

**Rule**:
A static allow or deny entry matching a tool plus path/argument patterns; first hit wins and skips the model.
_Avoid_: policy, permission

**Classification**:
The decision model's judgment of a call: `safe`, `unsafe`, or `unsure`.
_Avoid_: verdict, rating

**Jury**:
The `multiEndpointMode: "jury"` act: multiple configured endpoints classifying the same call in parallel; the most pessimistic verdict wins, and an unavailable endpoint counts as pessimistic. The model-evaluation rig (ADR-0006), opt-in since ADR-0007.
_Avoid_: ensemble, committee, panel

**modelSelect**:
The default multi-endpoint act (ADR-0007): exactly one configured endpoint — the operator's `selectedEndpoint` (set live with `/gate model <name>`), else the first entry — classifies alone. A failing selected endpoint never substitutes another judge.
_Avoid_: primary endpoint, active endpoint

**Fallback**:
The `multiEndpointMode: "fallback"` act (ADR-0007): endpoints tried in array order until one answers; only a transport failure moves on (any verdict, even `unsure`, ends the chain), the survivor decides alone, and every call starts over from the first entry. All entries failing falls to `failMode`.
_Avoid_: failover, retry chain

**Selection**:
The operator's choice of served endpoint, stored as `selectedEndpoint` by resolved name. A stale name still serves the first entry and announces the substitution — never a silent default.
_Avoid_: chosen model, active selection

**Endpoint**:
One Jev/System One-compatible service plus the model it serves; identified by a unique resolved name (defaulting to the model name) shown in the prompt and log.
_Avoid_: provider, backend

**Confidence**:
How concentrated the model's probabilities are, from 0 to 1. Not the probability the classification is correct.
_Avoid_: probability, score

**Threshold**:
The minimum confidence at which a `safe` or `unsafe` classification acts autonomously; below it, the call goes to the operator. Auto-allow additionally requires a negligible `unsafe` probability (a fixed bound, ≤ 0.1).
_Avoid_: cutoff

**Decision**:
The final action on a call: allow, block, or ask.
_Avoid_: verdict, outcome

**Operator**:
The human who approves or denies a call at the ask step.
_Avoid_: user (collides with "user level")

**Protected path**:
A path or glob whose contents must not be read, modified, or exfiltrated.
_Avoid_: blocked file, restricted file

**Secrets engine**:
The deterministic layer that scans tool-call text for credential-shaped content and blocks before rules and the model.
_Avoid_: scanner, detector, linter

**Snapshot**:
The machine-managed copy of the secrets corpus in the gate directory, replaced by the auto-update and never edited by hand.
_Avoid_: cache, vendor file

**Override**:
The operator's own entries for the secrets engine: extra rules and false-positive suppressions, never touched by the auto-update.
_Avoid_: patch, config file

**Masked match**:
How a detected secret is reported: the rule id and a size peek (`sk-…(51 chars)`), never the secret itself.
_Avoid_: redacted value, leaked token

**Chain**:
A shell command joined by separators (`&&`, `||`, `;`, `|`, `&`); rules evaluate it component by component, quotes respected.
_Avoid_: compound command, command line

**State**:
The payload sent to the model for classification: tool name, the first 100 characters of the arguments, the working directory, and the current task.
_Avoid_: prompt, context

**Policy**:
The configurable text defining what counts as unsafe, sent to the model as classification instructions.
_Avoid_: criteria, rules text

**Decision log**:
The JSONL record of every gate decision, with line-count rotation and day-based retention.
_Avoid_: audit trail, history
