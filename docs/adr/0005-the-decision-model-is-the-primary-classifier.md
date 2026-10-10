# The decision model is the primary classifier

The original concept was: the model classifies every tool call, confident classifications act, and the operator sees the low-confidence ones. An earlier design inverted this — rules first as a guard against model error, ask floors on `bash`/`edit`/`write`, a session cache, and grants persisted from prompts — on the theory that a misclassification is worse than an ask. That theory fails on its own terms: operator fatigue is the likelier and more dangerous failure, it compounds silently (rubber-stamping), and it hits on exactly the most common tools. The model is cheap and reliable at this job (a hosted clef-flash classifies in ~40ms). We return to the original concept: the model is the primary classifier; rules are a fast-path short-circuit, not a guard; asks are reserved for low confidence and model failure.

## Considered Options

- **Rules-primary with ask floors**: rejected — it puts the operator in the loop for every floored tool call, trains rubber-stamping, and pays model latency anyway on everything rules don't settle.
- **Model-primary, operator for low confidence**: chosen — deterministic layers (self-protection, ADR-0003; secrets detection, ADR-0004; rules) act first and cheaply, the model classifies the rest, and the operator sees only what the model can't settle.

## Consequences

- Ask floors are removed, with the `floors` config key. The model can auto-allow `bash`, `write`, and `edit` when confident; if that is wrong for a tool, the answer is a rule, not a meta-mechanism.
- The session cache is removed, with the `cache` config key: cached security decisions are an anti-pattern (decisions depend on context that shifts), and at ~40ms per classification, retries can simply re-classify.
- Grants are removed: no `allow-always` persistence from prompts, no cwd-relative grant traps. Want something persistent? `/gate:rules add allow …` — explicit, auditable, and reviewed as a rule.
- Operator outcomes collapse to allow / deny, and the prompt to `y` / `n`. A repeated ask means the model is genuinely uncertain; papering over it with an "always" button is how rubber-stamping starts.
- Rules remain a first-match fast-path ahead of the model: instant and free for the obvious cases (`ls`, `find` allowed by default), and the operator's explicit allow/deny intent. They no longer carry the burden of guarding the model.
- The state invariant tightens (ADR-0002): the model sees the tool name, the first 100 characters of the serialized arguments, and the capped task text. Full file contents never reach the judge; the operator prompt keeps a capped preview.
- `protectedPaths` (deny-rule patterns plus the gate dirs) still ride in the state, so obfuscated spellings the deterministic layers miss are judged with that knowledge.
- The accepted vulnerability, named: a confident-but-wrong `safe` now auto-allows any tool, including `bash` and `write`. This is a deliberate tradeoff — the operator judged fatigue the likelier and more dangerous failure — and its containment is the deterministic layers ahead of the model plus the threshold, not ask floors.
- Residual: a steered model is more dangerous as the primary classifier than as a fallback; that danger is the reason self-protection (ADR-0003) is code-level and overridable by no rule, and secrets detection (ADR-0004) is deterministic.

## Amendment

The decision matrix has since been tuned, with the operator's approval:

- The default threshold dropped from 0.85 to 0.65, and auto-allow now additionally requires the model's reported `unsafe` probability to sit at or below a fixed 0.1 bound — a constant, not a knob, same reasoning as the 100-character argument view (ADR-0002); a missing `probabilities` counts as unmet, fail-closed to ask. A confident `safe` with non-negligible unsafe mass now asks instead of auto-allowing, narrowing the accepted silent false-allow.
- The lower threshold also lowers the auto-block bar: an `unsafe` at 0.65 confidence now auto-blocks where it previously asked — fail-closed, but more blocking.

The containment story is otherwise unchanged: deterministic layers ahead of the model, plus the threshold and the probability bound. Ask floors and the session cache remain removed.

With more than one configured endpoint the single-judge matrix becomes a jury — most-pessimistic aggregation, one unavailable endpoint counts as pessimistic — recorded in [ADR-0006](0006-the-endpoint-jury-runs-most-pessimistic.md).
