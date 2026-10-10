# A decision model in the gate path

Static rules alone either nag the operator into rubber-stamping approvals — ask-fatigue is a security failure mode, not a UX nuisance — or miss indirect threats (exfiltration by script, by folder traversal, by written-then-run code). We put a decision model in the hot path of every tool call instead: a Jev/System One-compatible model (default local `clef-flash`) classifies each call `safe`/`unsafe`/`unsure` with confidence, and confident classifications act autonomously. The model's job is making asks rare and high-signal so operator attention stays meaningful.

## Consequences

The accepted vulnerabilities, named:

- **The judge can be steered by what it judges.** The model reads arguments that may embed text absorbed from untrusted sources. Contained by a state invariant (tightened by ADR-0005): the state is only the tool name, the **first 100 characters** of the serialized arguments, the capped task text, and the working directory (path metadata, so policy terms like "writes outside the project" are decidable against something the model can see) — never full file contents, fetched text, or conversation history. Secrets never reach the judge at all: deterministic detection (ADR-0004) blocks them before the model is invoked. The operator prompt keeps a capped preview — the operator is human.
- **Confident-but-wrong is silent.** The model's confidence is concentration of probabilities, not probability of correctness, and a false `safe` auto-allows without a prompt. Contained by keeping the deterministic layers — self-protection (ADR-0003), secrets detection (ADR-0004), rules — ahead of the model, and by the threshold on autonomous action. The former containment (ask floors) was removed with ADR-0005: the operator judged fatigue the likelier and more dangerous failure, and accepted that a false `safe` can auto-allow any tool.
- **Remote endpoints are data egress by design.** Configuring a remote clef/Jev endpoint sends every gated call's tool name, the first 100 characters of its arguments, and the current task text off-machine. Local-first is the default; remote must be a conscious choice.
- **Every tool call gains a latency and availability dependency.** The model is small and cheap — a hosted clef-flash classifies in ~40ms — and session caching was removed (ADR-0005): at that price, retries simply re-classify, and cached security decisions are an anti-pattern anyway. When the model is down every call degrades to ask (an ask storm in exactly the mode where fatigue sets in), with fail-block available for headless use.

The rejected alternative — static deny-all with operator confirmation on everything — fails operationally within days, when approvals stop being read.
