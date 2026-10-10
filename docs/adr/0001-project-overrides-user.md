# Project-level config overrides user-level

Safety tooling convention says user-level config must win: a cloned repository should never be able to weaken your gate. We invert it deliberately: user-level carries the safe defaults, and project-level overrides it — both per-key scalars and rule order — because trusted projects need to loosen the defaults for practical reasons, and the operator is responsible for the choices they make about the repos they run.

## Considered Options

- **User overrides project (convention)**: rejected — safe defaults that a trusted project cannot relax in practice get disabled entirely, which is worse than a scoped loosening.
- **Union with deny-priority**: rejected — a single user-level deny anywhere makes project loosening impossible without editing the user config.

## Consequences

- A repository's project config can weaken the gate. This is accepted: project config loads only after the operator grants pi project trust for that repo, which is where the review belongs.
- Operators must review project-level gatekeeper config when granting project trust, the same way they review project packages and extensions.
