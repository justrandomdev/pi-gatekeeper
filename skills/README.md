# Skills

Two kinds live under `skills/`, delivered differently:

- **Shipped skills** (part of the pi package): declared in the `pi` manifest in `package.json` and loaded with the plugin when pi installs this repo. [`gatekeeper-config`](./gatekeeper-config/SKILL.md) is the one shipped skill.
- **Dev skills** (CLI-managed, this repo only): vendored into `.agents/skills/` by the [Vercel skills CLI](https://github.com/vercel-labs/skills) and tracked in `skills-lock.json` — the upstream engineering skills (tdd, code-review, diagnosing-bugs, …). Every dev skill added here must also be listed in the catalog below.

A skill is a directory with a `SKILL.md` containing YAML frontmatter (`name`, `description`) followed by instructions the agent loads on demand.

## Managing dev skills

```bash
# Restore the upstream skills vendored in skills-lock.json
npx skills experimental_install

# Add an upstream skill
npx skills add <owner>/<repo>

# List / remove / update
npx skills ls
npx skills remove <name> -y
npx skills update -y
```

## Dev skills vendored in this repo

Upstream [mattpocock/skills](https://github.com/mattpocock/skills) — see `skills-lock.json` for the full list (ask-matt, codebase-design, code-review, diagnosing-bugs, domain-modeling, grilling, pr, prototype, research, tdd, writing-for-agents, …).
