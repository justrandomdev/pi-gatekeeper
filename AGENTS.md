# AGENTS.md

## Core principles

1. **Think before coding.** Don't assume — state your interpretation and ask when uncertain. Don't hide confusion. Surface tradeoffs, and push back when a simpler approach exists.
2. **Simplicity first.** Minimum code that solves the problem. No unasked features, single-use abstractions, unrequested configurability, or error handling for impossible cases. If 200 lines could be 50, rewrite.
3. **Surgical changes.** Every changed line traces directly to the request. Match existing style. Mention unrelated dead code — don't delete it. Remove orphans your own changes created; leave pre-existing ones.
4. **Goal-driven execution.** Turn tasks into verifiable goals: "fix the bug" → write a test that reproduces it, then make it pass. For multi-step work, state a plan with a verify check per step, and loop until every check passes.

## What this repo is

pi-gatekeeper — a standalone [pi](https://github.com/earendil-works/pi) package (`@earendil-works/pi-coding-agent`) that gates every agent tool call through deterministic secret detection, static rules, and a decision model, so destructive, secret-exposing, or out-of-scope actions stop before they run. Installed by users with `pi install` (git or npm source); developed here as the single plugin in this repo.

Full design: [docs/spec.md](docs/spec.md). Decisions worth knowing: the [ADR index](docs/adr/). Language: [GLOSSARY.md](GLOSSARY.md).

**Token efficiency is a hard design constraint.** A change that inflates context, attention, or output spend is a regression even when the feature works:
- Prefer on-demand material (commands, tools) over always-loaded context — every always-on cost justifies itself.
- Keep descriptions, UI strings, and output terse; extension output lands in the model's window or the user's screen.

## Pi harness documentation

Authoritative harness docs: `$(npm root -g)/@earendil-works/pi-coding-agent/docs/` (the `docs/` folder inside the installed package). Hot files: `extensions.md` (extension API and events), `packages.md` (packaging), `skills.md` (skills); `sdk.md`, `rpc.md`, `custom-provider.md` for deep integration. When docs and code disagree, the exported types in `extensions/types.ts` are final.

## Plugin conventions

- The plugin lives at the repo root as a standard pi package (`pi` manifest in `package.json`).
- Extensions are plain TypeScript (jiti — no build step); don't add bundlers or compilers.
- Extensions run with the user's permissions — no network, filesystem, or subprocess access beyond the plugin's function.

## Commands

```bash
pi -e .                     # load for one run — the verification loop
pi install ./<repo> -l      # install into a project (needs project trust)
pi list                     # show packages
pi remove <source>          # remove one
pi update --extensions      # reconcile installations
npm test                    # vitest run
npm run typecheck           # tsc --noEmit
```

Every plugin change ends verified: load it with `pi -e .` and exercise the feature end-to-end before reporting done.

## Gotchas

- The gate protects its own config, decision log, and secrets definitions — agent tool calls on `.pi/gate/` (project) or `~/.pi/agent/gate/` (user) are always denied; the operator configures the gate by hand or with `/gate` commands.
- `.agents/skills/` is populated by the Vercel `skills` CLI: upstream skills are vendored via `skills-lock.json`, and repo-owned dev skills are copied in from `skills/` (the plugin's shipped skill, `skills/gatekeeper-config`, is declared in the `pi` manifest and is not vendored). Pi scans `.agents/skills/` natively; `.claude/skills/` is a symlink farm the CLI maintains for Claude Code. Don't hand-edit anything under those paths — upstream changes belong at the upstream source, and dev skills are edited in `skills/` then re-synced with `npx skills update -y`. Every dev skill must also be listed in `skills/README.md`.
