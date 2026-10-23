# Auto mode: the uncertainty bucket allows

## Status

Accepted (amends ADR-0005's decision matrix: the ask floors and the
auto-allow probability bound no longer gate anything while auto mode is
on; user stories 7 and 8 are deliberately voided in that mode).

## Context

The gate's remaining ask storm is the uncertainty bucket: `unsure`,
below-threshold, and bound-exceeded `safe` all converge on the operator
prompt. Under pi swarms — several herdr-hosted pi sessions running on one
machine, each gated — that fatigue multiplies by the session count. The
decision model's classifications were evaluated across multiple projects
and its confident calls proved good; the highest-risk items (gate
self-protection, secret exfiltration, deny rules) are already caught by
the deterministic layers, which never consult the model. The operator,
who owns the gate's risk posture and has accepted the residual risk of
unattended uncertain calls, directs that the uncertainty bucket act on
its own in a dedicated mode.

## Decision

The config gains `mode: manual | auto` — default `manual`, safe by
default. Standard per-level merge (project overrides user),
whitelist-validated, set only via `/gate:config set mode auto|manual`
(no bare shorthand; one grammar). An invalid hand-edited value is a
config error, reported in `/gate` and refused by the model gate — never
silently read as manual; the posture the operator believes in must be
the posture that runs. Auto mode rewires exactly one bucket — the
**ask** side:

- Confident blocks are unchanged: `unsafe` at or above the threshold
  auto-blocks, as do deny rules, secrets hits, and self-protection.
  Allow rules allow unchanged.
- The ask bucket — explicit `unsure`, `safe` below the threshold, and
  `safe` failing the unsafe-probability bound — **allows** instead of
  asking. So does an `unsafe` verdict *below* the threshold: the
  threshold decides which verdicts are confident blocks, everything
  weaker is uncertainty, and uncertainty allows here. The
  unsafe-probability bound is inert in this mode (stories 7 and 8 are
  voided there, on purpose); the threshold is not — it still draws the
  block line.
- Model failure is untouched: `failMode` governs in both modes (default
  `ask`; an explicit `block` is honored, never vetoed). `fail` is the
  only path that still asks in auto mode. A second exception, when one
  shows up, is added by editing that one predicate — no configurable
  exception mechanism until a real second case exists.
- Auto mode is prompt-free by construction: outside the fail path the
  ask path is unreachable, not hidden.
- Auto decisions are logged with the new source `auto` (and an `[auto]`
  transparency tag, per the ADR-0007 tag precedent); `operator` forever
  means a human decided.

Every log record gains the pi session's id (`sessionId`, taken live at
write time, both modes). `/gate:log` gains a `session <prefix>` filter
composing with the existing `[n] [toolfilter]` form. Prefixes are
resolved against the whole log — never the tail window — by substring
test on the raw JSONL line, so records outside the window still match
and records that do not match are never parsed; ambiguous prefixes and
not-found prefixes are reported distinctly. The TUI log view gains a
column selector (`c` opens a vertical toggle menu, `x` or space
toggles, `q`/`esc` back keeping changes): all columns toggleable,
Session ID default off, the visible set persisted as a new `log.columns`
config key (validated, user level only — a view preference of the
human, not a repo posture; written by the selector, and its writes are
serialized through a promise chain so rapid toggles cannot interleave a
read-modify-write and truncate the file). A config level that fails to
parse is announced (`config unreadable at <level> level`) instead of
passing for defaults — a corrupt `failMode: block` file must never look
like an ordinary config.
`/gate` status shows the posture and the level that decided it
(`Gate mode: auto (project)`), so the ADR's central invariant — the
posture believed is the posture that runs — is checkable; the
endpoint-act line is `Endpoint mode:` to keep the two distinguishable.
An auto-allow count rides in the session stats; notify knobs govern
auto lines unchanged — the log is the audit trail.

## Consequences

- In auto mode the block set is only the deterministic layers plus an
  `unsafe` verdict at or above the threshold: the model's "I don't know"
  is a yes — and so is a weak `unsafe`. That is the sharpest consequence
  of the mode: raising `threshold` narrows the block line and widens the
  auto-allow set, which is why `/gate` shows the mode and the auto-allow
  count together. The operator's explicit, risk-accepted trade (see
  Context) — recorded here so a future reader does not "fix" it back to
  asking.
- Manual mode is byte-identical to pre-ADR-0008 behavior; the `mode`
  key changes nothing until set to `auto`.
- The session id on every record incidentally makes a shared log
  attributable per session — the review half of the spec's two-sessions
  rotation-race residual. The selector's un-awaited writes made that
  residual concrete (a lost write became a corrupt config), so writes
  are serialized: one queue, read-modify-write runs to completion.
- The `threshold` keeps its one job in auto mode — it draws the
  confident-block line — while the ask floors and the auto-allow bound
  stop gating anything. `/gate` surfaces the mode and the auto-allow
  count so the posture and its cost are visible at a glance.
