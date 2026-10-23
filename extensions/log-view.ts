/**
 * The /gate:log TUI overlay: a modal viewer with one row per decision,
 * Enter to expand the selected record in full. Non-TUI modes keep the
 * handler's one-line rendering (see gate:log in index.ts).
 */

import type { Theme } from "@earendil-works/pi-coding-agent";
import type { Component, TUI } from "@earendil-works/pi-tui";
import { Key, matchesKey, truncateToWidth, visibleWidth, wrapTextWithAnsi } from "@earendil-works/pi-tui";
import type { LogRecord } from "../src/decision.js";
import { DEFAULT_LOG_COLUMNS, LOG_COLUMNS, type LogColumn } from "../src/config.js";

export type LogEntry = LogRecord & { ts: string };

export interface LogViewOptions {
  /** Requested decision count (for the title). */
  n: number;
  /** Tool filter as typed by the operator (for the title). */
  filter?: string;
  /** Session-id prefix filter (for the title, ADR-0008). */
  session?: string;
  /** The persisted `log.columns` set; absent → the default view. */
  columns?: LogColumn[];
  /** Persist a new visible set (user level, ADR-0008), fired on each
   *  toggle. */
  persistColumns?: (columns: LogColumn[]) => void;
}

const ACTION_COLORS = { allow: "success", block: "error" } as const;
const CHOICE_COLORS = { safe: "success", unsafe: "error", unsure: "warning", unavailable: "error" } as const;

/** The column registry is config-shaped (src/config.ts); this module owns
 *  only how a column renders. */
const COL_CAPS: Record<Exclude<LogColumn, "args" | "reason">, number> = {
  time: 8,
  tool: 12,
  action: 6,
  source: 9,
  class: 13,
  model: 16,
  session: 10,
};
const FLEXIBLE: readonly string[] = ["args", "reason"];

/** The configured column set in registry order. Deliberately lenient,
 *  unlike `mode` (which throws): a column name is cosmetic — an unknown
 *  one is dropped and an unresolvable set falls back to the default
 *  view, which is always a usable table. */
function resolveColumns(configured?: LogColumn[]): LogColumn[] {
  const visible = configured?.length ? LOG_COLUMNS.filter((c) => configured.includes(c)) : [];
  return visible.length ? visible : [...DEFAULT_LOG_COLUMNS];
}

/** Model column: the serving endpoint, all jury/fallback member names, or —. */
export function modelName(r: LogEntry): string {
  if (r.endpoint) return r.endpoint;
  if (r.jury?.length) return r.jury.map((v) => v.name).join(", ");
  return "—";
}

export class GateLogView implements Component {
  private selected = 0;
  private detail = false;
  private scrollTop = 0;
  private cache: { width: number; lines: string[] } | undefined;
  private visible: LogColumn[];
  private menu = false;
  private menuIndex = 0;
  private menuTop = 0;
  /** The content width the last render wrapped at. The detail scroll clamp
   *  must use the same width, or it computes a short `maxTop` and the tail
   *  of a long record is unreachable. */
  private innerWidth = 0;

  constructor(
    private readonly tui: TUI,
    private readonly theme: Theme,
    private readonly records: LogEntry[],
    private readonly done: () => void,
    private readonly opts: LogViewOptions,
  ) {
    this.visible = resolveColumns(opts.columns);
  }

  invalidate(): void {
    this.cache = undefined;
  }

  handleInput(data: string): void {
    if (this.menu) {
      if (matchesKey(data, Key.escape) || data === "q") {
        this.menu = false;
      } else if (matchesKey(data, Key.up) || data === "k") {
        this.menuIndex = Math.max(0, this.menuIndex - 1);
      } else if (matchesKey(data, Key.down) || data === "j") {
        this.menuIndex = Math.min(LOG_COLUMNS.length - 1, this.menuIndex + 1);
      } else if (data === "x" || data === " ") {
        this.toggleColumn(LOG_COLUMNS[this.menuIndex]!);
      }
      this.invalidate();
      this.tui.requestRender();
      return;
    }
    if (data === "q") {
      this.done();
      return;
    }
    if (matchesKey(data, Key.escape)) {
      // Esc back to the table must fall through to invalidate/render;
      // only full closes may return early.
      if (!this.detail) {
        this.done();
        return;
      }
      this.detail = false;
      this.scrollTop = 0;
    } else if (this.detail) {
      if (matchesKey(data, Key.enter)) {
        this.detail = false;
        this.scrollTop = 0;
      } else {
        this.scrollDetail(data);
      }
    } else {
      const height = this.contentHeight();
      if (matchesKey(data, Key.up) || data === "k") this.moveSelection(-1);
      else if (matchesKey(data, Key.down) || data === "j") this.moveSelection(1);
      else if (matchesKey(data, Key.pageUp)) this.moveSelection(-height);
      else if (matchesKey(data, Key.pageDown)) this.moveSelection(height);
      else if (data === "c") {
        this.menu = true;
        this.menuIndex = 0;
        this.menuTop = 0;
      } else if (matchesKey(data, Key.enter)) {
        this.detail = true;
        this.scrollTop = 0;
      }
    }

    this.invalidate();
    this.tui.requestRender();
  }

  render(width: number): string[] {
    if (this.cache?.width === width) return this.cache.lines;
    const outer = this.outerWidth(width);
    const inner = outer - 4; // "│ " + content + " │"
    this.innerWidth = inner;
    const body = this.menu ? this.menuBody(inner) : this.detail ? this.detailBody(inner) : this.table(inner);
    const lines = [
      borderTop(this.title(), outer, this.theme),
      blankRow(outer, this.theme),
      ...body.map((l) => sideRow(l, inner, this.theme)),
      blankRow(outer, this.theme),
      borderBottom(this.hints(), `${this.selected + 1}/${this.records.length}`, outer, this.theme),
    ];
    this.cache = { width, lines };
    return lines;
  }

  // Table mode ---------------------------------------------------------------

  private table(inner: number): string[] {
    // Build every row once, clipped to the content width: a full-size args
    // value can run to hundreds of KB, and nothing wider than `inner` can
    // ever be shown. Without the clip the table re-handles megabytes of
    // string per frame, which is visible as stutter once records get big.
    const cellsByRecord = this.records.map((r) => this.rowCells(r, inner));
    const widths = columnWidths(this.visible, cellsByRecord, inner);

    const header = this.visible.map((h, i) => h.padEnd(widths[i]!));
    const ruleLines: string[] = [
      truncateToWidth(this.theme.fg("muted", this.theme.bold(header.join(" "))), inner),
      this.theme.fg("border", "─".repeat(inner)),
    ];

    const height = Math.max(1, this.contentHeight() - ruleLines.length);
    this.scrollTop = makeVisible(this.scrollTop, this.selected, height, this.records.length);

    const rows: string[] = [];
    for (let i = this.scrollTop; i < Math.min(this.records.length, this.scrollTop + height); i++) {
      const cells = cellsByRecord[i]!;
      const text = cells.map((c, j) => c.padEnd(widths[j]!)).join(" ");
      const line = i === this.selected
        ? this.theme.bg("selectedBg", text + trailingPad(text, inner))
        : this.colorRow(cells, widths, this.records[i]!);
      rows.push(truncateToWidth(line, inner));
    }
    return [...ruleLines, ...rows];
  }

  private colorRow(cells: string[], widths: number[], record: LogEntry): string {
    return this.visible.map((c, j) => this.color(c, record, cells[j]!.padEnd(widths[j]!))).join(" ");
  }

  private color(column: LogColumn, record: LogEntry, text: string): string {
    if (column === "time" || column === "source") return this.theme.fg("dim", text);
    if (column === "action") return this.theme.fg(ACTION_COLORS[record.action] ?? "text", text);
    return text;
  }

  private rowCells(r: LogEntry, max: number): string[] {
    return this.visible.map((c) => this.cell(r, c, max));
  }

  /** One cell, clipped to `max` characters — enough for any column width,
   *  so the clip is never visible. */
  private cell(r: LogEntry, column: LogColumn, max: number): string {
    const clip = (text: string) => (text.length <= max ? text : text.slice(0, max));
    const cls = r.classification ? `${r.classification} ${(r.confidence ?? 0).toFixed(2)}` : "—";
    switch (column) {
      case "time": return r.ts.slice(11, 19);
      case "tool": return r.tool;
      case "action": return r.action;
      case "source": return r.source;
      case "class": return cls;
      case "model": return modelName(r);
      case "session": return (r.sessionId ?? "—").slice(0, COL_CAPS.session);
      case "args": return clip(r.args ?? "");
      case "reason": return clip(r.reason ?? "—");
    }
  }

  /** The column selector: a vertical registry menu, toggled in place.
   *  Scrolled to the body height so a short terminal can still reach
   *  every column. */
  private menuBody(inner: number): string[] {
    const height = Math.max(1, this.contentHeight());
    this.menuTop = makeVisible(this.menuTop, this.menuIndex, height, LOG_COLUMNS.length);
    return LOG_COLUMNS.slice(this.menuTop, this.menuTop + height).map((c, j) => {
      const row = `${this.visible.includes(c) ? "[x]" : "[ ]"} ${c}`;
      const line = this.menuTop + j === this.menuIndex ? this.theme.bg("selectedBg", row + trailingPad(row, inner)) : row;
      return truncateToWidth(line, inner);
    });
  }

  private toggleColumn(column: LogColumn): void {
    const next = this.visible.includes(column)
      ? this.visible.filter((c) => c !== column)
      : LOG_COLUMNS.filter((c) => this.visible.includes(c) || c === column);
    if (!next.length) return;
    this.visible = next;
    this.opts.persistColumns?.(next);
  }

  // Detail mode ---------------------------------------------------------------

  private scrollDetail(data: string): void {
    const viewport = this.detailViewport();
    // Wrap at the width the last render used: the overlay is narrower than
    // the terminal, and clamping against the terminal width under-counts the
    // wrapped lines, leaving the end of a long record unreachable.
    const inner = this.innerWidth || this.outerWidth(this.tui.terminal.columns) - 4;
    const lines = this.detailLines(inner);
    const maxTop = Math.max(0, lines.length - viewport);
    if (matchesKey(data, Key.up) || data === "k") this.scrollTop = Math.max(0, this.scrollTop - 1);
    else if (matchesKey(data, Key.down) || data === "j") this.scrollTop = Math.min(maxTop, this.scrollTop + 1);
    else if (matchesKey(data, Key.pageUp)) this.scrollTop = Math.max(0, this.scrollTop - viewport);
    else if (matchesKey(data, Key.pageDown)) this.scrollTop = Math.min(maxTop, this.scrollTop + viewport);
  }

  /** Detail rows visible at once: two go to the scroll markers. */
  private detailViewport(): number {
    return Math.max(1, this.contentHeight() - 2);
  }

  /** Full record, every stored field untruncated (args up to the logged cap). */
  private detailLines(inner: number): string[] {
    const r = this.records[this.selected]!;
    const lines: string[] = [];
    const section = (label: string, value: string, colorize?: (s: string) => string) => {
      const wrapped = wrapTextWithAnsi(colorize ? colorize(value) : value, Math.max(1, inner - label.length - 2));
      lines.push(this.theme.fg("muted", `${label}: `) + wrapped[0]!);
      for (const line of wrapped.slice(1)) lines.push(" ".repeat(label.length + 2) + line);
    };

    section("time", r.ts);
    section("tool", r.tool);
    section("action", r.action, (s) => this.theme.fg(ACTION_COLORS[r.action] ?? "text", s));
    section("source", r.source, (s) => this.theme.fg("dim", s));
    if (r.sessionId) {
      section("session", r.sessionId);
    }
    if (r.classification) {
      section("class", `${r.classification} ${(r.confidence ?? 0).toFixed(2)}`);
    }
    if (r.jury?.length) {
      section("model", r.jury
        .map((v) => {
          const conf = v.confidence !== undefined ? ` ${(v.confidence).toFixed(2)}` : "";
          const err = v.error ? ` — ${v.error}` : "";
          const color = CHOICE_COLORS[v.choice as keyof typeof CHOICE_COLORS] ?? "text";
          return this.theme.fg(color, `${v.name}: ${v.choice}${conf}${err}`);
        })
        .join("\n"));
    } else if (r.endpoint) {
      section("model", r.endpoint);
    }
    if (r.probabilities) {
      section("probabilities", Object.entries(r.probabilities).map(([k, v]) => `${k} ${v.toFixed(2)}`).join("  "));
    }
    if (r.reason) {
      section("reason", r.reason);
    }
    if (r.args) {
      lines.push("");
      section("args", r.args);
    }
    return lines;
  }

  private detailBody(inner: number): string[] {
    const lines = this.detailLines(inner);
    const viewport = this.detailViewport();
    if (lines.length <= viewport) return lines;
    const slice = lines.slice(this.scrollTop, this.scrollTop + viewport);
    return ["…", ...slice, "…"].map((l) => truncateToWidth(l, inner));
  }

  // Layout helpers ------------------------------------------------------------

  /**
   * pi clips an overlay at maxHeight = floor(termRows × 0.9) (tui.js
   * resolveOverlayLayout + overlayLines.slice). Stay at or under it or the
   * bottom border is sliced off.
   */
  private heightBudget(): number {
    return Math.max(8, Math.floor(this.tui.terminal.rows * 0.9));
  }

  /** Body lines available: the budget minus the 4 frame lines (2 borders + 2 pads). */
  private contentHeight(): number {
    return Math.max(1, this.heightBudget() - 4);
  }

  private outerWidth(width: number): number {
    return Math.max(24, width - 1); // one space after the right border
  }

  private moveSelection(delta: number): void {
    this.selected = Math.min(this.records.length - 1, Math.max(0, this.selected + delta));
  }

  private title(): string {
    const filter = this.opts.filter ? ` [${this.opts.filter}]` : "";
    const session = this.opts.session ? ` [session ${this.opts.session}]` : "";
    return `gate › last ${this.records.length} decision${this.records.length === 1 ? "" : "s"}${filter}${session}`;
  }

  private hints(): string {
    if (this.menu) {
      return this.visible.length === 1
        ? "↑↓ move · x/space toggle · keep at least one · Esc back"
        : "↑↓ move · x/space toggle · Esc back";
    }
    return this.detail ? "↑↓ scroll · Enter/Esc back · q close" : "↑↓ select · Enter detail · c columns · Esc/q close";
  }
}

// Module-level helpers (pure string math / data, no component state) ---------

/** Keep the selected record inside the row window. */
function makeVisible(top: number, selected: number, height: number, count: number): number {
  const bounded = Math.max(0, Math.min(top, Math.max(0, count - height)));
  if (selected < bounded) return Math.max(0, selected);
  if (selected >= bounded + height) return Math.max(0, Math.min(selected - height + 1, count - height));
  return bounded;
}

/** Content-driven widths for the visible fixed columns; args/reason
 *  (whichever are visible) share the rest 40/60. */
function columnWidths(visible: LogColumn[], rows: string[][], inner: number): number[] {
  const fixedCols = visible.filter((c): c is Exclude<LogColumn, "args" | "reason"> => !FLEXIBLE.includes(c));
  const fixed = new Map<LogColumn, number>(fixedCols.map((c) => {
    const i = visible.indexOf(c);
    const longest = Math.max(0, ...rows.map((r) => r[i]?.length ?? 0));
    return [c, Math.max(c.length, Math.min(longest, COL_CAPS[c]))] as const;
  }));
  const used = [...fixed.values()].reduce((a, b) => a + b, 0) + visible.length - 1 + 2; // separators + padding
  const remaining = Math.max(12, inner - used);
  const hasArgs = visible.includes("args");
  const hasReason = visible.includes("reason");
  const argsW = hasArgs && hasReason ? Math.min(Math.max(6, Math.floor(remaining * 0.4)), 60) : hasArgs ? remaining : 0;
  const reasonW = hasReason ? Math.max(6, remaining - argsW) : 0;
  const flexible = new Map([["args", argsW], ["reason", reasonW]]);
  return visible.map((c) => fixed.get(c) ?? flexible.get(c) ?? 0);
}

function trailingPad(text: string, inner: number): string {
  return " ".repeat(Math.max(0, inner - visibleWidth(text)));
}

function borderTop(title: string, outer: number, theme: Theme): string {
  const label = `─ ${title} `;
  const rest = Math.max(0, outer - 2 - visibleWidth(label));
  return truncateToWidth(theme.fg("border", `┌${label}${"─".repeat(rest)}┐`), outer);
}

function borderBottom(hints: string, counter: string, outer: number, theme: Theme): string {
  const counterText = ` ${counter} `;
  const room = outer - 2 - 3 - 1 - visibleWidth(counterText) - 1; // corners + "└─ " + gap + ≥1 fill// corners + "└─ " + gap
  const label = truncateToWidth(hints, Math.max(0, room));
  const fill = Math.max(1, outer - 6 - visibleWidth(label) - visibleWidth(counterText));
  return (
    theme.fg("border", "└─ ") +
    theme.fg("dim", label) +
    theme.fg("border", " " + "─".repeat(fill)) +
    theme.fg("dim", counterText) +
    theme.fg("border", "─┘")
  );
}

/** A row inside the box: "│ " + content padded to `inner` + " │". */
function sideRow(content: string, inner: number, theme: Theme): string {
  const text = content + trailingPad(content, inner);
  return theme.fg("border", "│") + " " + text + " " + theme.fg("border", "│");
}

function blankRow(outer: number, theme: Theme): string {
  return theme.fg("border", `│${" ".repeat(Math.max(0, outer - 2))}│`);
}
