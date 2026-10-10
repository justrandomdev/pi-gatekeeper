/**
 * The /gate:log TUI overlay: a modal viewer with one row per decision,
 * Enter to expand the selected record in full. Non-TUI modes keep the
 * handler's one-line rendering (see gate:log in index.ts).
 */

import type { Theme } from "@earendil-works/pi-coding-agent";
import type { Component, TUI } from "@earendil-works/pi-tui";
import { Key, matchesKey, truncateToWidth, visibleWidth, wrapTextWithAnsi } from "@earendil-works/pi-tui";
import type { LogRecord } from "../src/decision.js";

export type LogEntry = LogRecord & { ts: string };

export interface LogViewOptions {
  /** Requested decision count (for the title). */
  n: number;
  /** Tool filter as typed by the operator (for the title). */
  filter?: string;
}

const ACTION_COLORS = { allow: "success", block: "error" } as const;
const CHOICE_COLORS = { safe: "success", unsafe: "error", unsure: "warning", unavailable: "error" } as const;

/** Model column: the serving endpoint, all jury/fallback member names, or —. */
export function modelName(r: LogEntry): string {
  if (r.endpoint) return r.endpoint;
  if (r.jury?.length) return r.jury.map((v) => v.name).join(", ");
  return "—";
}

/** Fixed caps for the leading columns; args/reason split what's left 40/60. */
const COL_HEADERS = ["time", "tool", "action", "source", "class", "model"] as const;
const COL_MAX = [8, 12, 6, 9, 13, 16];

export class GateLogView implements Component {
  private selected = 0;
  private detail = false;
  private scrollTop = 0;
  private cache: { width: number; lines: string[] } | undefined;

  constructor(
    private readonly tui: TUI,
    private readonly theme: Theme,
    private readonly records: LogEntry[],
    private readonly done: () => void,
    private readonly opts: LogViewOptions,
  ) {}

  invalidate(): void {
    this.cache = undefined;
  }

  handleInput(data: string): void {
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
      else if (matchesKey(data, Key.enter)) {
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
    const body = this.detail ? this.detailBody(inner) : this.table(inner);
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
    const widths = columnWidths(this.records.map((r) => this.rowCells(r)), inner);

    const header = [...COL_HEADERS, "args", "reason"].map((h, i) => h.padEnd(widths[i]));
    const ruleLines: string[] = [
      truncateToWidth(this.theme.fg("muted", this.theme.bold(header.join(" "))), inner),
      this.theme.fg("border", "─".repeat(inner)),
    ];

    const height = Math.max(1, this.contentHeight() - ruleLines.length);
    this.scrollTop = makeVisible(this.scrollTop, this.selected, height, this.records.length);

    const rows: string[] = [];
    for (let i = this.scrollTop; i < Math.min(this.records.length, this.scrollTop + height); i++) {
      const cells = this.rowCells(this.records[i]!);
      const text = cells.map((c, j) => c.padEnd(widths[j])).join(" ");
      const line = i === this.selected
        ? this.theme.bg("selectedBg", text + trailingPad(text, inner))
        : this.colorRow(cells, widths, this.records[i]!);
      rows.push(truncateToWidth(line, inner));
    }
    return [...ruleLines, ...rows];
  }

  private colorRow(cells: string[], widths: number[], record: LogEntry): string {
    return cells.map((c, j) => this.color(j, record, c.padEnd(widths[j]))).join(" ");
  }

  private color(column: number, record: LogEntry, text: string): string {
    switch (column) {
      case 0:
        return this.theme.fg("dim", text);
      case 2:
        return this.theme.fg(ACTION_COLORS[record.action] ?? "text", text);
      case 3:
        return this.theme.fg("dim", text);
      default:
        return text;
    }
  }

  private rowCells(r: LogEntry): string[] {
    const cls = r.classification ? `${r.classification} ${(r.confidence ?? 0).toFixed(2)}` : "—";
    return [r.ts.slice(11, 19), r.tool, r.action, r.source, cls, modelName(r), r.args ?? "", r.reason ?? "—"];
  }

  // Detail mode ---------------------------------------------------------------

  private scrollDetail(data: string): void {
    const viewport = this.detailViewport();
    const lines = this.detailLines(this.outerWidth(this.tui.terminal.columns) - 4);
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
    return `gate › last ${this.records.length} decision${this.records.length === 1 ? "" : "s"}${filter}`;
  }

  private hints(): string {
    return this.detail ? "↑↓ scroll · Enter/Esc back · q close" : "↑↓ select · Enter detail · Esc/q close";
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

/** Content-driven widths for the six capped columns; args/reason share the rest 40/60. */
function columnWidths(rows: string[][], inner: number): number[] {
  const fixed = COL_HEADERS.map((h, i) => {
    const longest = Math.max(0, ...rows.map((r) => r[i]?.length ?? 0));
    return Math.max(h.length, Math.min(longest, COL_MAX[i]));
  });
  const used = fixed.reduce((a, b) => a + b, 0) + (COL_HEADERS.length - 1) + 2; // separators + padding
  const remaining = Math.max(12, inner - used);
  const argsW = Math.min(Math.max(6, Math.floor(remaining * 0.4)), 60);
  return [...fixed, argsW, Math.max(6, remaining - argsW)];
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
