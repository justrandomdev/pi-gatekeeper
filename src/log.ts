/**
 * The decision log: JSONL with line-count rotation and day-based retention.
 * Every gate decision lands here, one line each. See docs/spec.md.
 */

import { appendFile, mkdir, readdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { LogRecord } from "./decision.js";

export const LOG_FILENAME = "decisions.jsonl";

export interface LogOptions {
  dir: string;
  maxLines: number;
  keepFiles: number;
  retentionDays: number;
  now?: () => Date;
}

export class DecisionLog {
  private readonly path: string;
  private readonly now: () => Date;
  private lineCount: number | undefined;

  constructor(private readonly opts: LogOptions) {
    this.path = join(opts.dir, LOG_FILENAME);
    this.now = opts.now ?? (() => new Date());
  }

  private async countLines(): Promise<number> {
    if (this.lineCount !== undefined) return this.lineCount;
    try {
      const text = await readFile(this.path, "utf8");
      this.lineCount = text.length === 0 ? 0 : text.trim().split("\n").length;
    } catch {
      this.lineCount = 0;
    }
    return this.lineCount;
  }

  /** Delete rotated files older than the retention window. */
  private async applyRetention(): Promise<void> {
    const cutoff = this.now().getTime() - this.opts.retentionDays * 24 * 60 * 60 * 1000;
    let entries: string[];
    try {
      entries = await readdir(this.opts.dir);
    } catch {
      return;
    }
    for (const entry of entries) {
      if (!entry.startsWith(`${LOG_FILENAME}.`)) continue;
      const full = join(this.opts.dir, entry);
      try {
        const info = await stat(full);
        if (info.mtimeMs < cutoff) await rm(full, { force: true });
      } catch {
        // raced away; nothing to do
      }
    }
  }

  /** Shift .1→.2→…→.keep, dropping beyond, then start a fresh active file. */
  private async rotate(): Promise<void> {
    for (let i = this.opts.keepFiles; i >= 2; i--) {
      const from = join(this.opts.dir, `${LOG_FILENAME}.${i - 1}`);
      const to = join(this.opts.dir, `${LOG_FILENAME}.${i}`);
      try {
        await rename(from, to);
      } catch {
        // nothing at this slot
      }
    }
    try {
      await rename(this.path, join(this.opts.dir, `${LOG_FILENAME}.1`));
    } catch {
      // nothing to rotate
    }
    // A fresh active file exists immediately after rotation.
    await writeFile(this.path, "", "utf8");
    this.lineCount = 0;
  }

  async append(record: LogRecord): Promise<void> {
    const line = JSON.stringify({ ts: this.now().toISOString(), ...record });
    const count = await this.countLines();
    await mkdir(this.opts.dir, { recursive: true, mode: 0o700 });
    await appendFile(this.path, `${line}\n`, "utf8");
    this.lineCount = count + 1;
    // Rotation happens once the file has reached the configured line count.
    if (this.lineCount >= this.opts.maxLines) {
      await this.rotate();
      await this.applyRetention();
    }
  }

  /** Most recent n decisions, newest last, across rotations. */
  async tail(n: number): Promise<(LogRecord & { ts: string })[]> {
    const collected: (LogRecord & { ts: string })[] = [];
    for (let i = this.opts.keepFiles; i >= 1 && collected.length < n; i--) {
      const rotated = join(this.opts.dir, `${LOG_FILENAME}.${i}`);
      try {
        const text = await readFile(rotated, "utf8");
        for (const line of text.trim().split("\n").filter(Boolean)) {
          collected.push(JSON.parse(line));
        }
      } catch {
        // no file at this slot
      }
    }
    try {
      const text = await readFile(this.path, "utf8");
      for (const line of text.trim().split("\n").filter(Boolean)) {
        collected.push(JSON.parse(line));
      }
    } catch {
      // no active file yet
    }
    return collected.slice(-n);
  }
}
