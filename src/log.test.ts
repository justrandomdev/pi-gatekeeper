import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdir, mkdtemp, readdir, readFile, rm, stat, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DecisionLog } from "./log.js";

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "gatekeeper-log-"));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

const DAY = 24 * 60 * 60 * 1000;
const now = () => new Date("2026-01-10T12:00:00Z");

function record(tool: string) {
  return { tool, args: "{}", action: "allow" as const, source: "model" as const };
}

describe("decision log", () => {
  it("appends JSONL records with timestamps", async () => {
    const log = new DecisionLog({ dir, maxLines: 10, keepFiles: 3, retentionDays: 30, now });
    await log.append(record("read"));
    await log.append(record("ls"));
    const lines = (await readFile(join(dir, "decisions.jsonl"), "utf8")).trim().split("\n");
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0]).tool).toBe("read");
    expect(JSON.parse(lines[0]).ts).toBe(now().toISOString());
  });

  it("works with the default clock (no injected now)", async () => {
    const log = new DecisionLog({ dir, maxLines: 10, keepFiles: 3, retentionDays: 30 });
    await log.append(record("read"));
    const parsed = JSON.parse((await readFile(join(dir, "decisions.jsonl"), "utf8")).trim());
    expect(parsed.ts).toBeTruthy();
    expect(new Date(parsed.ts).getTime()).toBeGreaterThan(0);
  });

  it("rotates after the configured line count and shifts older files", async () => {
    const log = new DecisionLog({ dir, maxLines: 3, keepFiles: 3, retentionDays: 30, now });
    for (let i = 0; i < 7; i++) await log.append(record(`t${i}`));
    const files = (await readdir(dir)).sort();
    // decisions.jsonl plus 2 rotated files (keepFiles 3 caps .1/.2/.3 → .3 dropped)
    expect(files).toEqual(["decisions.jsonl", "decisions.jsonl.1", "decisions.jsonl.2"]);
    const rotated = (await readFile(join(dir, "decisions.jsonl.1"), "utf8")).trim().split("\n");
    expect(rotated).toHaveLength(3);
    expect(JSON.parse(rotated[0]).tool).toBe("t3");
  });

  it("counts lines in a pre-existing log before rotating", async () => {
    await writeFile(join(dir, "decisions.jsonl"), `${JSON.stringify(record("x"))}\n${JSON.stringify(record("y"))}\n`);
    const log = new DecisionLog({ dir, maxLines: 3, keepFiles: 2, retentionDays: 30, now });
    await log.append(record("z"));
    expect((await readdir(dir))).toContain("decisions.jsonl");
    // reaching the line count rotated the pre-existing lines out with the new one
    const rotated = (await readFile(join(dir, "decisions.jsonl.1"), "utf8")).trim().split("\n");
    expect(rotated.map((l) => JSON.parse(l).tool)).toEqual(["x", "y", "z"]);
    expect((await readFile(join(dir, "decisions.jsonl"), "utf8")).trim()).toBe("");
  });

  it("creates the log directory with mode 0o700 so other local users can't read the log", async () => {
    const nested = join(dir, "fresh", "deeper");
    const log = new DecisionLog({ dir: nested, maxLines: 10, keepFiles: 3, retentionDays: 30, now });
    await log.append(record("read"));
    const info = await stat(nested);
    expect(info.mode & 0o777).toBe(0o700);
    const parentInfo = await stat(join(nested, ".."));
    // the parent was created by the same mkdir call, also mode 0o700
    expect(parentInfo.mode & 0o777).toBe(0o700);
  });

  it("deletes rotated files older than the retention window", async () => {
    const log = new DecisionLog({ dir, maxLines: 2, keepFiles: 5, retentionDays: 30, now });
    for (let i = 0; i < 2; i++) await log.append(record(`a${i}`));
    // rotate once, then age that rotated file beyond retention
    const stale = join(dir, "decisions.jsonl.1");
    await utimes(stale, new Date(now().getTime() - 40 * DAY), new Date(now().getTime() - 40 * DAY));
    for (let i = 0; i < 2; i++) await log.append(record(`b${i}`));
    const files = (await readdir(dir)).sort();
    expect(files).toEqual(["decisions.jsonl", "decisions.jsonl.1"]);
    // .1 is the fresh rotation (b0/b1); the stale a-file is gone
    const fresh = (await readFile(join(dir, "decisions.jsonl.1"), "utf8")).trim().split("\n");
    expect(JSON.parse(fresh[0]).tool).toBe("b0");
  });

  it("tails the most recent decisions across rotations", async () => {
    const log = new DecisionLog({ dir, maxLines: 2, keepFiles: 5, retentionDays: 30, now });
    for (let i = 0; i < 5; i++) await log.append(record(`t${i}`));
    const tail = await log.tail(3);
    expect(tail.map((r) => r.tool)).toEqual(["t2", "t3", "t4"]);
  });
});
