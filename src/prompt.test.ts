import { describe, expect, it } from "vitest";
import { createGatePrompt, type GatePromptInfo } from "./prompt.js";

/** A stub theme: tags instead of ANSI so assertions stay readable. */
const theme = {
  fg: (color: string, text: string) => `<${color}>${text}</${color}>`,
  bold: (text: string) => `<b>${text}</b>`,
} as unknown as any;

const info: GatePromptInfo = {
  tool: "bash",
  classification: "safe",
  confidence: 0.75,
  reason: "ask floor: bash calls always require operator review",
  argsSummary: '{"command":"ls /home/shaun/code/pi-decision","timeout":10}',
};

function render(prompt: GatePromptInfo, width = 80): string[] {
  const results: string[] = [];
  const factory = createGatePrompt(prompt);
  const component = factory({} as any, theme, {} as any, () => {});
  results.push(...component.render(width));
  return results;
}

describe("gate prompt component", () => {
  it("wraps the message in a rounded border with the tool in the top edge", () => {
    const lines = render(info);
    expect(lines[0].startsWith("╭")).toBe(true);
    expect(lines[0].endsWith("╮")).toBe(true);
    expect(lines[0]).toContain("gate › bash");
    expect(lines[lines.length - 1].startsWith("╰")).toBe(true);
    expect(lines[lines.length - 1].endsWith("╯")).toBe(true);
    for (const line of lines.slice(1, -1)) {
      expect(line.startsWith("│")).toBe(true);
      expect(line.endsWith("│")).toBe(true);
    }
  });

  it("colors the classification line green for safe, red for unsafe, yellow for unsure or unavailable", () => {
    expect(render(info).join("\n")).toContain("<success><b>safe (0.75)</b></success>");
    expect(render({ ...info, classification: "unsafe" }).join("\n")).toContain("<error><b>unsafe");
    expect(render({ ...info, classification: "unsure" }).join("\n")).toContain("<warning><b>unsure");
    expect(render({ ...info, classification: undefined }).join("\n")).toContain("<warning>");
  });

  it("shows the reason and the arguments inside the box", () => {
    const text = render(info).join("\n");
    expect(text).toContain("Reason:");
    expect(text).toContain("ask floor");
    expect(text).toContain("ls /home/shaun/code/pi-decision");
  });

  it("wraps long arguments within the box width", () => {
    const long: GatePromptInfo = { ...info, argsSummary: "x".repeat(400) };
    const lines = render(long, 80);
    const body = lines.slice(1, -1);
    expect(body.length).toBeGreaterThan(5);
    for (const line of body) {
      // visible width: each body line is │ + space + W + space + │ within the 80-char frame
      expect(line.length).toBeLessThanOrEqual(84 + 40); // ANSI tags inflate; strip them:
    }
    const stripped = body.map((l) => l.replace(/<[^>]+>/g, ""));
    for (const line of stripped) expect(line.length).toBeLessThanOrEqual(84);
  });

  it("maps keys to decisions, ignores everything else, and settles once", () => {
    const outcomes: string[] = [];
    const factory = createGatePrompt(info);
    const component = factory({} as any, theme, {} as any, (r) => outcomes.push(r));
    component.handleInput?.("x");
    component.handleInput?.("\x1b[A"); // arrow key
    component.handleInput?.("s"); // no longer an option
    component.handleInput?.("y"); // no longer an option
    expect(outcomes).toEqual([]);
    component.handleInput?.("a");
    component.handleInput?.("n"); // settled already
    expect(outcomes).toEqual(["allow"]);
  });

  it("shows the model's probability distribution alongside the classification", () => {
    const text = render({ ...info, probabilities: { safe: 0.8, unsafe: 0.15, unsure: 0.05 } }).join("\n");
    expect(text).toContain("Probabilities: safe 0.80 · unsafe 0.15 · unsure 0.05");
    // no probabilities (or empty) — no line
    expect(render(info).join("\n")).not.toContain("Probabilities:");
    expect(render({ ...info, probabilities: {} }).join("\n")).not.toContain("Probabilities:");
  });

  it("renders a jury as one colored verdict row plus a dim probabilities row per endpoint", () => {
    const text = render({
      ...info,
      jury: [
        { name: "hermes", choice: "safe", confidence: 0.9, probabilities: { safe: 0.9, unsafe: 0.05, unsure: 0.05 } },
        { name: "minerva", choice: "unsafe", confidence: 0.71, probabilities: { safe: 0.2, unsafe: 0.71, unsure: 0.09 } },
        { name: "athena", choice: "unavailable", error: "connection refused" },
      ],
    }).join("\n");
    // rows are padded before coloring, so only the opening tag position is exact
    expect(text).toContain("<success>hermes: safe 0.90");
    expect(text).toContain("<error>minerva: unsafe 0.71");
    expect(text).toContain("<warning>athena: unavailable");
    // the distributions ride under each verdict, dimmed
    expect(text).toContain("<dim>  safe 0.90 · unsafe 0.05 · unsure 0.05");
    // no single-endpoint probabilities line in jury mode
    expect(text).not.toContain("Probabilities:");
  });

  it("a jury row wider than the box truncates without breaking the border", () => {
    const lines = render({
      ...info,
      jury: [{ name: "a-very-long-endpoint-name-that-exceeds-the-box-width-somehow", choice: "safe", confidence: 0.9 }],
    }, 40).map((l) => l.replace(/<[^>]+>/g, ""));
    const widths = new Set(lines.map((l) => l.length));
    expect(widths.size).toBe(1);
  });

  it("esc denies and n denies", () => {
    for (const [key, expected] of [
      ["\x1b", "deny"],
      ["n", "deny"],
    ] as const) {
      const outcomes: string[] = [];
      const factory = createGatePrompt(info);
      factory({} as any, theme, {} as any, (r) => outcomes.push(r)).handleInput?.(key);
      expect(outcomes).toEqual([expected]);
    }
  });

  it("all border rows are the same visible width", () => {
    const lines = render(info, 80).map((l) => l.replace(/<[^>]+>/g, ""));
    const widths = new Set(lines.map((l) => l.length));
    expect(widths.size).toBe(1);
  });
});
