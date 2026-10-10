import { describe, expect, it } from "vitest";
import { createGate, type Decision, type GateDeps } from "./decision.js";
import { DEFAULT_CONFIG, type GatekeeperConfig } from "./config.js";
import type { ClassificationResult } from "./classifier.js";
import type { SecretsHit } from "./secrets.js";

const HOME = "/home/op";

function makeDeps(overrides: {
  config?: Partial<GatekeeperConfig>;
  classify?: (input: any, endpoint: any) => Promise<ClassificationResult>;
  askOperator?: (prompt: any) => Promise<"allow" | "deny" | "no-ui">;
  scanSecrets?: (tool: string, args: any) => Promise<SecretsHit | undefined>;
} = {}): { deps: GateDeps; log: any[]; notified: string[]; classifyCalls: any[]; asked: any[] } {
  const log: any[] = [];
  const notified: string[] = [];
  const classifyCalls: any[] = [];
  const asked: any[] = [];
  const deps: GateDeps = {
    home: HOME,
    getConfig: () => ({ ...structuredClone(DEFAULT_CONFIG), ...overrides.config }),
    classify: async (input, endpoint) => {
      classifyCalls.push({ input, endpoint });
      return (
        overrides.classify?.(input, endpoint) ?? {
          choice: "safe",
          probabilities: { safe: 0.99, unsafe: 0.005, unsure: 0.005 },
          confidence: 0.98,
        }
      );
    },
    askOperator: async (prompt) => {
      asked.push(prompt);
      return overrides.askOperator?.(prompt) ?? "deny";
    },
    notify: (line) => notified.push(line),
    writeLog: (record) => log.push(record),
    scanSecrets: async (tool, args) => overrides.scanSecrets?.(tool, args),
  };
  return { deps, log, notified, classifyCalls, asked };
}

function classifyResult(choice: "safe" | "unsafe" | "unsure", confidence: number): ClassificationResult {
  return { choice, probabilities: { safe: choice === "safe" ? confidence : 0.01, unsafe: choice === "unsafe" ? confidence : 0.01, unsure: choice === "unsure" ? confidence : 0.01 }, confidence };
}

describe("the gate", () => {
  it("passes through when disabled but still notifies and logs (transparency)", async () => {
    const { deps, log, notified } = makeDeps({ config: { enabled: false } });
    const gate = createGate(deps);
    const decision = await gate.decide({ tool: "bash", args: { command: "rm -rf /" }, task: "clean up" });
    expect(decision.action).toBe("allow");
    expect(decision.source).toBe("disabled");
    expect(log).toHaveLength(1);
    expect(log[0].source).toBe("disabled");
    expect(notified).toHaveLength(1);
    expect(notified[0]).toContain("disabled");
  });

  it("notify summary suppresses allow notifications but keeps blocks/asks", async () => {
    const { deps, notified } = makeDeps({
      config: { notify: "summary" },
      classify: async () => classifyResult("safe", 0.9),
    });
    const gate = createGate(deps);
    const allowed = await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
    expect(allowed.action).toBe("allow");
    expect(notified).toHaveLength(0);

    const askedDeps = makeDeps({
      config: { notify: "summary" },
      classify: async () => classifyResult("safe", 0.6),
      askOperator: async () => "deny",
    });
    const askedGate = createGate(askedDeps.deps);
    const asked = await askedGate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
    expect(asked.action).toBe("block");
    expect(asked.source).toBe("operator");
    expect(askedDeps.notified.length).toBeGreaterThan(0);
  });

  it("notify off suppresses all decision notifications but still logs", async () => {
    const { deps, log, notified } = makeDeps({
      config: { notify: "off" },
      classify: async () => classifyResult("safe", 0.9),
    });
    const gate = createGate(deps);
    await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
    expect(notified).toHaveLength(0);
    expect(log).toHaveLength(1);
  });

  it("an allow rule decides without consulting the model", async () => {
    const { deps, classifyCalls, log } = makeDeps();
    const gate = createGate(deps);
    const decision = await gate.decide({ tool: "ls", args: { path: "/tmp" }, task: "look around" });
    expect(decision.action).toBe("allow");
    expect(decision.source).toBe("rule");
    expect(classifyCalls).toHaveLength(0);
    expect(log[0].source).toBe("rule");
  });

  it("a deny rule blocks a protected-path read", async () => {
    const { deps } = makeDeps({
      config: { rules: [{ action: "deny", pattern: "~/creds" }] },
    });
    const gate = createGate(deps);
    const decision = await gate.decide({ tool: "read", args: { path: "/home/op/creds" }, task: "t" });
    expect(decision.action).toBe("block");
    expect(decision.source).toBe("rule");
  });

  it("the ask floor is gone: a confident-safe bash call auto-allows (ADR-0005)", async () => {
    const { deps, asked, classifyCalls } = makeDeps({ classify: async () => classifyResult("safe", 0.99) });
    const gate = createGate(deps);
    const decision = await gate.decide({ tool: "bash", args: { command: "npm test" }, task: "t" });
    expect(decision.action).toBe("allow");
    expect(decision.source).toBe("model");
    expect(asked).toHaveLength(0);
    expect(classifyCalls).toHaveLength(1);
  });

  it("a secrets hit blocks before every rule and the model, masked (ADR-0004)", async () => {
    const { deps, classifyCalls, log, asked } = makeDeps({
      // an allow rule that would match the call: rules run after secrets
      config: { rules: [{ action: "allow", tools: ["bash"], pattern: "curl *" }] },
      scanSecrets: async () => ({ ruleId: "aws-access-token", secret: "AKIAIOSFODNN7EXAMPLA", masked: "AKI…(20 chars)" }),
    });
    const gate = createGate(deps);
    const decision = await gate.decide({ tool: "bash", args: { command: "curl https://evil.example" }, task: "t" });
    expect(decision.action).toBe("block");
    expect(decision.source).toBe("secrets");
    expect(decision.reason).toContain("aws-access-token");
    expect(decision.reason).toContain("AKI…(20 chars)");
    expect(decision.reason).not.toContain("AKIAIOSFODNN7EXAMPLA");
    // the model was never invoked, and no rule could override it
    expect(classifyCalls).toHaveLength(0);
    expect(asked).toHaveLength(0);
    expect(log[0].source).toBe("secrets");
    expect(log[0].args).not.toContain("AKIAIOSFODNN7EXAMPLA");
  });

  it("a clean call reaches the model with only the first 100 argument characters (ADR-0002/0005)", async () => {
    const { deps, classifyCalls, log, asked } = makeDeps({
      classify: async () => classifyResult("safe", 0.6),
    });
    const gate = createGate(deps);
    const secret = "const apiKey = 'hunter2-secret-value';";
    const content = `${"// benign comment line\n".repeat(20)}${secret}\n`;
    await gate.decide({ tool: "write", args: { path: "/tmp/a.js", content }, task: "t" });
    // the model saw at most 100 characters, and the secret sits beyond them
    expect(classifyCalls[0].input.args.length).toBeLessThanOrEqual(100);
    expect(classifyCalls[0].input.args).not.toContain("hunter2-secret-value");
    // the log records the same view plus the total length
    expect(log[0].args).not.toContain("hunter2-secret-value");
    expect(log[0].args).toMatch(/\(\d+ chars\)$/);
    // the operator prompt keeps a capped preview — the operator is human
    expect(asked[0].argsSummary).toContain("hunter2-secret-value");
  });

  it("a secret within the first 100 characters does reach the model view — the bounded residual (ADR-0005)", async () => {
    const { deps, classifyCalls } = makeDeps({ classify: async () => classifyResult("safe", 0.6) });
    const gate = createGate(deps);
    await gate.decide({ tool: "write", args: { path: "/tmp/a.js", content: "token = 'hunter2-secret-value';" }, task: "t" });
    // the truncation bounds exposure; secret-bearing calls are blocked by
    // secrets detection (ADR-0004) before the model — when the corpus does
    // not recognize the shape, this residual is the accepted cost
    expect(classifyCalls[0].input.args.length).toBeLessThanOrEqual(100);
    expect(classifyCalls[0].input.args).toContain("hunter2-secret-value");
  });

  it("state carries only the tool, truncated arguments, task, cwd, and protected paths", async () => {
    const { deps, classifyCalls } = makeDeps({
      config: { rules: [{ action: "deny", pattern: "~/creds" }] },
    });
    const gate = createGate(deps);
    await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "read the file" });
    const state = classifyCalls[0].input;
    expect(Object.keys(state)).toEqual(["tool", "args", "task", "cwd", "protectedPaths", "policy"]);
    // the gate's own dirs ride along as a backstop (ADR-0003)
    expect(state.protectedPaths).toContain("/home/op/.pi/agent/gate");
    expect(state.protectedPaths).toContain("~/creds");
    expect(state.args).toContain("/tmp/a");
  });

  it("the model state carries the session's gate dirs and working directory", async () => {
    const { deps, classifyCalls } = makeDeps({ classify: async () => classifyResult("safe", 0.9) });
    const gate = createGate(deps);
    await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t", cwd: "/proj" });
    expect(classifyCalls[0].input.protectedPaths).toContain("/home/op/.pi/agent/gate");
    expect(classifyCalls[0].input.protectedPaths).toContain("/proj/.pi/gate");
    // the working directory rides along so "outside the project" judgments
    // are decidable against something the model can see
    expect(classifyCalls[0].input.cwd).toBe("/proj");
  });

  it("a safe classification at or above threshold auto-allows", async () => {
    const { deps, notified } = makeDeps({ classify: async () => classifyResult("safe", 0.9) });
    const gate = createGate(deps);
    const decision = await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
    expect(decision.action).toBe("allow");
    expect(decision.source).toBe("model");
    expect(notified[0]).toContain("read");
    expect(notified[0]).toContain("safe");
    expect(notified[0]).toContain("allow");
  });

  it("auto-allow requires a negligible unsafe probability: a safe above threshold with unsafe 0.2 asks", async () => {
    const { deps, asked } = makeDeps({
      classify: async () => ({ choice: "safe", probabilities: { safe: 0.8, unsafe: 0.2, unsure: 0.0 }, confidence: 0.8 }),
      askOperator: async () => "deny",
    });
    const gate = createGate(deps);
    const decision = await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
    expect(asked[0].reason).toContain("unsafe probability 0.20 above the auto-allow bound 0.15");
    expect(decision.action).toBe("block");
    expect(decision.source).toBe("operator");
  });

  it("the bound is inclusive: a safe with unsafe probability exactly 0.15 auto-allows", async () => {
    const { deps, asked } = makeDeps({
      classify: async () => ({ choice: "safe", probabilities: { safe: 0.85, unsafe: 0.15, unsure: 0.0 }, confidence: 0.9 }),
    });
    const gate = createGate(deps);
    const decision = await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
    expect(decision.action).toBe("allow");
    expect(decision.source).toBe("model");
    expect(asked).toHaveLength(0);
  });

  it("an answer without probabilities never auto-allows (fail-closed to the operator)", async () => {
    const { deps, asked } = makeDeps({
      classify: async () => ({ choice: "safe", probabilities: {}, confidence: 0.99 }),
      askOperator: async () => "deny",
    });
    const gate = createGate(deps);
    const decision = await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
    expect(asked[0].reason).toContain("unsafe probability 1.00 above the auto-allow bound 0.1");
    expect(decision.action).toBe("block");
    expect(decision.source).toBe("operator");
  });

  describe("the endpoint jury (ADR-0006)", () => {
    const twoEndpoints = {
      endpoints: [
        { name: "hermes", url: "http://a/v1/systemone", model: "m1", timeoutMs: 1000, keepAlive: "" },
        { name: "minerva", url: "http://b/v1/systemone", model: "m2", timeoutMs: 1000, keepAlive: "" },
      ],
    };

    function juryDeps(classify: (input: any, endpoint: any) => Promise<ClassificationResult>, overrides: any = {}) {
      return makeDeps({
        ...overrides,
        config: { ...twoEndpoints, multiEndpointMode: "jury", ...overrides.config },
        classify: async (input, endpoint) => classify(input, endpoint),
      });
    }

    it("classifies against every endpoint in parallel and waits for all", async () => {
      const started: string[] = [];
      const finished: string[] = [];
      const { deps, classifyCalls } = juryDeps(async (_input, endpoint) => {
        started.push(endpoint.name);
        await new Promise((r) => setTimeout(r, 30));
        finished.push(endpoint.name);
        return classifyResult("safe", 0.9);
      });
      const gate = createGate(deps);
      const decision = await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
      expect(classifyCalls).toHaveLength(2);
      // both start before either finishes — parallel, not sequential
      expect(started).toEqual(["hermes", "minerva"]);
      expect(finished).toEqual(["hermes", "minerva"]);
      expect(decision.action).toBe("allow");
      expect(decision.source).toBe("model");
    });

    it("unanimous confident safe auto-allows and logs the per-endpoint verdicts", async () => {
      const { deps, log } = juryDeps(async (_input, endpoint) =>
        endpoint.name === "hermes" ? classifyResult("safe", 0.9) : classifyResult("safe", 0.8));
      const gate = createGate(deps);
      const decision = await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
      expect(decision.action).toBe("allow");
      expect(decision.reason).toContain("weakest confidence 0.80");
      expect(log[0].jury).toEqual([
        { name: "hermes", choice: "safe", confidence: 0.9, probabilities: expect.anything() },
        { name: "minerva", choice: "safe", confidence: 0.8, probabilities: expect.anything() },
      ]);
    });

    it("one confident unsafe veto blocks even when the others say safe", async () => {
      const { deps } = juryDeps(async (_input, endpoint) =>
        endpoint.name === "hermes" ? classifyResult("safe", 0.9) : classifyResult("unsafe", 0.71));
      const gate = createGate(deps);
      const decision = await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
      expect(decision.action).toBe("block");
      expect(decision.source).toBe("model");
      expect(decision.reason).toBe("minerva classified unsafe (0.71)");
    });

    it("a safe failing the bound on one endpoint asks, naming the objection", async () => {
      const { deps, asked } = juryDeps(async (_input, endpoint) =>
        endpoint.name === "hermes"
          ? classifyResult("safe", 0.9)
          : { choice: "safe", probabilities: { safe: 0.75, unsafe: 0.25, unsure: 0.0 }, confidence: 0.8 },
      { askOperator: async () => "deny" });
      const gate = createGate(deps);
      const decision = await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
      expect(asked[0].jury).toHaveLength(2);
      expect(asked[0].reason).toContain("minerva: unsafe probability 0.25 above the auto-allow bound 0.15");
      expect(decision.action).toBe("block");
    });

    it("an unavailable endpoint is pessimistic: asks under failMode ask", async () => {
      const { deps, asked } = juryDeps(async (_input, endpoint) => {
        if (endpoint.name === "minerva") throw new Error("connection refused");
        return classifyResult("safe", 0.9);
      }, { askOperator: async () => "deny" });
      const gate = createGate(deps);
      const decision = await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
      expect(asked[0].reason).toContain("minerva: unavailable (connection refused)");
      expect(asked[0].jury?.[1].choice).toBe("unavailable");
      expect(decision.source).toBe("fail");
    });

    it("an unavailable endpoint blocks outright under failMode block", async () => {
      const { deps } = juryDeps(async (_input, endpoint) => {
        if (endpoint.name === "minerva") throw new Error("connection refused");
        return classifyResult("safe", 0.9);
      }, { config: { failMode: "block" } });
      const gate = createGate(deps);
      const decision = await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
      expect(decision.action).toBe("block");
      expect(decision.source).toBe("fail");
      expect(decision.reason).toContain("minerva: unavailable");
    });

    it("the transparency line tags the jury and lists every verdict (ADR-0007)", async () => {
      const { deps, notified } = juryDeps(async (_input, endpoint) => classifyResult("safe", 0.9));
      const gate = createGate(deps);
      await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
      expect(notified[0]).toContain("[jury] read: safe (0.90) (jury: hermes safe 0.90, minerva safe 0.90) → allowed (model)");
    });

    it("a duplicate resolved name fails closed", async () => {
      const { deps } = juryDeps(async () => classifyResult("safe", 0.9), {
        config: {
          endpoints: [
            { url: "http://a/v1/systemone", model: "same", timeoutMs: 1000, keepAlive: "" },
            { url: "http://b/v1/systemone", model: "same", timeoutMs: 1000, keepAlive: "" },
          ],
        },
      });
      const gate = createGate(deps);
      const decision = await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
      expect(decision.action).toBe("block");
      expect(decision.source).toBe("fail");
      expect(decision.reason).toContain("gate config error");
      expect(decision.reason).toContain("duplicate endpoint name");
    });

    it("a config error refuses outright — the operator is never asked (ADR-0007)", async () => {
      const { deps, asked } = juryDeps(async () => classifyResult("safe", 0.9), {
        config: { multiEndpointMode: "juryy" as never },
        // a willing operator must still not get the call through
        askOperator: async () => "allow",
      });
      const gate = createGate(deps);
      const decision = await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
      expect(decision.action).toBe("block");
      expect(decision.source).toBe("fail");
      expect(decision.reason).toContain('invalid multiEndpointMode "juryy"');
      expect(asked).toHaveLength(0);
    });
  });

  describe("fallback mode (ADR-0007)", () => {
    const chain = {
      multiEndpointMode: "fallback" as const,
      endpoints: [
        { name: "hermes", url: "http://a/v1/systemone", model: "m1", timeoutMs: 1000, keepAlive: "" },
        { name: "minerva", url: "http://b/v1/systemone", model: "m2", timeoutMs: 1000, keepAlive: "" },
      ],
    };

    function fallbackDeps(classify: (input: any, endpoint: any) => Promise<ClassificationResult>, overrides: any = {}) {
      return makeDeps({
        ...overrides,
        config: { ...chain, ...overrides.config },
        classify: async (input, endpoint) => classify(input, endpoint),
      });
    }

    it("the first endpoint's verdict decides alone — no jury aggregation", async () => {
      const { deps, classifyCalls, notified } = fallbackDeps(async (_input, endpoint) =>
        endpoint.name === "hermes" ? classifyResult("unsafe", 0.71) : classifyResult("safe", 0.9));
      const gate = createGate(deps);
      const decision = await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
      expect(classifyCalls).toHaveLength(1); // minerva never ran
      expect(decision.action).toBe("block");
      expect(decision.reason).toBe("classified unsafe (0.71)"); // single-judge wording
      expect(notified[0]).toContain("[fallback] read: unsafe (0.71) → blocked (model) (fallback: hermes unsafe 0.71)");
    });

    it("a failed first endpoint falls back to the next; the survivor decides", async () => {
      const { deps, classifyCalls, log } = fallbackDeps(async (_input, endpoint) => {
        if (endpoint.name === "hermes") throw new Error("connection refused");
        return classifyResult("safe", 0.9);
      });
      const gate = createGate(deps);
      const decision = await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
      expect(classifyCalls.map((c: any) => c.endpoint.name)).toEqual(["hermes", "minerva"]);
      expect(decision.action).toBe("allow");
      expect(decision.source).toBe("model");
      // the log records the attempts in order: the failure, then the verdict
      expect(log[0].jury).toEqual([
        { name: "hermes", choice: "unavailable", error: "connection refused" },
        { name: "minerva", choice: "safe", confidence: 0.9, probabilities: expect.anything() },
      ]);
    });

    it("every call starts over from the first endpoint — no circuit breaker", async () => {
      const { deps, classifyCalls } = fallbackDeps(async (_input, endpoint) => {
        if (endpoint.name === "hermes") throw new Error("connection refused");
        return classifyResult("safe", 0.9);
      });
      const gate = createGate(deps);
      await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
      await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
      expect(classifyCalls.map((c: any) => c.endpoint.name)).toEqual(["hermes", "minerva", "hermes", "minerva"]);
    });

    it("a verdict-level failure does not trigger a fallback: an unsure asks (ADR-0007)", async () => {
      const { deps, classifyCalls, asked } = fallbackDeps(async () => classifyResult("unsure", 0.55), {
        askOperator: async () => "deny",
      });
      const gate = createGate(deps);
      await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
      expect(classifyCalls).toHaveLength(1); // an answer, however unsure, ends the chain
      expect(asked[0].reason).toContain("model unsure (0.55)");
    });

    it("all endpoints failed: failMode ask routes to the operator with the attempts logged", async () => {
      const { deps, classifyCalls, log, asked } = fallbackDeps(async () => {
        throw new Error("connection refused");
      }, { askOperator: async () => "deny" });
      const gate = createGate(deps);
      const decision = await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
      expect(classifyCalls).toHaveLength(2);
      expect(asked[0].reason).toContain("model unavailable: connection refused");
      expect(decision.source).toBe("fail");
      expect(log[0].jury?.map((v: any) => v.choice)).toEqual(["unavailable", "unavailable"]);
    });

    it("all endpoints failed under failMode block denies", async () => {
      const { deps, classifyCalls, asked } = fallbackDeps(async () => {
        throw new Error("connection refused");
      }, { config: { failMode: "block" } });
      const gate = createGate(deps);
      const decision = await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
      expect(classifyCalls).toHaveLength(2);
      expect(asked).toHaveLength(0);
      expect(decision.action).toBe("block");
      expect(decision.source).toBe("fail");
    });

    it("a partial chain's survivor below threshold asks with the single-judge reason", async () => {
      const { deps, asked } = fallbackDeps(async (_input, endpoint) => {
        if (endpoint.name === "hermes") throw new Error("connection refused");
        return classifyResult("safe", 0.6);
      }, { askOperator: async () => "deny" });
      const gate = createGate(deps);
      await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
      expect(asked[0].reason).toContain("confidence 0.60 below threshold 0.65");
      expect(asked[0].jury?.[0].choice).toBe("unavailable");
    });
  });

  describe("modelSelect mode (ADR-0007)", () => {
    const jury = {
      endpoints: [
        { name: "hermes", url: "http://a/v1/systemone", model: "m1", timeoutMs: 1000, keepAlive: "" },
        { name: "minerva", url: "http://b/v1/systemone", model: "m2", timeoutMs: 1000, keepAlive: "" },
      ],
    };

    function selectDeps(classify: (input: any, endpoint: any) => Promise<ClassificationResult>, overrides: any = {}) {
      return makeDeps({
        ...overrides,
        config: { ...jury, ...overrides.config },
        classify: async (input, endpoint) => classify(input, endpoint),
      });
    }

    it("without a selection the first entry serves, tagged and logged by name", async () => {
      const { deps, classifyCalls, log, notified } = selectDeps(async () => classifyResult("safe", 0.9));
      const gate = createGate(deps);
      const decision = await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
      expect(classifyCalls.map((c: any) => c.endpoint.name)).toEqual(["hermes"]);
      expect(decision.action).toBe("allow");
      expect(decision.reason).toBe("classified safe (0.90)"); // the legacy single-judge reason
      expect(log[0].endpoint).toBe("hermes");
      expect(log[0].jury).toBeUndefined(); // no verdict array for a single judge
      expect(notified[0]).toContain("[modelSelect] read: safe (0.90) hermes → allowed (model)");
    });

    it("the selection names the judge", async () => {
      const { deps, classifyCalls, log } = selectDeps(async () => classifyResult("safe", 0.9), {
        config: { selectedEndpoint: "minerva" },
      });
      const gate = createGate(deps);
      await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
      expect(classifyCalls.map((c: any) => c.endpoint.name)).toEqual(["minerva"]);
      expect(log[0].endpoint).toBe("minerva");
    });

    it("a stale selection serves the first entry and warns", async () => {
      const { deps, classifyCalls, notified } = selectDeps(async () => classifyResult("safe", 0.9), {
        config: { selectedEndpoint: "ghost" },
      });
      const gate = createGate(deps);
      await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
      expect(classifyCalls.map((c: any) => c.endpoint.name)).toEqual(["hermes"]);
      expect(notified.some((n) => n.includes('gate › selected endpoint "ghost" not found — serving "hermes" instead'))).toBe(true);
    });

    it("a failing selected endpoint stops — no silent substitution (ADR-0007)", async () => {
      const { deps, classifyCalls } = selectDeps(async (_input, endpoint) => {
        if (endpoint.name === "minerva") throw new Error("connection refused");
        return classifyResult("safe", 0.9);
      }, { config: { selectedEndpoint: "minerva", }, askOperator: async () => "deny" });
      const gate = createGate(deps);
      const decision = await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
      expect(classifyCalls).toHaveLength(1); // hermes never substituted
      expect(decision.source).toBe("fail");
    });
  });

  it("an unsafe classification at or above threshold auto-blocks", async () => {
    const { deps } = makeDeps({ classify: async () => classifyResult("unsafe", 0.97) });
    const gate = createGate(deps);
    const decision = await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
    expect(decision.action).toBe("block");
    expect(decision.source).toBe("model");
  });

  it("below-threshold classifications route to the operator with allow/deny outcomes", async () => {
    const { deps, asked } = makeDeps({
      classify: async () => classifyResult("safe", 0.6),
      askOperator: async (p) => {
        asked.push(p);
        return "allow";
      },
    });
    const gate = createGate(deps);
    const decision = await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
    expect(asked[0].confidence).toBe(0.6);
    expect(asked[0].classification).toBe("safe");
    expect(decision.action).toBe("allow");
    expect(decision.source).toBe("operator");
  });

  it("operator denies and no-UI block; nothing is cached or persisted (ADR-0005)", async () => {
    const denied = makeDeps({
      classify: async () => classifyResult("safe", 0.6),
      askOperator: async () => "deny",
    });
    const denyGate = createGate(denied.deps);
    const deniedDecision = await denyGate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
    expect(deniedDecision.action).toBe("block");
    expect(deniedDecision.source).toBe("operator");

    // a re-issued identical call classifies and asks again — no session cache
    await denyGate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
    expect(denied.classifyCalls).toHaveLength(2);
    expect(denied.asked).toHaveLength(2);

    const blocked = makeDeps({
      classify: async () => classifyResult("safe", 0.6),
      askOperator: async () => "no-ui",
    });
    const noUiGate = createGate(blocked.deps);
    const noUiDecision = await noUiGate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
    expect(noUiDecision.action).toBe("block");
    expect(noUiDecision.reason).toContain("no UI available");
  });

  it("an explicit unsure routes to the operator even at high confidence", async () => {
    const { deps } = makeDeps({
      classify: async () => classifyResult("unsure", 0.99),
      askOperator: async () => "deny",
    });
    const gate = createGate(deps);
    const decision = await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
    expect(decision.action).toBe("block");
    expect(decision.source).toBe("operator");
  });

  it("model failure with failMode ask routes to the operator with a model-unavailable reason", async () => {
    const asked: any[] = [];
    const { deps } = makeDeps({
      classify: async () => {
        throw new Error("ECONNREFUSED");
      },
      askOperator: async (p) => {
        asked.push(p);
        return "deny";
      },
    });
    const gate = createGate(deps);
    const decision = await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
    expect(asked[0].reason).toContain("model unavailable");
    expect(decision.action).toBe("block");
    expect(decision.source).toBe("fail");
    expect(decision.reason).toContain("operator denied");
  });

  it("model failure with failMode block denies (headless)", async () => {
    const { deps } = makeDeps({
      config: { failMode: "block" },
      classify: async () => {
        throw new Error("ECONNREFUSED");
      },
    });
    const gate = createGate(deps);
    const decision = await gate.decide({ tool: "read", args: { path: "/tmp/a" }, task: "t" });
    expect(decision.action).toBe("block");
    expect(decision.source).toBe("fail");
    expect(decision.reason).toContain("model unavailable");
  });

  it("self-protection: always denies agent writes to the config, even while disabled with an allow rule", async () => {
    const { deps } = makeDeps({
      config: {
        enabled: false,
        rules: [{ action: "allow", tools: ["write"], pattern: "~/.pi/agent/gate/**" }],
      },
    });
    const gate = createGate(deps);
    const decision = await gate.decide({
      tool: "write",
      args: { path: "/home/op/.pi/agent/gate/config.json", content: "{}" },
      task: "neuter the gate",
    });
    expect(decision.action).toBe("block");
    expect(decision.source).toBe("protected");
    // but ordinary calls pass through ungated when disabled
    const passthrough = await gate.decide({ tool: "bash", args: { command: "rm -rf /tmp/x" }, task: "t" });
    expect(passthrough.action).toBe("allow");
    expect(passthrough.source).toBe("disabled");
  });

  it("self-protection: paths merely containing similar text pass through", async () => {
    const { deps } = makeDeps({ classify: async () => classifyResult("safe", 0.99) });
    const gate = createGate(deps);
    const decision = await gate.decide({ tool: "read", args: { path: "/home/op/notes.pi/gatekeeper/x.md" }, task: "t" });
    expect(decision.action).toBe("allow");
    expect(decision.source).toBe("model");
  });
});
