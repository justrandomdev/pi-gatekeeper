import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, stat, utimes, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createGatekeeper } from "./index.js";
import { visibleWidth } from "@earendil-works/pi-tui";

const HOME = "/home/op";
const bundledSnapshot = join(dirname(fileURLToPath(import.meta.url)), "../gitleaks.toml");

let userHome: string; // stand-in home for config/log paths
let projectDir: string;

beforeEach(async () => {
  userHome = await mkdtemp(join(tmpdir(), "gk-home-"));
  projectDir = await mkdtemp(join(tmpdir(), "gk-proj-"));
  // autoUpdate off by default: the extension tests stay offline and
  // deterministic (the updater has its own fetch-stubbed tests below)
  await mkdir(join(userHome, ".pi/agent/gate"), { recursive: true });
  await writeFile(
    join(userHome, ".pi/agent/gate/config.json"),
    JSON.stringify({ secrets: { autoUpdate: false } }),
  );
});
afterEach(async () => {
  await rm(userHome, { recursive: true, force: true });
  await rm(projectDir, { recursive: true, force: true });
});

interface Captured {
  events: Map<string, ((event: any, ctx: any) => any)[]>;
  commands: Map<string, { description?: string; handler: (args: string, ctx: any) => Promise<void> }>;
}

function fakePi(): { pi: any; captured: Captured } {
  const captured: Captured = { events: new Map(), commands: new Map() };
  const pi: any = {
    on: (name: string, handler: (event: any, ctx: any) => any) => {
      if (!captured.events.has(name)) captured.events.set(name, []);
      captured.events.get(name)!.push(handler);
    },
    registerCommand: (name: string, options: any) => {
      captured.commands.set(name, options);
    },
  };
  return { pi, captured };
}

/** A stubbed System One endpoint + recording ui + fake context. */
function makeEnv(canned: { choice: "safe" | "unsafe" | "unsure"; confidence: number } = { choice: "safe", confidence: 0.99 }) {
  const requests: any[] = [];
  const fetchFn = (async (_url: string, init: RequestInit) => {
    requests.push(JSON.parse(init.body as string));
    return {
      ok: true,
      status: 200,
      json: async () => ({
        answers: {
          safety: {
            type: "choice",
            choice: canned.choice,
            probabilities: { safe: 0.01, unsafe: 0.01, unsure: 0.01, [canned.choice]: canned.confidence },
            confidence: canned.confidence,
          },
        },
      }),
    } as Response;
  }) as typeof fetch;

  const ui = {
    notified: [] as string[],
    selected: [] as { title: string; options: string[] }[],
    custom: undefined as unknown as ((factory: any) => Promise<any>) | undefined,
    notify: (message: string) => ui.notified.push(message),
    select: async (title: string, options: string[]): Promise<string | undefined> => {
      ui.selected.push({ title, options });
      return "Deny";
    },
    confirm: async () => false,
    input: async () => undefined,
  };
  const ctx = (over: Record<string, unknown> = {}) => ({
    ui,
    hasUI: true,
    cwd: projectDir,
    isProjectTrusted: () => false,
    mode: "tui",
    ...over,
  });
  return { requests, fetchFn, ui, ctx };
}

async function runToolCall(captured: Captured, env: ReturnType<typeof makeEnv>, event: any, ctxOverride: Record<string, unknown> = {}) {
  const handler = captured.events.get("tool_call")![0];
  return handler(event, env.ctx(ctxOverride));
}

async function setup(
  canned?: { choice: "safe" | "unsafe" | "unsure"; confidence: number },
  fetchOverride?: typeof fetch,
) {
  const { pi, captured } = fakePi();
  const env = makeEnv(canned);
  await createGatekeeper(pi, { home: userHome, fetchFn: fetchOverride ?? env.fetchFn });
  return { captured, env };
}

/** A fetch stub serving gitleaks TOML at the source URL, classifier JSON elsewhere. */
function makeFetch(serves: string) {
  return (async (url: string | URL | Request, init?: RequestInit) => {
    const target = String(url);
    if (target.includes("gitleaks")) {
      return { ok: true, status: 200, text: async () => serves } as Response;
    }
    return {
      ok: true,
      status: 200,
      json: async () => ({
        answers: {
          safety: {
            type: "choice",
            choice: "safe",
            probabilities: { safe: 0.9, unsafe: 0.05, unsure: 0.05 },
            confidence: 0.9,
          },
        },
      }),
    } as Response;
  }) as typeof fetch;
}

describe("gatekeeper extension", () => {
  it("registers the tool_call handler and the five commands", () => {
    const { pi, captured } = fakePi();
    createGatekeeper(pi, { home: userHome });
    expect(captured.events.has("tool_call")).toBe(true);
    expect([...captured.commands.keys()].sort()).toEqual(["gate", "gate:config", "gate:log", "gate:rules", "gate:secrets"]);
  });

  it("an allow rule passes ls through without consulting the model", async () => {
    const { captured, env } = await setup();
    const result = await runToolCall(captured, env, { type: "tool_call", toolName: "ls", input: { path: "/tmp" } });
    expect(result).toBeUndefined();
    expect(env.requests).toHaveLength(0);
  });

  it("a confident safe read auto-allows with a transparency line", async () => {
    const { captured, env } = await setup({ choice: "safe", confidence: 0.9 });
    const result = await runToolCall(captured, env, { type: "tool_call", toolName: "read", input: { path: "/tmp/a" } });
    expect(result).toBeUndefined();
    expect(env.ui.notified[0]).toContain("read");
    expect(env.ui.notified[0]).toContain("safe (0.90)");
  });

  it("a confident unsafe classification blocks with a reason", async () => {
    const { captured, env } = await setup({ choice: "unsafe", confidence: 0.97 });
    const result = await runToolCall(captured, env, { type: "tool_call", toolName: "read", input: { path: "/etc/passwd" } });
    expect(result?.block).toBe(true);
    expect(result?.reason).toContain("unsafe");
  });

  it("the ask floor is gone: a confident-safe bash call auto-allows (ADR-0005)", async () => {
    const { captured, env } = await setup({ choice: "safe", confidence: 0.99 });
    const result = await runToolCall(captured, env, { type: "tool_call", toolName: "bash", input: { command: "npm test" } });
    expect(result).toBeUndefined();
    expect(env.ui.selected).toHaveLength(0);
    expect(env.requests).toHaveLength(1);
  });

  it("a below-threshold bash call asks the operator with Allow/Deny only", async () => {
    const { captured, env } = await setup({ choice: "safe", confidence: 0.6 });
    const result = await runToolCall(captured, env, { type: "tool_call", toolName: "bash", input: { command: "ls ~/work" } });
    expect(env.ui.selected).toHaveLength(1);
    expect(env.ui.selected[0].options).toEqual(["Allow", "Deny"]);
    expect(env.ui.selected[0].title).toContain("bash");
    // the stub operator picks Deny
    expect(result?.block).toBe(true);
    expect(result?.reason).toContain("operator denied");
  });

  it("uses the custom bordered prompt when the mode provides ui.custom; y allows, nothing persists", async () => {
    const { captured, env } = await setup({ choice: "safe", confidence: 0.6 });
    let component: any;
    const ctx = env.ctx();
    ctx.ui.custom = (async (factory: any) =>
      new Promise((resolve) => {
        component = factory({}, { fg: (_c: any, t: any) => t, bold: (t: any) => t } as any, {}, resolve);
      })) as any;
    const handler = captured.events.get("tool_call")![0];
    const pending = handler({ type: "tool_call", toolName: "bash", input: { command: "ls ~/work" } }, ctx);
    await new Promise((r) => setTimeout(r, 10));
    // the component renders a bordered box
    const lines = component.render(80) as string[];
    expect(lines[0].startsWith("╭")).toBe(true);
    expect(lines[lines.length - 1].endsWith("╯")).toBe(true);
    // pressing a settles the dialog; nothing persists (ADR-0005)
    component.handleInput("a");
    const result = await pending;
    expect(result).toBeUndefined();
    expect(env.ui.selected).toHaveLength(0); // the selector was not used
    const configPath = join(userHome, ".pi/agent/gate/config.json");
    const cfg = JSON.parse(await readFile(configPath, "utf8"));
    expect(cfg.rules).toBeUndefined(); // no grant was written
  });

  describe("the endpoint jury (ADR-0006)", () => {
    /** A fetch stub keyed by host: each configured endpoint answers its
     *  own canned verdict — a disagreeing jury. */
    function juryFetch(perHost: Record<string, { choice: string; confidence: number }>) {
      return (async (_url: string | URL, init: RequestInit) => {
        const host = new URL(String(_url)).host;
        const canned = perHost[host];
        void init;
        if (!canned) throw new Error(`unexpected endpoint ${host}`);
        return {
          ok: true,
          status: 200,
          json: async () => ({
            answers: {
              safety: {
                type: "choice",
                choice: canned.choice,
                probabilities: { safe: 0.01, unsafe: 0.01, unsure: 0.01, [canned.choice]: canned.confidence },
                confidence: canned.confidence,
              },
            },
          }),
        } as Response;
      }) as typeof fetch;
    }

    async function jurySetup(endpoints: unknown[]) {
      await writeFile(
        join(userHome, ".pi/agent/gate/config.json"),
        JSON.stringify({ secrets: { autoUpdate: false }, multiEndpointMode: "jury", endpoints }),
      );
    }

    const twoEndpoints = [
      { name: "hermes", url: "http://a.example/v1/systemone", model: "m1", timeoutMs: 5000, keepAlive: "" },
      { name: "minerva", url: "http://b.example/v1/systemone", model: "m2", timeoutMs: 5000, keepAlive: "" },
    ];

    it("both endpoints classify in parallel and the pessimistic verdict wins", async () => {
      const { pi, captured } = fakePi();
      const env = makeEnv();
      const fetchFn = juryFetch({ "a.example": { choice: "safe", confidence: 0.9 }, "b.example": { choice: "unsafe", confidence: 0.71 } });
      await createGatekeeper(pi, { home: userHome, fetchFn });
      await jurySetup(twoEndpoints);
      const result = await runToolCall(captured, env, { type: "tool_call", toolName: "bash", input: { command: "ls ~/work" } });
      // auto-blocked by minerva's confident unsafe — no operator prompt
      expect(result?.block).toBe(true);
      expect(result?.reason).toContain("minerva classified unsafe (0.71)");
      expect(env.ui.selected).toHaveLength(0);
    });

    it("the operator prompt shows a jury row per endpoint", async () => {
      const { pi, captured } = fakePi();
      const env = makeEnv();
      const fetchFn = juryFetch({ "a.example": { choice: "safe", confidence: 0.9 }, "b.example": { choice: "unsure", confidence: 0.55 } });
      await createGatekeeper(pi, { home: userHome, fetchFn });
      await jurySetup(twoEndpoints);
      let component: any;
      const ctx = env.ctx();
      ctx.ui.custom = (async (factory: any) =>
        new Promise((resolve) => {
          component = factory({}, { fg: (_c: any, t: any) => t, bold: (t: any) => t } as any, {}, resolve);
        })) as any;
      const pending = captured.events.get("tool_call")![0]({ type: "tool_call", toolName: "bash", input: { command: "ls ~/work" } }, ctx);
      await new Promise((r) => setTimeout(r, 10));
      const text = (component.render(80) as string[]).join("\n");
      expect(text).toContain("hermes: safe 0.90");
      expect(text).toContain("minerva: unsure 0.55");
      expect(text).toContain("Classification: unsure (0.55)");
      component.handleInput("n");
      const result = await pending;
      expect(result?.block).toBe(true);
    });

    it("/gate:config test fans the sample call out and lists every verdict", async () => {
      const { pi, captured } = fakePi();
      const env = makeEnv();
      const fetchFn = juryFetch({ "a.example": { choice: "safe", confidence: 0.9 }, "b.example": { choice: "unsafe", confidence: 0.4 } });
      await createGatekeeper(pi, { home: userHome, fetchFn });
      await jurySetup(twoEndpoints);
      const handler = captured.commands.get("gate:config")!.handler;
      await handler(`test bash '{"command":"ls /tmp"}'`, env.ctx());
      const line = env.ui.notified.find((n) => n.includes("jury test for bash"));
      expect(line).toContain("hermes: safe 0.90");
      expect(line).toContain("minerva: unsafe 0.40");
    });
  });

  describe("multi-endpoint modes (ADR-0007)", () => {
    const twoEndpoints = [
      { name: "hermes", url: "http://a.example/v1/systemone", model: "m1", timeoutMs: 5000, keepAlive: "" },
      { name: "minerva", url: "http://b.example/v1/systemone", model: "m2", timeoutMs: 5000, keepAlive: "" },
    ];

    // The gate hot-reloads on mtime change; two writes can land in the
    // same clock tick, so each write stamps a distinct mtime explicitly.
    let tick = Date.now();
    async function writeConfig(patch: Record<string, unknown>) {
      await writeFile(
        join(userHome, ".pi/agent/gate/config.json"),
        JSON.stringify({ secrets: { autoUpdate: false }, ...patch }),
      );
      const when = new Date(++tick);
      await utimes(join(userHome, ".pi/agent/gate/config.json"), when, when);
    }

    it("with an endpoints array and no mode, only the first endpoint runs (the deliberate break)", async () => {
      const { pi, captured } = fakePi();
      const env = makeEnv();
      await createGatekeeper(pi, { home: userHome, fetchFn: env.fetchFn });
      await writeConfig({ endpoints: twoEndpoints });
      const result = await runToolCall(captured, env, { type: "tool_call", toolName: "bash", input: { command: "ls ~/work" } });
      expect(result).toBeUndefined(); // allowed
      expect(env.requests).toHaveLength(1); // hermes alone — minerva never ran
    });

    it("gate:config set validates multiEndpointMode and selectedEndpoint", async () => {
      const { pi, captured } = fakePi();
      const env = makeEnv();
      createGatekeeper(pi, { home: userHome, fetchFn: env.fetchFn });
      const handler = captured.commands.get("gate:config")!.handler;
      await handler("set multiEndpointMode jury", env.ctx());
      await handler("set multiEndpointMode juryy", env.ctx()); // rejected, never written
      await handler("set selectedEndpoint hermes", env.ctx());
      const cfg = JSON.parse(await readFile(join(userHome, ".pi/agent/gate/config.json"), "utf8"));
      expect(cfg.multiEndpointMode).toBe("jury");
      expect(cfg.selectedEndpoint).toBe("hermes");
      expect(env.ui.notified.some((n) => n.includes('must be one of "jury", "fallback", "modelSelect"'))).toBe(true);
    });

    it("/gate model <name> selects and persists; an unknown name warns; /gate model lists", async () => {
      const { pi, captured } = fakePi();
      const env = makeEnv();
      createGatekeeper(pi, { home: userHome, fetchFn: env.fetchFn });
      await writeConfig({ multiEndpointMode: "modelSelect", endpoints: twoEndpoints });
      const handler = captured.commands.get("gate")!.handler;

      await handler("model minerva", env.ctx());
      expect(JSON.parse(await readFile(join(userHome, ".pi/agent/gate/config.json"), "utf8")).selectedEndpoint)
        .toBe("minerva");

      await handler("model ghost", env.ctx());
      expect(env.ui.notified.some((n) => n.includes('no endpoint named "ghost"'))).toBe(true);

      await handler("model", env.ctx());
      const listing = env.ui.notified.find((n) => n.includes("serving: minerva"));
      expect(listing).toContain("hermes @ http://a.example/v1/systemone");
      expect(listing).toContain("minerva @ http://b.example/v1/systemone");
    });

    it("/gate status shows the mode line only for multi-endpoint configs", async () => {
      const { pi, captured } = fakePi();
      const env = makeEnv();
      createGatekeeper(pi, { home: userHome, fetchFn: env.fetchFn });
      const handler = captured.commands.get("gate")!.handler;

      await handler("model minerva", env.ctx());
      expect(env.ui.notified.some((n) => n.includes("Mode: "))).toBe(false); // single endpoint: no mode

      await writeConfig({ multiEndpointMode: "fallback", endpoints: twoEndpoints });
      await handler("", env.ctx());
      expect(env.ui.notified.some((n) => n.includes("Mode: fallback › first-hit"))).toBe(true);

      await writeConfig({ multiEndpointMode: "juryy", endpoints: twoEndpoints });
      await handler("", env.ctx());
      expect(env.ui.notified.some((n) => n.includes("Mode: invalid multiEndpointMode"))).toBe(true);
    });
  });

  it("gate:rules rm removes exactly the listed rule and preserves the rest", async () => {
    const { pi, captured } = fakePi();
    const env = makeEnv();
    createGatekeeper(pi, { home: userHome, fetchFn: env.fetchFn });
    await mkdir(join(userHome, ".pi/agent/gate"), { recursive: true });
    await writeFile(
      join(userHome, ".pi/agent/gate/config.json"),
      JSON.stringify({
        rules: [
          { action: "deny", pattern: "~/creds" },
          { action: "allow", tools: ["bash"], pattern: "ls ?*" },
        ],
      }),
    );
    const handler = captured.commands.get("gate:rules")!.handler;
    const ctx = env.ctx();
    await handler("rm u1", ctx);
    const after = JSON.parse(await readFile(join(userHome, ".pi/agent/gate/config.json"), "utf8"));
    expect(after.rules).toEqual([{ action: "allow", tools: ["bash"], pattern: "ls ?*" }]);
    // removing a rule that does not exist reports and changes nothing
    await handler("rm u9", ctx);
    expect(env.ui.notified.some((n) => n.includes("no rule"))).toBe(true);
    const unchanged = JSON.parse(await readFile(join(userHome, ".pi/agent/gate/config.json"), "utf8"));
    expect(unchanged.rules).toEqual([{ action: "allow", tools: ["bash"], pattern: "ls ?*" }]);
  });

  it("a dismissed operator dialog denies", async () => {
    const { captured, env } = await setup({ choice: "safe", confidence: 0.6 });
    env.ui.select = async (): Promise<string | undefined> => undefined;
    const result = await runToolCall(captured, env, { type: "tool_call", toolName: "bash", input: { command: "ls" } });
    expect(result?.block).toBe(true);
  });

  it("model failure routes to the operator with a model-unavailable reason", async () => {
    const failing = (async () => {
      throw new Error("ECONNREFUSED");
    }) as typeof fetch;
    const { captured, env } = await setup(undefined, failing);
    const result = await runToolCall(captured, env, { type: "tool_call", toolName: "read", input: { path: "/tmp/a" } });
    expect(env.ui.selected).toHaveLength(1);
    expect(result?.block).toBe(true);
    expect(result?.reason).toContain("model unavailable");
  });

  it("the current task and working directory from the session ride in the model state", async () => {
    const { captured, env } = await setup({ choice: "safe", confidence: 0.9 });
    const startHandler = captured.events.get("before_agent_start")![0];
    startHandler({ type: "before_agent_start", prompt: "clean up the tmp folder" }, env.ctx());
    await runToolCall(captured, env, { type: "tool_call", toolName: "read", input: { path: "/tmp/a" } });
    expect(env.requests[0].state.task).toBe("clean up the tmp folder");
    expect(env.requests[0].state.cwd).toBe(projectDir);
  });

  it("every decision lands in the JSONL decision log", async () => {
    const { captured, env } = await setup({ choice: "safe", confidence: 0.9 });
    await runToolCall(captured, env, { type: "tool_call", toolName: "read", input: { path: "/tmp/a" } });
    const logPath = join(userHome, ".pi/agent/gate/decisions.jsonl");
    // the log write is fire-and-forget; poll until it lands
    let lines: string[] = [];
    for (let i = 0; i < 50 && lines.length < 1; i++) {
      try {
        lines = (await readFile(logPath, "utf8")).trim().split("\n").filter(Boolean);
      } catch {
        await new Promise((r) => setTimeout(r, 20));
      }
    }
    if (!lines.length) lines = ["(log never flushed)"];
    expect(lines).toHaveLength(1);
    const record = JSON.parse(lines[0]);
    expect(record.tool).toBe("read");
    expect(record.action).toBe("allow");
    expect(record.source).toBe("model");
    expect(record.ts).toBeTruthy();
  });

  it("a user-level deny rule blocks a protected read without the model", async () => {
    await mkdir(join(userHome, ".pi/agent/gate"), { recursive: true });
    await writeFile(
      join(userHome, ".pi/agent/gate/config.json"),
      JSON.stringify({ rules: [{ action: "deny", pattern: "~/creds" }] }),
    );
    const { captured, env } = await setup();
    const result = await runToolCall(captured, env, { type: "tool_call", toolName: "read", input: { path: join(userHome, "creds") } });
    expect(result?.block).toBe(true);
    expect(result?.reason).toContain("deny rule");
    expect(env.requests).toHaveLength(0);
  });

  it("project config overrides the user deny (ADR-0001), trusted projects only", async () => {
    await mkdir(join(userHome, ".pi/agent/gate"), { recursive: true });
    await writeFile(
      join(userHome, ".pi/agent/gate/config.json"),
      JSON.stringify({ rules: [{ action: "deny", pattern: "~/creds" }] }),
    );
    await mkdir(join(projectDir, ".pi/gate"), { recursive: true });
    await writeFile(
      join(projectDir, ".pi/gate/config.json"),
      JSON.stringify({ rules: [{ action: "allow", tools: ["read"], pattern: "~/creds" }] }),
    );
    const { captured, env } = await setup({ choice: "safe", confidence: 0.9 });

    // untrusted project: the user deny stands
    const denied = await runToolCall(captured, env, { type: "tool_call", toolName: "read", input: { path: join(userHome, "creds") } });
    expect(denied?.block).toBe(true);

    // trusted project: the project allow overrides the user deny
    const allowed = await runToolCall(captured, env, { type: "tool_call", toolName: "read", input: { path: join(userHome, "creds") } }, { isProjectTrusted: () => true });
    expect(allowed).toBeUndefined();
  });

  it("set endpoint.apiKey redacts the value in the notify so the secret doesn't leak", async () => {
    const { pi, captured } = fakePi();
    const env = makeEnv();
    createGatekeeper(pi, { home: userHome, fetchFn: env.fetchFn });
    const handler = captured.commands.get("gate:config")!.handler;
    const ctx = env.ctx();
    await handler("set endpoint.apiKey super-secret-token", ctx);
    // the value must not appear in any notify
    expect(env.ui.notified.some((n) => n.includes("super-secret-token"))).toBe(false);
    // ...but it does appear as "***" in the success line
    expect(env.ui.notified.some((n) => n.includes("endpoint.apiKey = ***"))).toBe(true);
    // ...and the actual value landed in the config file
    const cfg = JSON.parse(await readFile(join(userHome, ".pi/agent/gate/config.json"), "utf8"));
    expect(cfg.endpoint.apiKey).toBe("super-secret-token");
  });

  it("set log.maxLines / log.keepFiles / log.retentionDays / log.truncateArgsBytes and stateBudgetChars actually write", async () => {
    const { pi, captured } = fakePi();
    const env = makeEnv();
    createGatekeeper(pi, { home: userHome, fetchFn: env.fetchFn });
    const handler = captured.commands.get("gate:config")!.handler;
    const ctx = env.ctx();
    for (const args of [
      "set log.maxLines 5000",
      "set log.keepFiles 5",
      "set log.retentionDays 7",
      "set log.truncateArgsBytes 1024",
      "set stateBudgetChars 2000",
    ]) {
      await handler(args, ctx);
    }
    const cfg = JSON.parse(await readFile(join(userHome, ".pi/agent/gate/config.json"), "utf8"));
    expect(cfg.log.maxLines).toBe(5000);
    expect(cfg.log.keepFiles).toBe(5);
    expect(cfg.log.retentionDays).toBe(7);
    expect(cfg.log.truncateArgsBytes).toBe(1024);
    expect(cfg.stateBudgetChars).toBe(2000);
    // and not as stray top-level dotted keys (the bug we fixed)
    expect(cfg["log.maxLines"]).toBeUndefined();
    expect(cfg["log.keepFiles"]).toBeUndefined();
    expect(cfg["log.retentionDays"]).toBeUndefined();
    expect(cfg["log.truncateArgsBytes"]).toBeUndefined();
  });

  it("set log.level rejects values that are not user|project", async () => {
    const { pi, captured } = fakePi();
    const env = makeEnv();
    createGatekeeper(pi, { home: userHome, fetchFn: env.fetchFn });
    const handler = captured.commands.get("gate:config")!.handler;
    const ctx = env.ctx();
    await handler("set log.level foo", ctx);
    expect(env.ui.notified.some((n) => n.includes("must be"))).toBe(true);
  });

  it("--project writes are blocked when project trust is not granted", async () => {
    const { pi, captured } = fakePi();
    const env = makeEnv();
    createGatekeeper(pi, { home: userHome, fetchFn: env.fetchFn });
    const handler = captured.commands.get("gate:rules")!.handler;
    const ctx = env.ctx(); // isProjectTrusted: () => false
    await handler("add deny \"~/test\" --project", ctx);
    // the project file should not exist
    const projectCfg = join(projectDir, ".pi/gate/config.json");
    let exists = true;
    try {
      await stat(projectCfg);
    } catch {
      exists = false;
    }
    expect(exists).toBe(false);
    // ...and the operator was warned
    expect(env.ui.notified.some((n) => n.includes("project trust"))).toBe(true);
  });

  it("add allow '*' warns and requires explicit confirmation; aborts without it", async () => {
    const { pi, captured } = fakePi();
    const env = makeEnv();
    createGatekeeper(pi, { home: userHome, fetchFn: env.fetchFn });
    const handler = captured.commands.get("gate:rules")!.handler;
    const ctx = env.ctx();
    ctx.ui.confirm = async (): Promise<boolean> => false; // operator declines
    await handler("add allow \"*\"", ctx);
    const cfgPath = join(userHome, ".pi/agent/gate/config.json");
    let wroteRule = false;
    try {
      const cfg = JSON.parse(await readFile(cfgPath, "utf8"));
      wroteRule = (cfg.rules ?? []).some((r: any) => r.pattern === "*");
    } catch {
      // no file at all — also fine
    }
    expect(wroteRule).toBe(false);
    expect(env.ui.notified.some((n) => n.includes("aborted"))).toBe(true);
  });

  it("add allow '*' with confirm=true writes the wide-open rule", async () => {
    const { pi, captured } = fakePi();
    const env = makeEnv();
    createGatekeeper(pi, { home: userHome, fetchFn: env.fetchFn });
    const handler = captured.commands.get("gate:rules")!.handler;
    const ctx = env.ctx();
    ctx.ui.confirm = async (): Promise<boolean> => true; // operator confirms
    await handler("add allow \"*\"", ctx);
    const cfg = JSON.parse(await readFile(join(userHome, ".pi/agent/gate/config.json"), "utf8"));
    expect(cfg.rules).toContainEqual({ action: "allow", pattern: "*" });
  });

  it("a quoted multi-token pattern arrives whole: add allow \"ls ?*\" --tool bash", async () => {
    const { pi, captured } = fakePi();
    const env = makeEnv();
    createGatekeeper(pi, { home: userHome, fetchFn: env.fetchFn });
    const handler = captured.commands.get("gate:rules")!.handler;
    await handler('add allow "ls ?*" --tool bash', env.ctx());
    const cfg = JSON.parse(await readFile(join(userHome, ".pi/agent/gate/config.json"), "utf8"));
    expect(cfg.rules).toContainEqual({ action: "allow", tools: ["bash"], pattern: "ls ?*" });
  });

  it("gate:config set rejects unknown keys, rules, and invalid values without writing", async () => {
    const { pi, captured } = fakePi();
    const env = makeEnv();
    createGatekeeper(pi, { home: userHome, fetchFn: env.fetchFn });
    const handler = captured.commands.get("gate:config")!.handler;
    await handler("set threshold abc", env.ctx());
    await handler("set rules []", env.ctx());
    await handler("set nonsense 1", env.ctx());
    await handler("set log.maxLines -5", env.ctx());
    await handler("set enabled maybe", env.ctx());
    let cfg: any = {};
    try {
      cfg = JSON.parse(await readFile(join(userHome, ".pi/agent/gate/config.json"), "utf8"));
    } catch {
      // no file at all — nothing was ever written
    }
    expect(cfg.rules).toBeUndefined();
    expect(cfg.threshold).toBeUndefined();
    expect(cfg.nonsense).toBeUndefined();
    expect(cfg.log).toBeUndefined();
    expect(cfg.enabled).toBeUndefined();
    expect(env.ui.notified.some((n) => n.includes("unknown key"))).toBe(true);
    expect(env.ui.notified.some((n) => n.includes("must be a number between 0 and 1"))).toBe(true);
    expect(env.ui.notified.some((n) => n.includes("use gate:rules"))).toBe(true);
  });

  it("self-protection blocks relative reads of the gate's own config and log", async () => {
    const { captured, env } = await setup({ choice: "safe", confidence: 0.99 });
    const project = await runToolCall(captured, env, { type: "tool_call", toolName: "read", input: { path: ".pi/gate/config.json" } });
    expect(project?.block).toBe(true);
    expect(project?.reason).toContain("protects its own");
    const user = await runToolCall(captured, env, { type: "tool_call", toolName: "read", input: { path: ".pi/agent/gate/config.json" } });
    expect(user?.block).toBe(true);
    expect(env.requests).toHaveLength(0);
  });

  it("the plain selector maps Allow, and nothing is cached: a re-issued call asks again", async () => {
    const { captured, env } = await setup({ choice: "safe", confidence: 0.6 });
    env.ui.select = async (title: string, options: string[]): Promise<string | undefined> => {
      env.ui.selected.push({ title, options });
      return options[0]; // "Allow"
    };
    const first = await runToolCall(captured, env, { type: "tool_call", toolName: "bash", input: { command: "ls ~/work" } });
    expect(first).toBeUndefined();
    const second = await runToolCall(captured, env, { type: "tool_call", toolName: "bash", input: { command: "ls ~/work" } });
    expect(second).toBeUndefined();
    // no session cache (ADR-0005): the second call classified and asked again
    expect(env.ui.selected).toHaveLength(2);
    expect(env.requests).toHaveLength(2);
  });

  it("a secret-bearing write blocks before the model with a masked reason (ADR-0004)", async () => {
    const { captured, env } = await setup({ choice: "safe", confidence: 0.99 });
    // the secret sits past the first 100 characters, so the truncated log
    // view cannot hold it — the scan sees the full content regardless
    const content = `${"x".repeat(90)}\naws_key = AKIAIOSFODNN7EXAMPLA\n`;
    const result = await runToolCall(captured, env, {
      type: "tool_call",
      toolName: "write",
      input: { path: "notes.txt", content },
    });
    expect(result?.block).toBe(true);
    expect(result?.reason).toContain("aws-access-token");
    expect(result?.reason).toContain("AKI…(20 chars)");
    expect(result?.reason).not.toContain("AKIAIOSFODNN7EXAMPLA");
    expect(result?.reason).toContain("secrets.toml");
    // the model was never consulted and no secret landed in the log
    expect(env.requests).toHaveLength(0);
    const logPath = join(userHome, ".pi/agent/gate/decisions.jsonl");
    let logText = "";
    for (let i = 0; i < 50 && !logText; i++) {
      try {
        logText = await readFile(logPath, "utf8");
      } catch {
        await new Promise((r) => setTimeout(r, 20));
      }
    }
    expect(logText).toContain("\"source\":\"secrets\"");
    expect(logText).not.toContain("AKIAIOSFODNN7EXAMPLA");
  });

  it("a secret within the first 100 chars of the serialized args does not leak into the decision log", async () => {
    // Boundary case for the log-masking fix: the key sits at byte ~23 of
    // the JSON — well inside the first 100 characters that the logged
    // argument view captures. Constructed at runtime (joined halves) so
    // this fixture doesn't trip the very engine under test when the
    // file is written.
    const awsKey = ["AKIA", "IOSFODNN7EXAMPLA"].join("");
    const maskedPeek = `${awsKey.slice(0, 3)}…(20 chars)`;
    const { captured, env } = await setup({ choice: "safe", confidence: 0.99 });
    const result = await runToolCall(captured, env, {
      type: "tool_call",
      toolName: "write",
      input: { path: "x", content: awsKey },
    });
    expect(result?.block).toBe(true);
    expect(result?.reason).toContain("aws-access-token");
    expect(result?.reason).not.toContain(awsKey);
    // the model was never consulted
    expect(env.requests).toHaveLength(0);
    // poll the log (the write is fire-and-forget)
    const logPath = join(userHome, ".pi/agent/gate/decisions.jsonl");
    let logText = "";
    for (let i = 0; i < 50 && !logText; i++) {
      try {
        logText = await readFile(logPath, "utf8");
      } catch {
        await new Promise((r) => setTimeout(r, 20));
      }
    }
    // the decision is logged: the masked peek rides in the reason, the
    // args column is the constant — the key itself never lands in the log
    expect(logText).toContain('"source":"secrets"');
    expect(logText).toContain(maskedPeek);
    expect(logText).toContain("<blocked: secrets>");
    expect(logText).not.toContain(awsKey);
    // a secret-bearing path (no content, short target) is covered too
    const secretPath = ["/keys/", awsKey, ".json"].join("");
    const second = await runToolCall(captured, env, {
      type: "tool_call",
      toolName: "read",
      input: { path: secretPath },
    });
    expect(second?.block).toBe(true);
    let logText2 = logText;
    for (let i = 0; i < 50 && logText2 === logText; i++) {
      try {
        logText2 = await readFile(logPath, "utf8");
      } catch {
        await new Promise((r) => setTimeout(r, 20));
      }
    }
    expect(logText2.trim().split("\n")).toHaveLength(2);
    expect(logText2).not.toContain(awsKey);
  });

  it("secrets.enabled false turns detection off (the single switch, ADR-0005)", async () => {
    await writeFile(
      join(userHome, ".pi/agent/gate/config.json"),
      JSON.stringify({ secrets: { enabled: false, autoUpdate: false } }),
    );
    const { captured, env } = await setup({ choice: "safe", confidence: 0.99 });
    const result = await runToolCall(captured, env, {
      type: "tool_call",
      toolName: "write",
      input: { path: "notes.txt", content: "aws_key = AKIAIOSFODNN7EXAMPLA\n" },
    });
    expect(result).toBeUndefined();
    expect(env.requests).toHaveLength(1); // the model decided it
  });

  it("the operator's secrets.toml overrides ride ahead and suppress, hot-reloading", async () => {
    await writeFile(
      join(userHome, ".pi/agent/gate/secrets.toml"),
      ['[[allow]]', 'id = "aws-access-token"'].join("\n"),
    );
    const { captured, env } = await setup({ choice: "safe", confidence: 0.99 });
    // suppressed: goes to the model and auto-allows
    const first = await runToolCall(captured, env, {
      type: "tool_call",
      toolName: "write",
      input: { path: "notes.txt", content: "aws_key = AKIAIOSFODNN7EXAMPLA\n" },
    });
    expect(first).toBeUndefined();
    expect(env.requests).toHaveLength(1);
    // removing the override hot-reloads back to blocking
    await rm(join(userHome, ".pi/agent/gate/secrets.toml"), { force: true });
    const second = await runToolCall(captured, env, {
      type: "tool_call",
      toolName: "write",
      input: { path: "notes.txt", content: "aws_key = AKIAIOSFODNN7EXAMPLA\n" },
    });
    expect(second?.block).toBe(true);
    expect(second?.reason).toContain("aws-access-token");
  });

  it("an agent tool call touching secrets.toml is denied by self-protection (ADR-0003)", async () => {
    const { captured, env } = await setup({ choice: "safe", confidence: 0.99 });
    const result = await runToolCall(captured, env, {
      type: "tool_call",
      toolName: "read",
      input: { path: join(userHome, ".pi/agent/gate/secrets.toml") },
    });
    expect(result?.block).toBe(true);
    expect(result?.reason).toContain("protects its own");
    expect(env.requests).toHaveLength(0);
  });

  it("the auto-update adopts a fetched corpus and notifies on change, writing the snapshot only", async () => {
    await writeFile(
      join(userHome, ".pi/agent/gate/config.json"),
      JSON.stringify({ secrets: { autoUpdate: true } }),
    );
    const bundled = await readFile(bundledSnapshot, "utf8");
    const fetched = `${bundled}\n[[rules]]\nid = "test-extra"\nregex = "test-extra-[a-z]{10}"\nkeywords = ["test-extra-"]\n`;
    const { pi, captured } = fakePi();
    const env = makeEnv();
    await createGatekeeper(pi, { home: userHome, fetchFn: makeFetch(fetched) });
    // the update notice is flushed at the first before_agent_start
    captured.events.get("before_agent_start")![0]({ prompt: "do things" }, env.ctx());
    expect(env.ui.notified.some((n) => n.includes("secrets") && n.includes("updated"))).toBe(true);
    // the snapshot landed in the gate dir; secrets.toml was never touched
    const snapshot = await readFile(join(userHome, ".pi/agent/gate/gitleaks.toml"), "utf8");
    expect(snapshot).toContain("test-extra");
    let overridesExist = true;
    try {
      await stat(join(userHome, ".pi/agent/gate/secrets.toml"));
    } catch {
      overridesExist = false;
    }
    expect(overridesExist).toBe(false);
    // and the new rule detects through a tool call
    const result = await runToolCall(captured, env, {
      type: "tool_call",
      toolName: "write",
      input: { path: "notes.txt", content: "test-extra-abcdefghij" },
    });
    expect(result?.block).toBe(true);
    expect(result?.reason).toContain("test-extra");
  });

  it("an unchanged corpus stays silent; a failed fetch warns and keeps the current rules", async () => {
    const bundled = await readFile(bundledSnapshot, "utf8");
    const { pi, captured } = fakePi();
    const env = makeEnv();
    await createGatekeeper(pi, { home: userHome, fetchFn: makeFetch(bundled) });
    captured.events.get("before_agent_start")![0]({ prompt: "do things" }, env.ctx());
    // unchanged: nothing was notified (ADR-0004 — only change or failure)
    expect(env.ui.notified.filter((n) => n.includes("secrets"))).toHaveLength(0);
    // the same engine still blocks secret-bearing calls
    const still = await runToolCall(captured, env, {
      type: "tool_call",
      toolName: "write",
      input: { path: "notes.txt", content: "aws_key = AKIAIOSFODNN7EXAMPLA\n" },
    });
    expect(still?.block).toBe(true);
  });

  it("the sanity gate rejects a collapsing corpus and keeps the previous snapshot", async () => {
    await writeFile(
      join(userHome, ".pi/agent/gate/config.json"),
      JSON.stringify({ secrets: { autoUpdate: true } }),
    );
    const tiny = ['[[rules]]', 'id = "one-rule"', 'regex = "one-rule-[a-z]{6}"', 'keywords = ["one-rule-"]'].join("\n");
    const { pi, captured } = fakePi();
    const env = makeEnv();
    await createGatekeeper(pi, { home: userHome, fetchFn: makeFetch(tiny) });
    captured.events.get("before_agent_start")![0]({ prompt: "do things" }, env.ctx());
    expect(env.ui.notified.some((n) => n.includes("sanity gate"))).toBe(true);
    // no snapshot was written, and the bundled rules still detect
    let snapshotExists = true;
    try {
      await stat(join(userHome, ".pi/agent/gate/gitleaks.toml"));
    } catch {
      snapshotExists = false;
    }
    expect(snapshotExists).toBe(false);
    const result = await runToolCall(captured, env, {
      type: "tool_call",
      toolName: "write",
      input: { path: "notes.txt", content: "aws_key = AKIAIOSFODNN7EXAMPLA\n" },
    });
    expect(result?.block).toBe(true);
  });

  it("an invalid fetched corpus warns and keeps the current rules", async () => {
    await writeFile(
      join(userHome, ".pi/agent/gate/config.json"),
      JSON.stringify({ secrets: { autoUpdate: true } }),
    );
    const { pi, captured } = fakePi();
    const env = makeEnv();
    await createGatekeeper(pi, { home: userHome, fetchFn: makeFetch("this is not toml ]]]") });
    captured.events.get("before_agent_start")![0]({ prompt: "do things" }, env.ctx());
    expect(env.ui.notified.some((n) => n.includes("failed"))).toBe(true);
  });

  it("gate:secrets status reports the engine, and test masks its hits", async () => {
    const { pi, captured } = fakePi();
    const env = makeEnv();
    await createGatekeeper(pi, { home: userHome, fetchFn: env.fetchFn });
    const handler = captured.commands.get("gate:secrets")!.handler;
    const ctx = env.ctx();
    await handler("", ctx);
    expect(env.ui.notified.some((n) => n.includes("gitleaks rules active"))).toBe(true);
    expect(env.ui.notified.some((n) => n.includes(join(userHome, ".pi/agent/gate/secrets.toml")))).toBe(true);
    await handler('test "AKIAIOSFODNN7EXAMPLA"', ctx);
    const hit = env.ui.notified.find((n) => n.includes("hit —"));
    expect(hit).toContain("aws-access-token");
    expect(hit).toContain("AKI…(20 chars)");
    expect(hit).not.toContain("AKIAIOSFODNN7EXAMPLA");
  });

  it("gate:secrets update forces a refresh even with autoUpdate off", async () => {
    const bundled = await readFile(bundledSnapshot, "utf8");
    const fetched = `${bundled}\n[[rules]]\nid = "forced-rule"\nregex = "forced-[a-z]{8}"\nkeywords = ["forced-"]\n`;
    const { pi, captured } = fakePi();
    const env = makeEnv();
    await createGatekeeper(pi, { home: userHome, fetchFn: makeFetch(fetched) });
    const handler = captured.commands.get("gate:secrets")!.handler;
    await handler("update", env.ctx());
    expect(env.ui.notified.some((n) => n.includes("updated"))).toBe(true);
    const snapshot = await readFile(join(userHome, ".pi/agent/gate/gitleaks.toml"), "utf8");
    expect(snapshot).toContain("forced-rule");
  });

  it("gate:config set secrets.enabled writes the secrets knob", async () => {
    const { pi, captured } = fakePi();
    const env = makeEnv();
    await createGatekeeper(pi, { home: userHome, fetchFn: env.fetchFn });
    const handler = captured.commands.get("gate:config")!.handler;
    await handler("set secrets.enabled false", env.ctx());
    const cfg = JSON.parse(await readFile(join(userHome, ".pi/agent/gate/config.json"), "utf8"));
    expect(cfg.secrets.enabled).toBe(false);
    await handler("set secrets.source https://example.com/rules.toml", env.ctx());
    const cfg2 = JSON.parse(await readFile(join(userHome, ".pi/agent/gate/config.json"), "utf8"));
    expect(cfg2.secrets.source).toBe("https://example.com/rules.toml");
    // an unknown secrets key is rejected
    await handler("set secrets.bogus 1", env.ctx());
    expect(env.ui.notified.some((n) => n.includes("unknown key"))).toBe(true);
  });

  it("a tool call racing the secrets load still blocks — the handler awaits the init (ADR-0004)", async () => {
    const bundled = await readFile(bundledSnapshot, "utf8");
    // a large corpus widens the engine-load window into a real race
    const extra = Array.from(
      { length: 3000 },
      (_, i) => `[[rules]]\nid = "big-${i}"\nregex = "bigsec-${i}-[a-z]{8}"\nkeywords = ["bigsec-${i}-"]\n`,
    ).join("");
    await writeFile(join(userHome, ".pi/agent/gate/gitleaks.toml"), `${bundled}\n${extra}`);
    const { pi, captured } = fakePi();
    const env = makeEnv();
    const init = createGatekeeper(pi, { home: userHome, fetchFn: env.fetchFn }); // deliberately not awaited
    // built in pieces: a literal fixture here would trip the very engine under test
    const fakeKey = ["AKIA", "IOSFODNN7EXAMPLA"].join("");
    const result = await runToolCall(captured, env, {
      type: "tool_call",
      toolName: "write",
      input: { path: "notes.txt", content: `aws_key = ${fakeKey}\n` },
    });
    expect(result?.block).toBe(true);
    expect(result?.reason).toContain("aws-access-token");
    await init;
  });

  it("notify debug dumps the full model request and answer per classification", async () => {
    await writeFile(
      join(userHome, ".pi/agent/gate/config.json"),
      JSON.stringify({ secrets: { autoUpdate: false }, notify: "debug" }),
    );
    const { captured, env } = await setup({ choice: "safe", confidence: 0.9 });
    await runToolCall(captured, env, { type: "tool_call", toolName: "read", input: { path: "/tmp/a" } });
    const dump = env.ui.notified.find((n) => n.includes("gate › debug [clef-flash] — model request:"));
    expect(dump).toBeDefined();
    // the exact request body: state with tool/arguments/cwd, questions, model
    expect(dump).toContain('"model":"clef-flash"');
    expect(dump).toContain('"tool":"read"');
    expect(dump).toContain('"cwd":"');
    expect(dump).toContain('"questions"');
    // the answer the gate acted on
    expect(dump).toContain("gate › debug [clef-flash] — model answer:");
    expect(dump).toContain('"choice":"safe"');
    expect(dump).toContain('"probabilities"');
    expect(dump).toContain('"confidence":0.9');
    // and the regular transparency line still shows (debug implies always)
    expect(env.ui.notified.some((n) => n.includes("read") && n.includes("allowed") && n.includes("(model)"))).toBe(true);
  });

  it("rule listings do not surface untrusted project config before trust is granted", async () => {
    await mkdir(join(projectDir, ".pi/gate"), { recursive: true });
    await writeFile(
      join(projectDir, ".pi/gate/config.json"),
      JSON.stringify({ rules: [{ action: "allow", pattern: "project-only-rule" }] }),
    );
    const { pi, captured } = fakePi();
    const env = makeEnv();
    await createGatekeeper(pi, { home: userHome, fetchFn: env.fetchFn });
    const handler = captured.commands.get("gate:rules")!.handler;
    // untrusted: the project rules stay hidden
    await handler("", env.ctx());
    expect(env.ui.notified.some((n) => n.includes("project-only-rule"))).toBe(false);
    // trusted: they surface
    await handler("", env.ctx({ isProjectTrusted: () => true }));
    expect(env.ui.notified.some((n) => n.includes("project-only-rule"))).toBe(true);
  });

  it("gate:log in non-TUI modes keeps the one-line rendering", async () => {
    const { captured, env } = await setup({ choice: "unsafe", confidence: 0.97 });
    await runToolCall(captured, env, { type: "tool_call", toolName: "read", input: { path: "/etc/passwd" } });
    const handler = captured.commands.get("gate:log")!.handler;
    await handler("5", env.ctx({ mode: "rpc" }));
    const line = env.ui.notified.find((n) => n.includes("gate › last"));
    expect(line).toContain("read → block (model unsafe 0.97)");
  });

  describe("gate:log overlay (tui)", () => {
    /** Captures the overlay factory and hands back a renderable view. */
    function captureOverlay() {
      let factory: ((tui: any, theme: any, kb: any, done: () => void) => any) | undefined;
      const closed = { value: false };
      const fakeTheme = {
        fg: (_c: string, s: string) => s,
        bg: (_c: string, s: string) => s,
        bold: (s: string) => s,
      };
      return {
        fakeTheme,
        install: (ui: any) => {
          ui.custom = async (f: any) => {
            factory = f;
            return undefined;
          };
        },
        build: (rows = 30) => {
          expect(factory).toBeDefined();
          const tui = { terminal: { rows, columns: 110 }, requestRender() {} };
          return factory!(tui, fakeTheme, {} as any, () => (closed.value = true));
        },
        closed,
      };
    }

    it("opens a table overlay with the full decision context", async () => {
      const { captured, env } = await setup({ choice: "unsafe", confidence: 0.97 });
      await runToolCall(captured, env, { type: "tool_call", toolName: "read", input: { path: "/etc/passwd" } });
      const overlay = captureOverlay();
      overlay.install(env.ui);
      await captured.commands.get("gate:log")!.handler("", env.ctx());

      const view = overlay.build();
      const all = view.render(100).join("\n");
      // the columns the operator reviews
      expect(all).toMatch(/time\s+tool\s+action\s+source\s+class\s+model\s+args\s+reason/);
      expect(all).toContain("read");
      expect(all).toContain("block");
      expect(all).toContain('"path":"/etc/passwd"');
      // no overlay for an empty selection — the fallback message instead
      const empty = captureOverlay();
      empty.install(env.ui);
      await captured.commands.get("gate:log")!.handler("zzz", env.ctx());
      expect(env.ui.notified.some((n) => n.includes("(none yet)"))).toBe(true);
    });

    it("Enter expands the selected record, Esc returns, Esc/q closes", async () => {
      const { captured, env } = await setup({ choice: "unsafe", confidence: 0.97 });
      await runToolCall(captured, env, { type: "tool_call", toolName: "read", input: { path: "/etc/passwd" } });
      const overlay = captureOverlay();
      overlay.install(env.ui);
      await captured.commands.get("gate:log")!.handler("", env.ctx());
      const view = overlay.build();

      view.handleInput("\r"); // Enter → detail
      const detail = view.render(100).join("\n");
      expect(detail).toContain("time: ");
      expect(detail).toContain("probabilities: ");
      expect(detail).toContain("reason: ");
      expect(detail).toContain("args: ");

      view.handleInput("\x1b"); // Esc → back to the table
      expect(view.render(100).join("\n")).toMatch(/time\s+tool\s+action\s+source\s+class\s+model\s+args\s+reason/);

      view.handleInput("q");
      expect(overlay.closed.value).toBe(true);
    });

    it("every boxed line is the same width at any terminal size", async () => {
      const { captured, env } = await setup({ choice: "unsafe", confidence: 0.97 });
      await runToolCall(captured, env, { type: "tool_call", toolName: "read", input: { path: "/etc/passwd" } });
      for (const width of [100, 60, 40]) {
        const overlay = captureOverlay();
        overlay.install(env.ui);
        await captured.commands.get("gate:log")!.handler("", env.ctx());
        const lines = overlay.build(30).render(width);
        const expected = Math.max(24, width - 1);
        expect(new Set(lines.map((l: string) => visibleWidth(l)))).toEqual(new Set([expected]));
        expect(lines[0]!.startsWith("┌")).toBe(true);
        expect(lines[lines.length - 1]!.startsWith("└")).toBe(true);
      }
    });

    it("an over-page detail keeps the frame: bottom border survives clipping", async () => {
      const { captured, env } = await setup({ choice: "unsafe", confidence: 0.97 });
      await runToolCall(captured, env, { type: "tool_call", toolName: "read", input: { path: "/etc/passwd" } });
      const overlay = captureOverlay();
      overlay.install(env.ui);
      await captured.commands.get("gate:log")!.handler("", env.ctx());
      // 10 rows → 9-line maxHeight; the record's detail fills more, forcing
      // the scroll-marker path that used to overflow the budget
      const view = overlay.build(10);
      view.handleInput("\r"); // Enter → detail (over a page long)
      const lines = view.render(100);
      expect(lines).toHaveLength(9); // floor(10 * 0.9) — never more
      expect(lines[0]).toContain("┌");
      expect(lines[lines.length - 1]).toContain("└");
      expect(lines[lines.length - 1]).toContain("Enter/Esc back");
      expect(lines.join("\n")).toContain("time: ");
    });
  });
});
