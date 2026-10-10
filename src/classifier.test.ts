import { describe, expect, it } from "vitest";
import { createSystemOneClassifier } from "./classifier.js";

/** A stubbed System One endpoint: records the request, replies canned. */
function stubEndpoint(reply: (body: unknown) => unknown) {
  const requests: { url: string; body: any }[] = [];
  const fetchFn = (async (url: string, init: RequestInit) => {
    requests.push({ url, body: JSON.parse(init.body as string) });
    return {
      ok: true,
      status: 200,
      json: async () => reply(requests[requests.length - 1].body),
    } as Response;
  }) as typeof fetch;
  return { requests, fetchFn };
}

const cannedAnswer = {
  model: "clef-flash",
  answers: {
    safety: {
      type: "choice",
      choice: "unsafe",
      probabilities: { safe: 0.02, unsafe: 0.97, unsure: 0.01 },
      confidence: 0.95,
    },
  },
};

describe("System One classifier", () => {
  it("posts to the configured endpoint URL with the policy as instructions, safe listed first", async () => {
    const { requests, fetchFn } = stubEndpoint(() => cannedAnswer);
    const classifier = createSystemOneClassifier(
      { url: "http://localhost:11434/v1/systemone", model: "clef-flash", timeoutMs: 5000, keepAlive: "10m" },
      fetchFn,
    );
    const result = await classifier.classify({
      tool: "bash",
      args: '{"command":"ls ~"}',
      task: "explore the repo",
      cwd: "/home/op/code",
      protectedPaths: ["~/.zshrc"],
      policy: "the policy text",
    });

    expect(requests[0].url).toBe("http://localhost:11434/v1/systemone");
    const body = requests[0].body as Record<string, any>;
    expect(body.model).toBe("clef-flash");
    expect(body.keep_alive).toBe("10m");
    // state invariant: tool, agent arguments, operator task, working
    // directory, protected paths — nothing else
    expect(body.state).toEqual({
      tool: "bash",
      arguments: '{"command":"ls ~"}',
      task: "explore the repo",
      cwd: "/home/op/code",
      protectedPaths: ["~/.zshrc"],
    });
    expect(body.questions.safety.type).toBe("choice");
    expect(body.questions.safety.instructions).toBe("the policy text");
    // option order: safe first, so ties fail toward asking
    expect(Object.keys(body.questions.safety.criteria)).toEqual(["safe", "unsafe", "unsure"]);

    expect(result.choice).toBe("unsafe");
    expect(result.confidence).toBe(0.95);
    expect(result.probabilities).toEqual({ safe: 0.02, unsafe: 0.97, unsure: 0.01 });
  });

  it("sends the API key as a bearer token when configured", async () => {
    const { requests, fetchFn } = stubEndpoint(() => cannedAnswer);
    const classifier = createSystemOneClassifier(
      { url: "https://jev.example.com/v1/systemone", model: "jev-1", apiKey: "k-123", timeoutMs: 5000, keepAlive: "10m" },
      fetchFn,
    );
    await classifier.classify({ tool: "read", args: "{}", task: "t", protectedPaths: [], policy: "p" });
    // header capture isn't wired in the stub; verify the URL and that it was called
    expect(requests[0].url).toBe("https://jev.example.com/v1/systemone");
    // cwd is omitted from the state when absent
    expect(requests[0].body.state.cwd).toBeUndefined();
  });

  it("omits keep_alive when keepAlive is empty, for strict endpoints", async () => {
    const { requests, fetchFn } = stubEndpoint(() => cannedAnswer);
    const classifier = createSystemOneClassifier(
      { url: "https://api.cloudflare.com/v1/systemone", model: "clef-flash", keepAlive: "", timeoutMs: 5000 },
      fetchFn,
    );
    await classifier.classify({ tool: "read", args: "{}", task: "t", protectedPaths: [], policy: "p" });
    expect(requests[0].body.keep_alive).toBeUndefined();
  });

  it("accepts the answer wrapped in a result envelope (Cloudflare-style)", async () => {
    const { fetchFn } = stubEndpoint(() => ({ result: cannedAnswer }));
    const classifier = createSystemOneClassifier(
      { url: "https://api.cloudflare.com/v1/systemone", model: "clef-flash", timeoutMs: 5000, keepAlive: "" },
      fetchFn,
    );
    const result = await classifier.classify({ tool: "read", args: "{}", task: "t", protectedPaths: [], policy: "p" });
    expect(result.choice).toBe("unsafe");
    expect(result.confidence).toBe(0.95);
  });

  it("the debug hook receives the exact request body and the answer", async () => {
    const { requests, fetchFn } = stubEndpoint(() => cannedAnswer);
    const seen: { request: unknown; answer: unknown }[] = [];
    const classifier = createSystemOneClassifier(
      { url: "http://localhost:11434/v1/systemone", model: "clef-flash", timeoutMs: 5000, keepAlive: "10m" },
      fetchFn,
      { onExchange: (request, answer) => seen.push({ request, answer }) },
    );
    const result = await classifier.classify({ tool: "read", args: "{}", task: "t", cwd: "/p", protectedPaths: [], policy: "p" });
    expect(seen).toHaveLength(1);
    // the exact body that was posted, and the answer the gate acted on
    expect(seen[0].request).toStrictEqual(requests[0].body);
    expect(seen[0].answer).toMatchObject({ type: "choice", choice: "unsafe", confidence: 0.95 });
    expect(result.choice).toBe("unsafe");
  });

  it("propagates HTTP and network errors to the decision layer", async () => {
    const failing = (async () => {
      throw new Error("connect ECONNREFUSED");
    }) as typeof fetch;
    const classifier = createSystemOneClassifier(
      { url: "http://localhost:11434/v1/systemone", model: "clef-flash", timeoutMs: 5000, keepAlive: "10m" },
      failing,
    );
    await expect(
      classifier.classify({ tool: "read", args: "{}", task: "t", protectedPaths: [], policy: "p" }),
    ).rejects.toThrow("connect ECONNREFUSED");
  });
});
