import { describe, expect, it } from "vitest";
import { createSystemOneClassifier } from "./classifier.js";

/** Live feedback loop: runs only with GATEKEEPER_LIVE=1 against a real
 *  System One endpoint (default: local Ollama). Skipped in the normal suite. */
const live = process.env.GATEKEEPER_LIVE === "1";

describe.skipIf(!live)("live System One endpoint", () => {
  it(
    "classifies a trivial call",
    async () => {
      const classifier = createSystemOneClassifier({
        url: process.env.GATEKEEPER_URL ?? "http://localhost:11434/v1/systemone",
        model: process.env.GATEKEEPER_MODEL ?? "clef-flash",
        timeoutMs: Number(process.env.GATEKEEPER_TIMEOUT ?? 60_000),
        keepAlive: "10m",
      });
      const result = await classifier.classify({
        tool: "read",
        args: '{"path":"/tmp/a"}',
        task: "diagnose the gatekeeper connection",
        cwd: "/home/op/code",
        protectedPaths: [],
        policy: "Classify the tool call.",
      });
      expect(["safe", "unsafe", "unsure"]).toContain(result.choice);
    },
    90_000,
  );
});
