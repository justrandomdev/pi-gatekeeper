import { describe, expect, it } from "vitest";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { matchRules, protectedPatterns, ruleMatches, touchesGatePaths, type Rule } from "./rules.js";

const HOME = "/home/op";

describe("rule matching", () => {
  it("a tool-only allow rule matches any call of that tool", () => {
    const rule: Rule = { action: "allow", tools: ["ls", "find"] };
    expect(ruleMatches(rule, "ls", { path: "/anything" }, HOME)).toBe(true);
    expect(ruleMatches(rule, "read", { path: "/anything" }, HOME)).toBe(false);
  });

  it("a pattern without a glob matches a file tool target exactly", () => {
    const rule: Rule = { action: "deny", pattern: "~/.zshrc" };
    expect(ruleMatches(rule, "read", { path: "/home/op/.zshrc" }, HOME)).toBe(true);
    expect(ruleMatches(rule, "read", { path: "/home/op/.zshrc.local" }, HOME)).toBe(false);
  });

  it("globs work on file tool targets: * stays within one segment, ** crosses", () => {
    const one: Rule = { action: "deny", pattern: "~/*" };
    expect(ruleMatches(one, "read", { path: "/home/op/.zshrc" }, HOME)).toBe(true);
    expect(ruleMatches(one, "read", { path: "/home/op/.config/a" }, HOME)).toBe(false);
    const deep: Rule = { action: "deny", pattern: "~/**" };
    expect(ruleMatches(deep, "read", { path: "/home/op/.config/a" }, HOME)).toBe(true);
    const tail: Rule = { action: "deny", pattern: "**/.zshrc" };
    expect(ruleMatches(tail, "read", { path: "/home/op/.zshrc" }, HOME)).toBe(true);
  });

  it("shell commands are matched content-wide, with ~ expanded", () => {
    const rule: Rule = { action: "deny", pattern: "~/.zshrc" };
    expect(ruleMatches(rule, "bash", { command: "cat ~/.zshrc" }, HOME)).toBe(true);
    expect(ruleMatches(rule, "bash", { command: "node -e \"readFileSync('/home/op/.zshrc')\"" }, HOME)).toBe(true);
    expect(ruleMatches(rule, "bash", { command: "cat ~/.zshenv" }, HOME)).toBe(false);
  });

  it("a glob rule searches the shell command text, not just the target", () => {
    const rule: Rule = { action: "deny", pattern: "~/.ssh/**" };
    expect(ruleMatches(rule, "bash", { command: "for f in ~/.ssh/*; do cat $f; done" }, HOME)).toBe(true);
    expect(ruleMatches(rule, "bash", { command: "cat ~/notes.txt" }, HOME)).toBe(false);
  });

  it("other tools are matched content-wide over their serialized arguments", () => {
    const rule: Rule = { action: "deny", pattern: "~/.zshrc" };
    expect(ruleMatches(rule, "web_fetch", { urls: ["file:///home/op/.zshrc"] }, HOME)).toBe(true);
    expect(ruleMatches(rule, "web_fetch", { urls: ["https://example.com"] }, HOME)).toBe(false);
  });

  it("allow rules on shell commands anchor to the command start, with * crossing everything", () => {
    const rule: Rule = { action: "allow", tools: ["bash"], pattern: "ls *" };
    expect(ruleMatches(rule, "bash", { command: "ls /home/op/code && ls /home/op/code/other 2>/dev/null" }, HOME)).toBe(true);
    expect(ruleMatches(rule, "bash", { command: "cat notes && ls /a" }, HOME)).toBe(false);
    expect(ruleMatches(rule, "bash", { command: "rm -rf / && ls" }, HOME)).toBe(false);
  });

  it("a leading * opts an allow rule out of anchoring", () => {
    const rule: Rule = { action: "allow", tools: ["bash"], pattern: "*ls*" };
    expect(ruleMatches(rule, "bash", { command: "xargs ls" }, HOME)).toBe(true);
    expect(ruleMatches(rule, "bash", { command: "cd /opt && grep x" }, HOME)).toBe(false);
  });

  it("deny rules stay unanchored so they catch exfiltration mid-command", () => {
    const rule: Rule = { action: "deny", pattern: "~/creds" };
    expect(ruleMatches(rule, "bash", { command: "tar czf backup.tgz ~/creds" }, HOME)).toBe(true);
  });

  it("a chained command splits into components; an allow needs every component to match", () => {
    const rule: Rule = { action: "allow", tools: ["bash"], pattern: "ls *" };
    expect(ruleMatches(rule, "bash", { command: "ls /a && ls /b" }, HOME)).toBe(true);
    expect(ruleMatches(rule, "bash", { command: "ls /a && rm -rf /b" }, HOME)).toBe(false);
    expect(ruleMatches(rule, "bash", { command: "ls /a | grep x" }, HOME)).toBe(false);
    expect(ruleMatches(rule, "bash", { command: "ls /a & rm -rf /" }, HOME)).toBe(false);
  });

  it("a deny matches if any component of a chain matches", () => {
    const rule: Rule = { action: "deny", pattern: "~/creds" };
    expect(ruleMatches(rule, "bash", { command: "ls /a && cat ~/creds" }, HOME)).toBe(true);
    expect(ruleMatches(rule, "bash", { command: "ls /a && cat ~/notes" }, HOME)).toBe(false);
  });

  it("quoted separators are not chain separators", () => {
    const rule: Rule = { action: "allow", tools: ["bash"], pattern: "ls *" };
    expect(ruleMatches(rule, "bash", { command: 'ls "a && b"' }, HOME)).toBe(true);
  });

  it("command substitution defeats an allow rule and falls to the model gate", () => {
    const rule: Rule = { action: "allow", tools: ["bash"], pattern: "ls *" };
    expect(ruleMatches(rule, "bash", { command: "ls $(rm -rf /)" }, HOME)).toBe(false);
    expect(ruleMatches(rule, "bash", { command: "ls `rm -rf /`" }, HOME)).toBe(false);
  });

  it("redirects defeat allow rules, except inert ones to /dev/null and fd duplication", () => {
    const rule: Rule = { action: "allow", tools: ["bash"], pattern: "ls ?*" };
    expect(ruleMatches(rule, "bash", { command: "ls /a && ls /b 2>/dev/null" }, HOME)).toBe(true);
    expect(ruleMatches(rule, "bash", { command: "ls /a >/dev/null" }, HOME)).toBe(true);
    expect(ruleMatches(rule, "bash", { command: "ls /a 2>&1" }, HOME)).toBe(true);
    expect(ruleMatches(rule, "bash", { command: "ls /a > out.txt" }, HOME)).toBe(false);
    expect(ruleMatches(rule, "bash", { command: "ls /a >> /etc/passwd" }, HOME)).toBe(false);
    expect(ruleMatches(rule, "bash", { command: "ls -la> /etc/passwd" }, HOME)).toBe(false);
    expect(ruleMatches(rule, "bash", { command: "cat notes < ~/.creds" }, HOME)).toBe(false);
  });

  it("self-protection catches env-var and dot-segment path spellings in shell text", async () => {
    const touches = (command: string) => touchesGatePaths("bash", { command }, HOME);
    expect(await touches("cat $HOME/.pi/agent/gate/config.json")).toBe(true);
    expect(await touches("cat ${HOME}/.pi/agent/gate/config.json")).toBe(true);
    expect(await touches("cat /home/op/.pi/agent/../agent/gate/config.json")).toBe(true);
    expect(await touches("sed -i s/../../ /home/op/.pi/agent/gate/../gate/config.json")).toBe(true);
  });

  it("self-protection catches cd into a gate directory before relative access", async () => {
    const touches = (command: string) => touchesGatePaths("bash", { command }, HOME);
    expect(await touches("cd ~/.pi/agent/gate && cat config.json")).toBe(true);
    expect(await touches("cd /home/op/code && cat notes.md")).toBe(false);
  });

  it("self-protection tracks cwd across a chain of cd commands", async () => {
    const touches = (command: string, cwd?: string) => touchesGatePaths("bash", { command }, HOME, cwd);
    // `cd ~` then `cd .pi/agent/gate` lands inside the user-level gate dir.
    expect(await touches("cd ~ && cd .pi/agent/gate && cat config.json")).toBe(true);
    // The chain is detected regardless of the original cwd — `cd ~` overrides it.
    expect(await touches("cd ~ && cd .pi/agent/gate && cat config.json", "/elsewhere")).toBe(true);
    // An absolute-path cd followed by a relative one resolves against the new cwd,
    // not the original (without cwd tracking the second cd would resolve to
    // /proj/.pi/agent/gate, which isn't a gate dir; with tracking it resolves
    // to /home/op/.pi/agent/gate, which is).
    expect(await touches("cd /home/op && cd .pi/agent/gate && cat config.json", "/proj")).toBe(true);
    // The same relative cd from the original cwd, without the chain, lands somewhere
    // else and is harmless.
    expect(await touches("cd .pi/agent/gate", "/proj")).toBe(false);
  });

  it("self-protection still ignores look-alike paths", async () => {
    const touches = (command: string) => touchesGatePaths("bash", { command }, HOME);
    expect(await touches("ls /home/op/notes.pi/gatekeeper")).toBe(false);
    expect(await touches("cat $HOME/notes.txt")).toBe(false);
  });

  it("matchRules returns the first hit in order", () => {
    const rules: Rule[] = [
      { action: "allow", tools: ["bash"], pattern: "~/work/**" },
      { action: "deny", pattern: "~/work/**" },
    ];
    expect(matchRules(rules, "bash", { command: "~/work/bin/run --all" }, HOME)?.action).toBe("allow");
    expect(matchRules(rules, "read", { path: "/home/op/work/src/a.ts" }, HOME)?.action).toBe("deny");
  });

  it("no rule matches when the list is empty", () => {
    expect(matchRules([], "bash", { command: "rm -rf /" }, HOME)).toBeUndefined();
  });

  it("protectedPatterns collects deny-rule patterns for state injection", () => {
    const rules: Rule[] = [
      { action: "deny", pattern: "~/.zshrc" },
      { action: "allow", tools: ["ls"] },
      { action: "deny", pattern: "~/.ssh/**" },
    ];
    expect(protectedPatterns(rules)).toEqual(["~/.zshrc", "~/.ssh/**"]);
  });

  it("self-protection resolves file-tool targets against the cwd", async () => {
    const touches = (path: string, cwd?: string) => touchesGatePaths("read", { path }, HOME, cwd);
    // the project gate dir, reached by a relative spelling
    expect(await touches(".pi/gate/config.json", "/proj")).toBe(true);
    // the user gate dir, reached from home
    expect(await touches(".pi/agent/gate/config.json", "/home/op")).toBe(true);
    // dot-detours and doubled slashes that normalize into a gate spelling
    expect(await touches(".pi/agent/../agent/gate/config.json", "/elsewhere")).toBe(true);
    expect(await touches(".pi//agent/gate/config.json", "/elsewhere")).toBe(true);
    // relative spellings protect the gate even without a cwd
    expect(await touches(".pi/gate/config.json")).toBe(true);
    // look-alikes pass
    expect(await touches("src/main.ts", "/proj")).toBe(false);
    expect(await touches(".pi/gatekeeper-notes.md", "/proj")).toBe(false);
  });

  it("self-protection follows symlink chains into the gate directory (ADR-0003)", async () => {
    const home = await mkdtemp(join(tmpdir(), "gk-home-"));
    const gateDir = join(home, ".pi/agent/gate");
    await mkdir(gateDir, { recursive: true });
    await writeFile(join(gateDir, "config.json"), "{}", "utf8");
    const link = join(home, "notes");
    await symlink(gateDir, link);
    // a file-tool read through the symlink is caught
    expect(await touchesGatePaths("read", { path: join(link, "config.json") }, home)).toBe(true);
    // a shell command referencing the symlink is caught
    expect(await touchesGatePaths("bash", { command: `cat ${join(link, "config.json")}` }, home)).toBe(true);
    // the same spelling pointing at a real non-gate dir is not
    const plain = join(home, "plain");
    await mkdir(plain);
    await writeFile(join(plain, "config.json"), "{}", "utf8");
    expect(await touchesGatePaths("read", { path: join(plain, "config.json") }, home)).toBe(false);
    await rm(home, { recursive: true, force: true });
  });

  it("a glob-free allow pattern matches shell text exactly, not as a prefix", () => {
    const literal: Rule = { action: "allow", tools: ["bash"], pattern: "ls -la /tmp" };
    expect(ruleMatches(literal, "bash", { command: "ls -la /tmp" }, HOME)).toBe(true);
    expect(ruleMatches(literal, "bash", { command: "ls -la /tmpsecrets" }, HOME)).toBe(false);
    expect(ruleMatches(literal, "bash", { command: "ls -la /tmp && ls -la /tmp" }, HOME)).toBe(true);
    // glob-bearing allows keep their prefix semantics
    const globbed: Rule = { action: "allow", tools: ["bash"], pattern: "npm test *" };
    expect(ruleMatches(globbed, "bash", { command: "npm test -- --grep foo" }, HOME)).toBe(true);
    // denies stay unanchored anywhere in the text
    const deny: Rule = { action: "deny", pattern: "ls -la /tmp" };
    expect(ruleMatches(deny, "bash", { command: "echo rm ls -la /tmp x" }, HOME)).toBe(true);
  });

  it("a glob-free deny on a file tool also covers everything beneath the pattern", () => {
    const deny: Rule = { action: "deny", pattern: "~/creds" };
    expect(ruleMatches(deny, "read", { path: "/home/op/creds/token" }, HOME)).toBe(true);
    expect(ruleMatches(deny, "write", { path: "/home/op/creds" }, HOME)).toBe(true);
    expect(ruleMatches(deny, "read", { path: "/home/op/creds-token" }, HOME)).toBe(false);
    // allows stay exact: the widening is a deny-only asymmetry
    const allow: Rule = { action: "allow", tools: ["read"], pattern: "~/creds" };
    expect(ruleMatches(allow, "read", { path: "/home/op/creds/token" }, HOME)).toBe(false);
    // glob-bearing denies do exactly what their glob says
    const one: Rule = { action: "deny", pattern: "~/*" };
    expect(ruleMatches(one, "read", { path: "/home/op/.config/a" }, HOME)).toBe(false);
  });

  it("file-tool targets resolve against the cwd, so absolute patterns catch relative spellings", () => {
    const deny: Rule = { action: "deny", pattern: "~/.zshrc" };
    expect(ruleMatches(deny, "read", { path: ".zshrc" }, HOME, "/home/op")).toBe(true);
    expect(ruleMatches(deny, "read", { path: ".zshrc" }, HOME, "/elsewhere")).toBe(false);
    // a hand-written relative pattern still matches its relative spelling
    const relative: Rule = { action: "deny", pattern: "creds/token" };
    expect(ruleMatches(relative, "read", { path: "creds/token" }, HOME, "/proj")).toBe(true);
  });
});
