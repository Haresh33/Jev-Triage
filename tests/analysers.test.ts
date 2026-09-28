// Detection rules: every known attack pattern is caught, and ordinary admin activity is not flagged.
import { describe, expect, test } from "bun:test";
import { analyzeBehaviors } from "../server/src/behavior";
import { analyzeCloud, extractCloudEvents } from "../server/src/cloud";
import { BENIGN, MALICIOUS } from "./fixtures/lolbin-cases";
import { CLOUD_BAD, CLOUD_OK, UNIX_BAD, UNIX_OK } from "./fixtures/unix-cloud-cases";

type B = { strength: string; technique: string; id: string };
const real = (b: B) => b.strength !== "weak" && b.technique !== "context" && !b.id.startsWith("lolbin_present");

describe("Windows built-in tool abuse (LOLBins)", () => {
  test.each(MALICIOUS.map(([name, cmd, parents]) => [name, cmd, parents ?? []] as const))("flags %s", (_name, cmd, parents) => {
    expect(analyzeBehaviors([cmd], [...parents], []).filter(real).length).toBeGreaterThan(0);
  });
  test.each(BENIGN.map((c) => [c]))("does not flag admin command: %s", (cmd) => {
    expect(analyzeBehaviors([cmd], [], []).filter(real)).toEqual([]);
  });
});

describe("Linux and macOS", () => {
  test.each(UNIX_BAD.map(([name, cmd, parents]) => [name, cmd, parents ?? []] as const))("flags %s", (_name, cmd, parents) => {
    expect(analyzeBehaviors([cmd], [...parents], []).filter(real).length).toBeGreaterThan(0);
  });
  test.each(UNIX_OK.map((c) => [c]))("does not flag: %s", (cmd) => {
    expect(analyzeBehaviors([cmd], [], []).filter(real)).toEqual([]);
  });
});

describe("cloud and identity audit events", () => {
  test.each(CLOUD_BAD.map(([name, ev]) => [name, ev] as const))("flags %s", (_name, ev) => {
    const events = extractCloudEvents(ev);
    expect(events.length).toBeGreaterThan(0);
    expect(analyzeCloud(events).filter(real).length).toBeGreaterThan(0);
  });
  test.each(CLOUD_OK.map(([name, ev]) => [name, ev] as const))("does not flag %s", (_name, ev) => {
    expect(analyzeCloud(extractCloudEvents(ev)).filter(real)).toEqual([]);
  });
});
