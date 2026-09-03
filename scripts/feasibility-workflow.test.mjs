import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

function loadWorkflow() {
  const script = [
    "require 'json'",
    "require 'yaml'",
    "puts JSON.generate(YAML.load_file(ARGV.fetch(0)))",
  ].join("; ");
  const result = spawnSync(
    "ruby",
    ["-e", script, ".github/workflows/feasibility.yml"],
    { encoding: "utf8" },
  );
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test("live Tor evidence depends on the deterministic gate", () => {
  const workflow = loadWorkflow();

  assert.equal(workflow.jobs["live-tor"].needs, "deterministic");
});
