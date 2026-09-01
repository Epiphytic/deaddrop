import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import Ajv2020 from "ajv/dist/2020.js";

import {
  commandWithEvidence,
  decide,
  isComplete,
  mandatoryChecks,
  modeSucceeded,
} from "./run-feasibility.mjs";

const pass = Object.fromEntries(
  [
    "mdk_native_current_profile",
    "mdk_wasm_compiles",
    "identity_proof_v2",
    "key_package_30443",
    "welcome_1059",
    "group_event_445",
    "chat_payload_9",
    "wasm_state_round_trip",
    "native_wasm_interop",
    "node_onion_fetch",
    "native_onion_service",
    "browser_kps_onion_fetch",
  ].map((name) => [name, { status: "PASS" }]),
);

test("the mandatory check list stays exact", () => {
  assert.deepEqual(Object.keys(pass), mandatoryChecks);
});

test("all mandatory checks passing yields PASS", () => {
  assert.equal(decide(pass), "PASS");
});

test("a failed or missing mandatory check yields FAIL", () => {
  assert.equal(
    decide({ ...pass, mdk_wasm_compiles: { status: "FAIL" } }),
    "FAIL",
  );
  const missing = { ...pass };
  delete missing.native_onion_service;
  assert.equal(decide(missing), "FAIL");
});

test("optional unsupported Snowflake does not fail the gate", () => {
  assert.equal(
    decide({
      ...pass,
      snowflake_transport: { status: "UNSUPPORTED", mandatory: false },
    }),
    "PASS",
  );
});

test("offline mode fails when any deterministic check fails", () => {
  const deterministic = Object.fromEntries(
    mandatoryChecks.slice(0, 9).map((name) => [name, { status: "PASS" }]),
  );
  deterministic.onion_unit = { status: "PASS", mandatory: false };
  deterministic.transport_unit = { status: "PASS", mandatory: false };
  assert.equal(modeSucceeded("offline", deterministic), true);
  deterministic.native_wasm_interop.status = "FAIL";
  assert.equal(modeSucceeded("offline", deterministic), false);
  deterministic.native_wasm_interop.status = "PASS";
  deterministic.transport_unit.status = "FAIL";
  assert.equal(modeSucceeded("offline", deterministic), false);
});

test("live completion means every mandatory probe actually ran", () => {
  assert.equal(isComplete("live", new Set(mandatoryChecks)), true);
  assert.equal(isComplete("live", new Set(mandatoryChecks.slice(1))), false);
  assert.equal(isComplete("offline", new Set(mandatoryChecks)), false);
});

test("successful commands need named test evidence", () => {
  const command = { ok: true, stdout: "test expected_probe ... ok", stderr: "" };
  assert.equal(commandWithEvidence(command, ["test expected_probe ... ok"]).ok, true);
  const missing = commandWithEvidence(command, ["test browser_probe ... ok"]);
  assert.equal(missing.ok, false);
  assert.match(missing.reason, /missing expected evidence/);
});

test("the schema independently rejects an empty live PASS", async () => {
  const schema = JSON.parse(
    await readFile(new URL("../schemas/feasibility-result.schema.json", import.meta.url)),
  );
  const validate = new Ajv2020({ strict: true, allErrors: true }).compile(schema);
  const invalid = {
    schema_version: 1,
    mode: "live",
    complete: true,
    decision: "PASS",
    next_action: "continue",
    generated_at: "2026-09-01T00:00:00Z",
    platform: { os: "linux", arch: "x64", rust: "rustc", node: "22" },
    pins: { mdk_rev: "abc" },
    checks: {},
  };
  assert.equal(validate(invalid), false);
});
