import { spawn, spawnSync } from "node:child_process";
import { mkdir, readFile, rename, rm, unlink, writeFile } from "node:fs/promises";
import { arch, platform } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";

export const mandatoryChecks = [
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
];
const deterministicChecks = mandatoryChecks.slice(0, 9);
const deterministicPrerequisites = ["onion_unit", "transport_unit"];

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const artifactDir = join(repoRoot, "artifacts", "feasibility");
const logDir = join(artifactDir, "live-probe-logs");
const finalResultPath = join(artifactDir, "results.json");
const offlineResultPath = join(artifactDir, "offline-results.json");
const reportPath = join(repoRoot, "docs", "feasibility", "2026-08-31-results.md");

export function decide(records) {
  return mandatoryChecks.every((name) => records[name]?.status === "PASS")
    ? "PASS"
    : "FAIL";
}

async function main() {
  const mode = parseMode(process.argv.slice(2));
  await removeIfPresent(finalResultPath);
  await removeIfPresent(reportPath);
  await rm(logDir, { recursive: true, force: true });
  await mkdir(logDir, { recursive: true });

  const checks = {};
  const executedChecks = new Set();
  const pinCheck = await runCommand(
    "pin-validation",
    "npm",
    ["run", "check:pins"],
    300_000,
  );

  if (!pinCheck.ok) {
    for (const name of mandatoryChecks) {
      checks[name] = record(pinCheck, true, "pin validation failed");
    }
  } else {
    const native = await runCommand(
      "marmot-native",
      "cargo",
      ["test", "-p", "marmot-wasm-probe"],
      600_000,
    );
    const nativeEvidence = commandWithEvidence(native, [
      "test current_profile_two_party_flow_survives_restart ... ok",
    ]);
    assign(checks, [
      "mdk_native_current_profile",
      "identity_proof_v2",
      "key_package_30443",
      "welcome_1059",
      "group_event_445",
      "chat_payload_9",
    ], nativeEvidence, executedChecks);
    await reclaimCargoTargetIfRequested("after-native");

    await removeIfPresent(join(artifactDir, "marmot-wasm-size.json"));
    const wasm = await runCommand(
      "marmot-wasm",
      "bash",
      ["scripts/build-marmot-wasm.sh"],
      600_000,
    );
    const wasmEvidence = commandWithEvidence(wasm, [
      "test current_profile_two_party_flow_runs_after_browser_restart ... ok",
    ]);
    assign(checks, [
      "mdk_wasm_compiles",
      "wasm_state_round_trip",
      "native_wasm_interop",
    ], wasmEvidence, executedChecks);
    await reclaimCargoTargetIfRequested("after-wasm");

    const onionUnit = await runCommand(
      "onion-unit",
      "cargo",
      ["test", "-p", "onion-probe", "--tests"],
      600_000,
    );
    const browserUnit = await runCommand(
      "transport-unit",
      "npm",
      ["test", "-w", "packages/transport-probe"],
      300_000,
    );
    checks.onion_unit = record(onionUnit, false);
    checks.transport_unit = record(browserUnit, false);

    if (mode === "live") {
      const liveEnvironment = { ...process.env, DEADDROP_LIVE_TOR: "1" };
      const nativeOnion = await runCommand(
        "native-onion-live",
        "cargo",
        ["test", "-p", "onion-probe", "--test", "live_persistence", "--", "--nocapture"],
        600_000,
        liveEnvironment,
      );
      const nativeOnionEvidence = commandWithEvidence(nativeOnion, [
        "test persistent_state_restores_the_same_onion_identity_without_a_tcp_listener ... ok",
      ]);
      checks.native_onion_service = combine(onionUnit, nativeOnionEvidence);
      executedChecks.add("native_onion_service");

      const nodeOnion = await runCommand(
        "node-onion-live",
        "node",
        ["scripts/run-live-node-probe.mjs"],
        600_000,
        liveEnvironment,
      );
      checks.node_onion_fetch = combine(browserUnit, nodeOnion);
      executedChecks.add("node_onion_fetch");

      const browserOnion = await runCommand(
        "browser-kps-live",
        "node",
        ["scripts/run-live-browser-probe.mjs"],
        600_000,
        liveEnvironment,
      );
      checks.browser_kps_onion_fetch = combine(browserUnit, browserOnion);
      executedChecks.add("browser_kps_onion_fetch");
    }
  }

  checks.snowflake_transport = await readOptionalSnowflake();
  const result = await buildResult(mode, checks, executedChecks);
  const outputPath = mode === "live" ? finalResultPath : offlineResultPath;
  await validateAndWrite(result, outputPath);

  if (mode === "live") {
    await atomicWrite(reportPath, await renderReport(result));
  }
  if (!modeSucceeded(mode, checks)) process.exitCode = 1;
  console.log(`${mode} feasibility ${result.decision ?? "checks complete"}: ${outputPath}`);
}

async function reclaimCargoTargetIfRequested(phase) {
  if (process.env.DEADDROP_RECLAIM_CARGO_TARGET !== "1") return;
  const cleanup = await runCommand(
    `cargo-clean-${phase}`,
    "cargo",
    ["clean"],
    300_000,
  );
  if (!cleanup.ok) throw new Error(`could not reclaim Cargo target space ${phase}`);
}

function parseMode(args) {
  if (args.length !== 1 || !["--offline", "--live"].includes(args[0])) {
    throw new Error("usage: node scripts/run-feasibility.mjs --offline|--live");
  }
  return args[0].slice(2);
}

function assign(checks, names, result, executedChecks) {
  for (const name of names) {
    checks[name] = record(result, true);
    executedChecks.add(name);
  }
}

export function commandWithEvidence(result, expectedLines) {
  if (!result.ok) return result;
  const output = `${result.stdout}\n${result.stderr}`;
  const missing = expectedLines.filter((line) => !output.includes(line));
  return missing.length === 0
    ? result
    : { ...result, ok: false, reason: `missing expected evidence: ${missing.join(", ")}` };
}

export function modeSucceeded(mode, checks) {
  const expected = mode === "live"
    ? mandatoryChecks
    : [...deterministicChecks, ...deterministicPrerequisites];
  return expected.every((name) => checks[name]?.status === "PASS");
}

export function isComplete(mode, executedChecks) {
  return mode === "live" && mandatoryChecks.every((name) => executedChecks.has(name));
}

function record(result, mandatory, reason) {
  return {
    status: result.ok ? "PASS" : "FAIL",
    mandatory,
    command: result.command,
    duration_ms: result.durationMs,
    ...(reason || result.reason ? { reason: reason ?? result.reason } : {}),
    log: result.log,
  };
}

function combine(first, second) {
  const ok = first.ok && second.ok;
  return {
    status: ok ? "PASS" : "FAIL",
    mandatory: true,
    command: `${first.command} && ${second.command}`,
    duration_ms: first.durationMs + second.durationMs,
    ...(!ok ? { reason: first.reason ?? second.reason ?? "command failed" } : {}),
    log: `${first.log}, ${second.log}`,
  };
}

async function buildResult(mode, checks, executedChecks) {
  const pinText = await readFile(join(repoRoot, "upstream-pins.toml"), "utf8");
  const result = {
    schema_version: 1,
    mode,
    complete: isComplete(mode, executedChecks),
    generated_at: new Date().toISOString(),
    platform: {
      os: platform(),
      arch: arch(),
      rust: spawnSync("rustc", ["--version"], { encoding: "utf8" }).stdout.trim(),
      node: process.versions.node,
    },
    pins: Object.fromEntries(
      [...pinText.matchAll(/^([a-z0-9_]+) = "([^"]+)"$/gm)].map((match) => [match[1], match[2]]),
    ),
    checks,
  };
  if (mode === "live") {
    result.decision = decide(checks);
    const failed = mandatoryChecks.filter((name) => checks[name]?.status !== "PASS");
    result.next_action = failed.length === 0
      ? "write the native relay implementation plan"
      : `revise the failed design assumptions: ${failed.join(", ")}`;
  }
  return result;
}

async function readOptionalSnowflake() {
  const value = JSON.parse(
    await readFile(join(artifactDir, "snowflake.json"), "utf8"),
  );
  return {
    status: value.status,
    mandatory: false,
    reason: value.reason,
  };
}

async function validateAndWrite(result, path) {
  const schema = JSON.parse(
    await readFile(join(repoRoot, "schemas", "feasibility-result.schema.json"), "utf8"),
  );
  const ajv = new Ajv2020({ strict: true, allErrors: true });
  const validate = ajv.compile(schema);
  if (!validate(result)) {
    throw new Error(`feasibility result failed schema validation: ${ajv.errorsText(validate.errors)}`);
  }
  await atomicWrite(path, `${JSON.stringify(result, null, 2)}\n`);
}

async function atomicWrite(path, text) {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.tmp`;
  await writeFile(temporary, text, "utf8");
  await rename(temporary, path);
}

async function removeIfPresent(path) {
  try {
    await unlink(path);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}

async function runCommand(name, command, args, timeoutMs, env = process.env) {
  const started = performance.now();
  const commandText = [command, ...args].join(" ");
  process.stderr.write(`→ ${commandText}\n`);
  const result = await supervise(command, args, timeoutMs, env);
  const durationMs = Math.round(performance.now() - started);
  const logName = `${name}.log`;
  await writeFile(
    join(logDir, logName),
    sanitize(`${result.stdout}\n${result.stderr}`),
    "utf8",
  );
  process.stderr.write(`${result.ok ? "✓" : "✗"} ${name} (${durationMs}ms)\n`);
  return {
    ...result,
    durationMs,
    command: commandText,
    log: `artifacts/feasibility/live-probe-logs/${logName}`,
  };
}

function supervise(command, args, timeoutMs, env) {
  return new Promise((resolveRun) => {
    const child = spawn(command, args, {
      cwd: repoRoot,
      env,
      stdio: ["ignore", "pipe", "pipe"],
      detached: process.platform !== "win32",
    });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let settled = false;
    let forceTimer;
    const append = (current, chunk) => {
      const next = current + chunk;
      return next.length > 5_000_000 ? `[earlier output truncated]\n${next.slice(-5_000_000)}` : next;
    };
    child.stdout.on("data", (chunk) => { stdout = append(stdout, chunk); });
    child.stderr.on("data", (chunk) => { stderr = append(stderr, chunk); });
    const finish = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(forceTimer);
      resolveRun(value);
    };
    const timer = setTimeout(() => {
      timedOut = true;
      signalTree(child, "SIGTERM");
      forceTimer = setTimeout(() => {
        signalTree(child, "SIGKILL");
        finish({
          ok: false,
          stdout,
          stderr,
          reason: `timed out after ${timeoutMs}ms`,
        });
      }, 5_000);
    }, timeoutMs);
    child.once("error", (error) => {
      if (!timedOut) finish({ ok: false, stdout, stderr, reason: error.message });
    });
    child.once("exit", (code, signal) => {
      if (timedOut) return;
      finish({
        ok: code === 0,
        stdout,
        stderr,
        ...(code !== 0 ? { reason: `exited with code ${code} and signal ${signal}` } : {}),
      });
    });
  });
}

function signalTree(child, signal) {
  if (!child.pid) return;
  try {
    if (process.platform === "win32") child.kill(signal);
    else process.kill(-child.pid, signal);
  } catch (error) {
    if (error?.code !== "ESRCH") throw error;
  }
}

function sanitize(text) {
  return text
    .replace(/[a-z2-7]{56}\.onion/gi, "[redacted-onion]")
    .replace(/(?:\d{1,3}\.){3}\d{1,3}:\d+:u[A-Za-z0-9_-]+/g, "[redacted-kps]")
    .replace(/"state_dir":"[^"]+"/g, '"state_dir":"[redacted-state-dir]"')
    .replace(/(?:\/[^\s"']+)*\/deaddrop-(?:node|browser)-probe-[^\s"']+/g, "[redacted-state-dir]");
}

async function renderReport(result) {
  const passed = result.complete && result.decision === "PASS";
  const size = result.checks.mdk_wasm_compiles?.status === "PASS"
    ? await readJsonIfPresent(join(artifactDir, "marmot-wasm-size.json"))
    : undefined;
  const rows = Object.entries(result.checks)
    .map(([name, value]) => `| \`${name}\` | ${value.mandatory === false ? "optional" : "mandatory"} | ${value.status} | ${value.duration_ms ?? "—"} |`)
    .join("\n");
  const summary = passed
    ? "The one-to-one proof passes the current Marmot profile in native Rust and real browser WASM, preserves state across restart, and reaches an embedded onion service from both Node Arti and browser Arti over a loopback-only KPS/WebRTC gateway."
    : "The complete one-to-one proof did not pass. The failed or unexecuted mandatory checks below must be resolved before implementation relies on the affected assumptions.";
  const sizeLine = size
    ? `The browser Marmot WASM produced by this run is ${size.uncompressed_bytes} bytes uncompressed and ${size.gzip_bytes} bytes with gzip. `
    : "No current successful browser Marmot WASM size is reported. ";
  return `# Deaddrop feasibility result\n\nDecision: **${result.decision}**\n\n${summary} Snowflake remains optional and unsupported by the pinned tor-js public API; it is not a substitute for KPS.\n\n| Check | Requirement | Result | Duration (ms) |\n|---|---|---:|---:|\n${rows}\n\n${sizeLine}Machine-readable evidence is in [results.json](../../artifacts/feasibility/results.json). Sanitized command logs are under \`artifacts/feasibility/live-probe-logs/\` and contain no onion hostname, KPS capability address, private key, or state directory.\n\nNext action: ${result.next_action}.\n`;
}

async function readJsonIfPresent(path) {
  try {
    return JSON.parse(await readFile(path, "utf8"));
  } catch {
    return undefined;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await main();
}
