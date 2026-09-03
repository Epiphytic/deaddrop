import { spawn } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const buildTimeoutMs = 300_000;
const startupTimeoutMs = 300_000;
const testTimeoutMs = 210_000;
const shutdownTimeoutMs = 20_000;
const terminationGraceMs = 5_000;

if (process.env.DEADDROP_LIVE_TOR !== "1") {
  throw new Error("set DEADDROP_LIVE_TOR=1 to run the live Node onion probe");
}

await run("cargo", ["build", "-p", "onion-probe"], {
  cwd: repoRoot,
  stdio: "inherit",
  timeoutMs: buildTimeoutMs,
});

const stateDir = await mkdtemp(join(tmpdir(), "deaddrop-node-probe-"));
await chmod(stateDir, 0o700);
const rawResultPath = join(stateDir, "node-onion-result.json");
const onion = spawn(join(repoRoot, "target", "debug", "onion-probe"), [stateDir], {
  cwd: repoRoot,
  stdio: ["ignore", "pipe", "inherit"],
});

try {
  const startup = JSON.parse(
    await firstLine(onion, startupTimeoutMs),
  );
  if (!/^http:\/\/[a-z2-7]{56}\.onion$/.test(startup.onion_url)) {
    throw new Error("onion-probe emitted an invalid startup URL");
  }

  await run(
    "npm",
    ["test", "-w", "packages/transport-probe", "--", "node-onion"],
    {
      cwd: repoRoot,
      stdio: "inherit",
      timeoutMs: testTimeoutMs,
      env: {
        ...process.env,
        DEADDROP_LIVE_TOR: "1",
        DEADDROP_ONION_URL: startup.onion_url,
        DEADDROP_RESULT_PATH: rawResultPath,
      },
    },
  );

  const result = JSON.parse(await readFile(rawResultPath, "utf8"));
  const pinText = await readFile(join(repoRoot, "upstream-pins.toml"), "utf8");
  const artifact = {
    schema_version: 1,
    check: "node_onion_fetch",
    generated_at: new Date().toISOString(),
    pins: {
      tor_js_fork_rev: readPin(pinText, "tor_js_fork_rev"),
      tor_js_package_sha256: readPin(pinText, "tor_js_package_sha256"),
    },
    ...result,
  };
  const artifactDir = join(repoRoot, "artifacts", "feasibility");
  await mkdir(artifactDir, { recursive: true });
  await writeFile(
    join(artifactDir, "node-onion.json"),
    JSON.stringify(artifact, null, 2) + "\n",
    "utf8",
  );
  console.log(JSON.stringify(artifact));
} finally {
  await stop(onion);
  await rm(stateDir, { recursive: true, force: true });
}

function readPin(text, name) {
  const match = text.match(new RegExp(`^${name} = "([^"]+)"$`, "m"));
  if (!match) throw new Error(`missing ${name} in upstream-pins.toml`);
  return match[1];
}

function firstLine(child, timeoutMs) {
  return new Promise((resolveLine, reject) => {
    const lines = createInterface({ input: child.stdout });
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error(`onion service did not start within ${timeoutMs}ms`));
    }, timeoutMs);
    const onLine = (line) => {
      cleanup();
      resolveLine(line);
    };
    const onExit = (code, signal) => {
      cleanup();
      reject(
        new Error(
          `onion service exited before startup (code ${code}, signal ${signal})`,
        ),
      );
    };
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    const cleanup = () => {
      clearTimeout(timer);
      lines.off("line", onLine);
      child.off("exit", onExit);
      child.off("error", onError);
      lines.close();
    };

    lines.once("line", onLine);
    child.once("exit", onExit);
    child.once("error", onError);
  });
}

function run(command, args, options) {
  return new Promise((resolveRun, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      stdio: options.stdio,
      env: options.env,
      detached: process.platform !== "win32",
    });
    let timedOut = false;
    let forceTimer;
    let settled = false;
    const settle = (callback) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(forceTimer);
      callback();
    };
    const timer = options.timeoutMs
      ? setTimeout(() => {
          timedOut = true;
          void signalProcessTree(child, "SIGTERM");
          forceTimer = setTimeout(async () => {
            await signalProcessTree(child, "SIGKILL");
            settle(() =>
              reject(new Error(`${command} timed out after ${options.timeoutMs}ms`)),
            );
          }, terminationGraceMs);
        }, options.timeoutMs)
      : undefined;

    child.once("error", (error) => {
      if (!timedOut) settle(() => reject(error));
    });
    child.once("exit", (code, signal) => {
      if (timedOut) return;
      if (code === 0) settle(resolveRun);
      else {
        settle(() =>
          reject(
            new Error(`${command} exited with code ${code} and signal ${signal}`),
          ),
        );
      }
    });
  });
}

function signalProcessTree(child, signal) {
  if (!child.pid) return;
  if (process.platform === "win32") {
    const args = ["/pid", String(child.pid), "/t"];
    if (signal === "SIGKILL") args.push("/f");
    return new Promise((resolveSignal) => {
      const taskkill = spawn("taskkill", args, { stdio: "ignore" });
      taskkill.once("error", () => resolveSignal());
      taskkill.once("exit", () => resolveSignal());
    });
  }

  try {
    process.kill(-child.pid, signal);
  } catch (error) {
    if (error?.code !== "ESRCH") throw error;
  }
}

async function stop(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;

  child.kill("SIGINT");
  const exited = await Promise.race([
    new Promise((resolveExit) => child.once("exit", () => resolveExit(true))),
    new Promise((resolveExit) =>
      setTimeout(() => resolveExit(false), shutdownTimeoutMs),
    ),
  ]);
  if (!exited) {
    child.kill("SIGKILL");
    await new Promise((resolveExit) => child.once("exit", resolveExit));
  }
}
