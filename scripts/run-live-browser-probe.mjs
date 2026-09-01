import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { createReadStream } from "node:fs";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, extname, join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { createSocket } from "node:dgram";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const gatewayRevision = "dfa2096ec2067b063e873525f7ac6beaba5be966";
const setupTimeoutMs = 600_000;
const startupTimeoutMs = 300_000;
const testTimeoutMs = 210_000;
const shutdownTimeoutMs = 20_000;
const terminationGraceMs = 5_000;

if (process.env.DEADDROP_LIVE_TOR !== "1") {
  throw new Error("set DEADDROP_LIVE_TOR=1 to run the live browser onion probe");
}

const pinText = await readFile(join(repoRoot, "upstream-pins.toml"), "utf8");
if (readPin(pinText, "tor_js_gateway_rev") !== gatewayRevision) {
  throw new Error("the browser harness gateway revision differs from upstream-pins.toml");
}

await run("bash", ["scripts/install-kps-gateway.sh"], {
  cwd: repoRoot,
  stdio: "inherit",
  timeoutMs: setupTimeoutMs,
});
await run("npm", ["run", "build:browser", "-w", "packages/transport-probe"], {
  cwd: repoRoot,
  stdio: "inherit",
  timeoutMs: setupTimeoutMs,
});
await run("cargo", ["build", "-p", "onion-probe"], {
  cwd: repoRoot,
  stdio: "inherit",
  timeoutMs: setupTimeoutMs,
});

const stateDir = await mkdtemp(join(tmpdir(), "deaddrop-browser-probe-"));
await chmod(stateDir, 0o700);
const children = [];
let fixture;

try {
  const gatewayPort = await reserveUdpPort();
  const gatewayConfig = join(stateDir, "gateway.json5");
  const gatewayData = join(stateDir, "gateway-data");
  await writeFile(
    gatewayConfig,
    `${JSON.stringify({
      data_dir: gatewayData,
      kps_port: gatewayPort,
      kps_key_file: join(stateDir, "kps.key"),
      keccak_repo: "",
      keccak_branch: "",
      keccak_poll_interval: 86400,
      keccak_manual_sync_min_interval: 1800,
      advertised_addresses: ["127.0.0.1"],
      tunnel_max: 128,
      tunnel_per_ip: 16,
      tunnel_idle_timeout: 300,
      tunnel_max_lifetime: 3600,
    }, null, 2)}\n`,
    "utf8",
  );

  const gateway = spawnManaged(
    join(repoRoot, "artifacts", "tools", "tor-js-gateway", "bin", "tor-js-gateway"),
    ["--config", gatewayConfig, "run", "--no-mirror"],
    { cwd: repoRoot, stdio: ["ignore", "pipe", "pipe"] },
  );
  children.push(gateway);
  const gatewayLines = watchLines(gateway, true);
  const gatewayAddressPromise = gatewayLines.waitFor(
    (line) => line.match(/127\.0\.0\.1:\d+:[A-Za-z0-9_-]+/)?.[0],
    startupTimeoutMs,
    "KPS gateway did not publish its loopback address",
  );
  const gatewayReadyPromise = gatewayLines.waitFor(
    (line) => /wrote bootstrap\.zip|consensus unchanged, skipping bootstrap archive/.test(line),
    startupTimeoutMs,
    "KPS gateway did not finish its Tor consensus sync",
  );

  const onion = spawnManaged(
    join(repoRoot, "target", "debug", "onion-probe"),
    [join(stateDir, "onion-state")],
    { cwd: repoRoot, stdio: ["ignore", "pipe", "inherit"] },
  );
  children.push(onion);
  const onionLines = watchLines(onion, false);
  const onionReadyPromise = onionLines.waitFor(
    (line) => line.startsWith("{") ? line : undefined,
    startupTimeoutMs,
    "onion service did not publish its address",
  );
  const [gatewayAddress, , startupLine] = await Promise.all([
    gatewayAddressPromise,
    gatewayReadyPromise,
    onionReadyPromise,
  ]);
  const startup = JSON.parse(startupLine);
  if (!/^http:\/\/[a-z2-7]{56}\.onion$/.test(startup.onion_url)) {
    throw new Error("onion-probe emitted an invalid startup URL");
  }

  fixture = await startFixtureServer(
    join(repoRoot, "packages", "transport-probe", "web"),
  );

  const rawResultPath = join(stateDir, "browser-kps-result.json");
  await run(
    "npm",
    ["run", "test:browser", "-w", "packages/transport-probe", "--", "browser-kps.spec.ts"],
    {
      cwd: repoRoot,
      stdio: "inherit",
      timeoutMs: testTimeoutMs,
      env: {
        ...process.env,
        DEADDROP_LIVE_TOR: "1",
        DEADDROP_ONION_URL: startup.onion_url,
        DEADDROP_KPS_GATEWAY: gatewayAddress,
        DEADDROP_FIXTURE_URL: fixture.url,
        DEADDROP_RESULT_PATH: rawResultPath,
      },
    },
  );

  const result = JSON.parse(await readFile(rawResultPath, "utf8"));
  const artifact = {
    schema_version: 1,
    check: "browser_kps_onion_fetch",
    generated_at: new Date().toISOString(),
    pins: {
      tor_js_gateway_rev: gatewayRevision,
      tor_js_gateway_patch_sha256: await sha256File(
        join(repoRoot, "patches", "tor-js-gateway-loopback.patch"),
      ),
      tor_js_gateway_binary_sha256: await sha256File(
        join(repoRoot, "artifacts", "tools", "tor-js-gateway", "bin", "tor-js-gateway"),
      ),
      tor_js_fork_rev: readPin(pinText, "tor_js_fork_rev"),
    },
    ...result,
  };
  const artifactDir = join(repoRoot, "artifacts", "feasibility");
  await mkdir(artifactDir, { recursive: true });
  await writeFile(
    join(artifactDir, "browser-kps.json"),
    `${JSON.stringify(artifact, null, 2)}\n`,
    "utf8",
  );
  console.log(JSON.stringify(artifact));
} finally {
  if (fixture) await fixture.close();
  for (const child of children.reverse()) await stop(child);
  await rm(stateDir, { recursive: true, force: true });
}

async function sha256File(path) {
  const { createHash } = await import("node:crypto");
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

function readPin(text, name) {
  const match = text.match(new RegExp(`^${name} = "([^"]+)"$`, "m"));
  if (!match) throw new Error(`missing ${name} in upstream-pins.toml`);
  return match[1];
}

function spawnManaged(command, args, options) {
  return spawn(command, args, {
    ...options,
    detached: process.platform !== "win32",
  });
}

function watchLines(child, echo) {
  const history = [];
  const waiters = new Set();
  for (const stream of [child.stdout, child.stderr]) {
    if (!stream) continue;
    const lines = createInterface({ input: stream });
    lines.on("line", (line) => {
      history.push(line);
      if (echo) process.stderr.write(`${line}\n`);
      for (const waiter of waiters) waiter(line);
    });
  }

  return {
    waitFor(match, timeoutMs, timeoutMessage) {
      for (const line of history) {
        const value = match(line);
        if (value !== undefined && value !== false) return Promise.resolve(value);
      }
      return new Promise((resolveWait, reject) => {
        const onLine = (line) => {
          const value = match(line);
          if (value === undefined || value === false) return;
          cleanup();
          resolveWait(value);
        };
        const onExit = (code, signal) => {
          cleanup();
          reject(new Error(`child exited before readiness (code ${code}, signal ${signal})`));
        };
        const onError = (error) => {
          cleanup();
          reject(error);
        };
        const timer = setTimeout(() => {
          cleanup();
          reject(new Error(timeoutMessage));
        }, timeoutMs);
        const cleanup = () => {
          clearTimeout(timer);
          waiters.delete(onLine);
          child.off("exit", onExit);
          child.off("error", onError);
        };
        waiters.add(onLine);
        child.once("exit", onExit);
        child.once("error", onError);
      });
    },
  };
}

async function reserveUdpPort() {
  const socket = createSocket("udp4");
  await new Promise((resolveBind, reject) => {
    socket.once("error", reject);
    socket.bind(0, "127.0.0.1", resolveBind);
  });
  const address = socket.address();
  const port = address.port;
  await new Promise((resolveClose) => socket.close(resolveClose));
  return port;
}

async function startFixtureServer(root) {
  const allowed = new Map([
    ["/", "index.html"],
    ["/index.html", "index.html"],
    ["/browser.js", "browser.js"],
  ]);
  const server = createServer(async (request, response) => {
    try {
      const pathname = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
      const file = allowed.get(pathname);
      if (!file) {
        response.writeHead(404).end("not found");
        return;
      }
      const path = join(root, file);
      const details = await stat(path);
      response.writeHead(200, {
        "content-length": details.size,
        "content-type": extname(path) === ".html" ? "text/html; charset=utf-8" : "text/javascript; charset=utf-8",
        "cache-control": "no-store",
      });
      createReadStream(path).pipe(response);
    } catch (error) {
      response.writeHead(500).end(error instanceof Error ? error.message : String(error));
    }
  });
  await new Promise((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolveListen);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("fixture server has no TCP address");
  return {
    url: `http://127.0.0.1:${address.port}`,
    close: () => new Promise((resolveClose, reject) => {
      server.close((error) => error ? reject(error) : resolveClose());
    }),
  };
}

function run(command, args, options) {
  return new Promise((resolveRun, reject) => {
    const child = spawnManaged(command, args, {
      cwd: options.cwd,
      stdio: options.stdio,
      env: options.env,
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
    const timer = setTimeout(() => {
      timedOut = true;
      void signalProcessTree(child, "SIGTERM");
      forceTimer = setTimeout(async () => {
        await signalProcessTree(child, "SIGKILL");
        settle(() => reject(new Error(`${command} timed out after ${options.timeoutMs}ms`)));
      }, terminationGraceMs);
    }, options.timeoutMs);
    child.once("error", (error) => {
      if (!timedOut) settle(() => reject(error));
    });
    child.once("exit", (code, signal) => {
      if (timedOut) return;
      if (code === 0) settle(resolveRun);
      else settle(() => reject(new Error(`${command} exited with code ${code} and signal ${signal}`)));
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
      taskkill.once("error", resolveSignal);
      taskkill.once("exit", resolveSignal);
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
  const exitPromise = new Promise((resolveExit) => child.once("exit", resolveExit));
  await signalProcessTree(child, "SIGINT");
  const exited = await Promise.race([
    exitPromise.then(() => true),
    new Promise((resolveExit) => setTimeout(() => resolveExit(false), shutdownTimeoutMs)),
  ]);
  if (!exited) {
    await signalProcessTree(child, "SIGKILL");
    await exitPromise;
  }
}
