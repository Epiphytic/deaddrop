import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const wrapperPath = join(scriptDir, "build-marmot-wasm.sh");

async function runWrapper({ cargoExit = 0 } = {}) {
  const fixtureRoot = await mkdtemp(join(tmpdir(), "deaddrop-wasm-wrapper-test-"));
  const fixtureBin = join(fixtureRoot, "bin");
  const cargoRecord = join(fixtureRoot, "cargo-record.json");

  try {
    await mkdir(fixtureBin);
    const compilerPath = join(fixtureBin, "wasm-clang");
    await writeFile(
      compilerPath,
      "#!/bin/sh\nprintf '%s\\n' 'wasm32 - WebAssembly 32-bit'\n",
      { mode: 0o755 },
    );
    await writeFile(
      join(fixtureBin, "cargo"),
      `#!/usr/bin/env node
import { writeFileSync } from "node:fs";
writeFileSync(process.env.FAKE_CARGO_RECORD, JSON.stringify({
  hasRustflags: Object.hasOwn(process.env, "RUSTFLAGS"),
  hasEncodedRustflags: Object.hasOwn(process.env, "CARGO_ENCODED_RUSTFLAGS"),
}));
process.exit(Number(process.env.FAKE_CARGO_EXIT));
`,
      { mode: 0o755 },
    );
    await writeFile(
      join(fixtureBin, "wasm-pack"),
      `#!/usr/bin/env node
import { mkdirSync, writeFileSync } from "node:fs";
if (process.argv[2] === "build") {
  mkdirSync("artifacts/feasibility/marmot-wasm", { recursive: true });
  writeFileSync("artifacts/feasibility/marmot-wasm/marmot_wasm_probe_bg.wasm", "wasm");
}
`,
      { mode: 0o755 },
    );

    const result = spawnSync("bash", [wrapperPath], {
      cwd: fixtureRoot,
      encoding: "utf8",
      env: {
        ...process.env,
        CARGO_ENCODED_RUSTFLAGS: "--cfg\u001ftokio_unstable",
        CC_wasm32_unknown_unknown: compilerPath,
        FAKE_CARGO_EXIT: String(cargoExit),
        FAKE_CARGO_RECORD: cargoRecord,
        PATH: `${fixtureBin}:${process.env.PATH}`,
        RUSTFLAGS: "--cfg tokio_unstable",
      },
    });
    const record = JSON.parse(await readFile(cargoRecord, "utf8"));
    return { record, result };
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
}

test("clears inherited Cargo rustflags channels", async () => {
  const { record, result } = await runWrapper();

  assert.equal(result.status, 0, result.stderr);
  assert.equal(record.hasRustflags, false);
  assert.equal(record.hasEncodedRustflags, false);
});

test("propagates a nonzero Cargo exit", async () => {
  const { result } = await runWrapper({ cargoExit: 37 });

  assert.equal(result.status, 37, result.stderr);
});
