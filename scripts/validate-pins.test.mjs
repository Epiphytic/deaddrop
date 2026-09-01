import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  copyFile,
  mkdir,
  mkdtemp,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const validatorPath = join(scriptDir, "validate-pins.mjs");
const upstreamRevision = "876bdf3c408df0658c158da6a6521745cd0abde5";
const forkRevision = "4981e591bd9399fdad6d5bf62ce6eafa70da7d0b";
const openMlsRevision = "59e7d3b27a7e95237879dd5478de1fd90eff7ada";

const basePins = `mdk_upstream_repo = "https://github.com/marmot-protocol/mdk.git"
mdk_upstream_base_rev = "876bdf3c408df0658c158da6a6521745cd0abde5"
mdk_fork_repo = "https://github.com/Epiphytic/mdk.git"
mdk_fork_rev = "${forkRevision}"
openmls_repo = "https://github.com/erskingardner/openmls.git"
openmls_rev = "${openMlsRevision}"
tor_js_repo = "https://github.com/ethereum/tor-js.git"
tor_js_gateway_rev = "dfa2096ec2067b063e873525f7ac6beaba5be966"
tor_js_npm = "0.4.1"
hypertor = "0.3.0"
`;

function cargoSource(repository, requested, resolved = requested) {
  return `git+${repository}?rev=${requested}#${resolved}`;
}

function validMetadata() {
  const mdkSource = cargoSource(
    "https://github.com/Epiphytic/mdk.git",
    forkRevision,
  );
  const openMlsSource = cargoSource(
    "https://github.com/erskingardner/openmls.git",
    openMlsRevision,
  );

  return {
    packages: [
      "cgka-engine",
      "cgka-traits",
      "transport-nostr-peeler",
      "fs-private",
      "marmot-forensics",
    ]
      .map((name) => ({ name, source: mdkSource }))
      .concat({ name: "openmls", source: openMlsSource }),
  };
}

async function runValidator({ metadata = validMetadata(), pins = basePins } = {}) {
  const fixtureRoot = await mkdtemp(join(tmpdir(), "deaddrop-pin-test-"));
  const fixtureScripts = join(fixtureRoot, "scripts");
  const fixtureBin = join(fixtureRoot, "bin");

  try {
    await mkdir(fixtureScripts);
    await mkdir(fixtureBin);
    await copyFile(validatorPath, join(fixtureScripts, "validate-pins.mjs"));
    await writeFile(join(fixtureRoot, "upstream-pins.toml"), pins);
    await writeFile(join(fixtureBin, "git"), "#!/bin/sh\nexit 0\n", {
      mode: 0o755,
    });
    await writeFile(
      join(fixtureBin, "cargo"),
      "#!/usr/bin/env node\nprocess.stdout.write(process.env.FAKE_CARGO_METADATA);\n",
      { mode: 0o755 },
    );

    return spawnSync(process.execPath, [join(fixtureScripts, "validate-pins.mjs")], {
      encoding: "utf8",
      env: {
        ...process.env,
        FAKE_CARGO_METADATA: JSON.stringify(metadata),
        PATH: `${fixtureBin}:${process.env.PATH}`,
      },
    });
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
}

test("rejects a resolved MDK package revision that drifts from the fork pin", async () => {
  const metadata = validMetadata();
  metadata.packages.find(({ name }) => name === "cgka-traits").source = cargoSource(
    "https://github.com/Epiphytic/mdk.git",
    forkRevision,
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  );

  const result = await runValidator({ metadata });

  assert.notEqual(result.status, 0, result.stderr);
  assert.match(result.stderr, /cgka-traits.*MDK source/i);
});

test("rejects a duplicate provenance key hidden by TOML whitespace", async () => {
  const pins = `${basePins}mdk_fork_rev\t =   "${forkRevision}"\n`;

  const result = await runValidator({ pins });

  assert.notEqual(result.status, 0, result.stderr);
  assert.match(result.stderr, /duplicate pin name: mdk_fork_rev/);
});

test("accepts an equivalent SSH form of the pinned MDK repository", async () => {
  const metadata = validMetadata();
  const equivalentSource = cargoSource(
    "ssh://git@github.com/Epiphytic/mdk.git",
    forkRevision,
  );
  for (const candidate of metadata.packages.filter(({ name }) =>
    [
      "cgka-engine",
      "cgka-traits",
      "transport-nostr-peeler",
      "fs-private",
      "marmot-forensics",
    ].includes(name),
  )) {
    candidate.source = equivalentSource;
  }

  const result = await runValidator({ metadata });

  assert.equal(result.status, 0, result.stderr);
});

test("rejects a symbolic MDK Cargo source", async () => {
  const metadata = validMetadata();
  metadata.packages.find(({ name }) => name === "cgka-engine").source =
    `git+https://github.com/Epiphytic/mdk.git?branch=main#${forkRevision}`;

  const result = await runValidator({ metadata });

  assert.notEqual(result.status, 0, result.stderr);
  assert.match(result.stderr, /cgka-engine.*exactly one full rev SHA/i);
});

test("rejects a requested MDK revision that drifts from the fork pin", async () => {
  const metadata = validMetadata();
  metadata.packages.find(({ name }) => name === "cgka-traits").source = cargoSource(
    "https://github.com/Epiphytic/mdk.git",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    forkRevision,
  );

  const result = await runValidator({ metadata });

  assert.notEqual(result.status, 0, result.stderr);
  assert.match(result.stderr, /cgka-traits.*MDK source/i);
});

test("rejects missing and duplicate expected MDK packages", async (context) => {
  await context.test("missing", async () => {
    const metadata = validMetadata();
    metadata.packages = metadata.packages.filter(
      ({ name }) => name !== "transport-nostr-peeler",
    );

    const result = await runValidator({ metadata });

    assert.notEqual(result.status, 0, result.stderr);
    assert.match(result.stderr, /transport-nostr-peeler.*found 0/i);
  });

  await context.test("duplicate", async () => {
    const metadata = validMetadata();
    metadata.packages.push(
      structuredClone(
        metadata.packages.find(({ name }) => name === "marmot-forensics"),
      ),
    );

    const result = await runValidator({ metadata });

    assert.notEqual(result.status, 0, result.stderr);
    assert.match(result.stderr, /marmot-forensics.*found 2/i);
  });
});

test("rejects a mismatched MDK repository", async () => {
  const metadata = validMetadata();
  metadata.packages.find(({ name }) => name === "fs-private").source = cargoSource(
    "https://github.com/marmot-protocol/mdk.git",
    forkRevision,
  );

  const result = await runValidator({ metadata });

  assert.notEqual(result.status, 0, result.stderr);
  assert.match(result.stderr, /fs-private.*repository/i);
});

test("rejects malformed selectors on additional fork MDK packages", async (context) => {
  for (const [name, source] of [
    [
      "symbolic branch",
      `git+https://github.com/Epiphytic/mdk.git?branch=main#${forkRevision}`,
    ],
    [
      "malformed revision",
      `git+https://github.com/Epiphytic/mdk.git?rev=main#${forkRevision}`,
    ],
    [
      "extra selector before revision",
      `git+https://github.com/Epiphytic/mdk.git?branch=main&rev=${forkRevision}#${forkRevision}`,
    ],
    [
      "extra selector after revision",
      `git+https://github.com/Epiphytic/mdk.git?rev=${forkRevision}&branch=main#${forkRevision}`,
    ],
  ]) {
    await context.test(name, async () => {
      const metadata = validMetadata();
      metadata.packages.push({ name: "mdk-extra", source });

      const result = await runValidator({ metadata });

      assert.notEqual(result.status, 0, result.stderr);
      assert.match(result.stderr, /mdk-extra.*MDK source/i);
    });
  }
});

test("rejects additional packages from the upstream MDK repository", async (context) => {
  for (const [name, source] of [
    [
      "exact revision",
      cargoSource(
        "https://github.com/marmot-protocol/mdk.git",
        upstreamRevision,
      ),
    ],
    [
      "symbolic branch",
      `git+https://github.com/marmot-protocol/mdk.git?branch=main#${upstreamRevision}`,
    ],
  ]) {
    await context.test(name, async () => {
      const metadata = validMetadata();
      metadata.packages.push({ name: "mdk-extra", source });

      const result = await runValidator({ metadata });

      assert.notEqual(result.status, 0, result.stderr);
      assert.match(result.stderr, /mdk-extra.*MDK source/i);
    });
  }
});

test("accepts one additional package from the exactly pinned fork", async () => {
  const metadata = validMetadata();
  metadata.packages.push({
    name: "mdk-extra",
    source: cargoSource("https://github.com/Epiphytic/mdk.git", forkRevision),
  });

  const result = await runValidator({ metadata });

  assert.equal(result.status, 0, result.stderr);
});

test("rejects a revision mismatch on an additional fork MDK package", async () => {
  const metadata = validMetadata();
  metadata.packages.push({
    name: "mdk-extra",
    source: cargoSource(
      "https://github.com/Epiphytic/mdk.git",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      forkRevision,
    ),
  });

  const result = await runValidator({ metadata });

  assert.notEqual(result.status, 0, result.stderr);
  assert.match(result.stderr, /mdk-extra.*MDK source/i);
});

test("rejects duplicate additional MDK packages", async () => {
  const metadata = validMetadata();
  const extraPackage = {
    name: "mdk-extra",
    source: cargoSource("https://github.com/Epiphytic/mdk.git", forkRevision),
  };
  metadata.packages.push(extraPackage, structuredClone(extraPackage));

  const result = await runValidator({ metadata });

  assert.notEqual(result.status, 0, result.stderr);
  assert.match(result.stderr, /mdk-extra.*expected exactly one package.*found 2/i);
});

test("does not classify deceptive Git repository identities as MDK", async () => {
  const metadata = validMetadata();
  metadata.packages.push(
    {
      name: "deceptive-owner",
      source: `git+https://github.com/not-Epiphytic/mdk.git?branch=main#${forkRevision}`,
    },
    {
      name: "deceptive-repository",
      source: `git+https://github.com/Epiphytic/mdk-tools.git?branch=main#${forkRevision}`,
    },
    {
      name: "deceptive-host",
      source: `git+https://github.example.com/Epiphytic/mdk.git?branch=main#${forkRevision}`,
    },
  );

  const result = await runValidator({ metadata });

  assert.equal(result.status, 0, result.stderr);
});
