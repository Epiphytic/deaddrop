import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const text = await readFile(join(repoRoot, "upstream-pins.toml"), "utf8");
const pins = {};

for (const [index, rawLine] of text.split(/\r?\n/).entries()) {
  if (!rawLine.trim() || rawLine.trimStart().startsWith("#")) {
    continue;
  }

  const assignment = rawLine.match(
    /^\s*([a-z][a-z0-9_]*)\s*=\s*"([^"\r\n]+)"\s*(?:#.*)?$/,
  );
  if (!assignment) {
    throw new Error(`invalid pin assignment at line ${index + 1}`);
  }

  const [, name, value] = assignment;
  if (Object.hasOwn(pins, name)) {
    throw new Error(`duplicate pin name: ${name}`);
  }
  pins[name] = value;
}

const fullSha = /^[0-9a-f]{40}$/;
const required = {
  mdk_upstream_repo: /^https:\/\/github\.com\/marmot-protocol\/mdk\.git$/,
  mdk_upstream_base_rev: fullSha,
  mdk_fork_repo: /^https:\/\/github\.com\/Epiphytic\/mdk\.git$/,
  mdk_fork_rev: fullSha,
  openmls_repo: /^https:\/\/github\.com\/erskingardner\/openmls\.git$/,
  openmls_rev: fullSha,
  tor_js_repo: /^https:\/\/github\.com\/ethereum\/tor-js\.git$/,
  tor_js_gateway_rev: fullSha,
  tor_js_npm: /^0\.4\.1$/,
  tor_js_fork_repo: /^https:\/\/github\.com\/Epiphytic\/tor-js\.git$/,
  tor_js_fork_rev: fullSha,
  tor_js_package_url:
    /^https:\/\/github\.com\/Epiphytic\/tor-js\/releases\/download\/deaddrop-onion-v0\.4\.1\.1\/tor-js-0\.4\.1\.tgz$/,
  tor_js_package_sha256: /^[0-9a-f]{64}$/,
  tor_js_package_integrity: /^sha512-[A-Za-z0-9+/]+={0,2}$/,
  tor_js_upstream_pr: /^https:\/\/github\.com\/ethereum\/tor-js\/pull\/15$/,
  hypertor: /^0\.3\.0$/,
};
const sentinel = /(?:replace|sentinel|todo|tbd|pending|branch|head)/i;

for (const [name, pattern] of Object.entries(required)) {
  const value = pins[name];
  if (!value || sentinel.test(value) || !pattern.test(value)) {
    throw new Error(`invalid or missing pin: ${name}`);
  }
}

for (const obsolete of ["mdk_repo", "mdk_rev"]) {
  if (Object.hasOwn(pins, obsolete)) {
    throw new Error(`obsolete pin must be removed: ${obsolete}`);
  }
}

function normalizeGitRepository(repository) {
  if (typeof repository !== "string" || repository.length === 0) {
    throw new Error("missing Git repository URL");
  }

  const withoutCargoPrefix = repository.startsWith("git+")
    ? repository.slice(4)
    : repository;
  let host;
  let path;

  const scpStyle = withoutCargoPrefix.match(
    /^(?:[^@/:]+@)?([^/:?#]+):([^?#]+)\/?$/,
  );
  if (scpStyle && !withoutCargoPrefix.includes("://")) {
    [, host, path] = scpStyle;
  } else {
    let parsed;
    try {
      parsed = new URL(withoutCargoPrefix);
    } catch {
      throw new Error(`invalid Git repository URL: ${repository}`);
    }
    if (parsed.search || parsed.hash || !parsed.hostname) {
      throw new Error(`invalid Git repository URL: ${repository}`);
    }
    host = parsed.host;
    path = parsed.pathname;
  }

  const normalizedPath = path
    .replace(/^\/+|\/+$/g, "")
    .replace(/\.git$/i, "")
    .toLowerCase();
  if (!normalizedPath) {
    throw new Error(`invalid Git repository URL: ${repository}`);
  }
  return `${host.toLowerCase()}/${normalizedPath}`;
}

function cargoGitRepositoryIdentity(source) {
  if (typeof source !== "string" || !source.startsWith("git+")) {
    throw new Error("source is not a Cargo Git source");
  }

  let parsed;
  try {
    parsed = new URL(source.slice(4));
  } catch {
    throw new Error("source has an invalid Git URL");
  }

  parsed.search = "";
  parsed.hash = "";
  return normalizeGitRepository(parsed.toString());
}

function parseCargoGitSource(source) {
  const repository = cargoGitRepositoryIdentity(source);
  const parsed = new URL(source.slice(4));

  const queryKeys = [...parsed.searchParams.keys()];
  const requestedRevisions = parsed.searchParams.getAll("rev");
  if (
    queryKeys.length !== 1 ||
    queryKeys[0] !== "rev" ||
    requestedRevisions.length !== 1 ||
    !fullSha.test(requestedRevisions[0])
  ) {
    throw new Error("source must request exactly one full rev SHA");
  }

  const resolvedRevision = parsed.hash.slice(1);
  if (!fullSha.test(resolvedRevision)) {
    throw new Error("source must resolve to one full precise SHA");
  }

  return {
    repository,
    requestedRevision: requestedRevisions[0],
    resolvedRevision,
  };
}

function requirePinnedGitSource(name, source, expectedRepository, expectedRevision, label) {
  let parsed;
  try {
    parsed = parseCargoGitSource(source);
  } catch (error) {
    throw new Error(`${name} ${label}: ${error.message}`);
  }

  if (parsed.repository !== expectedRepository) {
    throw new Error(
      `${name} ${label}: repository ${parsed.repository} does not match ${expectedRepository}`,
    );
  }
  if (
    parsed.requestedRevision !== expectedRevision ||
    parsed.resolvedRevision !== expectedRevision
  ) {
    throw new Error(
      `${name} ${label}: requested ${parsed.requestedRevision} and resolved ${parsed.resolvedRevision}; expected ${expectedRevision}`,
    );
  }
}

function run(command, args, options = {}) {
  return execFileSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
    ...options,
  });
}

const checkout = await mkdtemp(join(tmpdir(), "deaddrop-mdk-pin-"));
try {
  run("git", ["-C", checkout, "init", "--quiet"]);
  run("git", ["-C", checkout, "remote", "add", "origin", pins.mdk_fork_repo]);
  run("git", [
    "-C",
    checkout,
    "fetch",
    "--quiet",
    "--no-tags",
    "--depth=64",
    "origin",
    pins.mdk_fork_rev,
  ]);
  run("git", [
    "-C",
    checkout,
    "fetch",
    "--quiet",
    "--no-tags",
    "--depth=1",
    "origin",
    pins.mdk_upstream_base_rev,
  ]);
  try {
    run("git", [
      "-C",
      checkout,
      "merge-base",
      "--is-ancestor",
      pins.mdk_upstream_base_rev,
      pins.mdk_fork_rev,
    ]);
  } catch (error) {
    if (error.status === 1) {
      throw new Error("mdk_fork_rev is not descended from mdk_upstream_base_rev");
    }
    throw error;
  }
} finally {
  await rm(checkout, { recursive: true, force: true });
}

const metadata = JSON.parse(
  run("cargo", ["metadata", "--format-version", "1", "--locked"]),
);
const expectedMdkPackageNames = new Set([
  "cgka-engine",
  "cgka-traits",
  "transport-nostr-peeler",
  "fs-private",
  "marmot-forensics",
]);
const expectedMdkRepository = normalizeGitRepository(pins.mdk_fork_repo);
const recognizedMdkRepositories = new Set([
  expectedMdkRepository,
  normalizeGitRepository(pins.mdk_upstream_repo),
]);
const mdkPackages = [];

for (const name of expectedMdkPackageNames) {
  const matchingPackages = metadata.packages.filter(
    (candidate) => candidate.name === name,
  );
  if (matchingPackages.length !== 1) {
    throw new Error(
      `${name} MDK source: expected exactly one package, found ${matchingPackages.length}`,
    );
  }
  mdkPackages.push(matchingPackages[0]);
}

for (const candidate of metadata.packages) {
  if (mdkPackages.includes(candidate) || typeof candidate.source !== "string") {
    continue;
  }
  try {
    if (recognizedMdkRepositories.has(cargoGitRepositoryIdentity(candidate.source))) {
      mdkPackages.push(candidate);
    }
  } catch {
    // Expected MDK packages were collected by name above. An unparseable source
    // for any other package has no repository identity that classifies it as MDK.
  }
}

const mdkPackageCounts = new Map();
for (const { name } of mdkPackages) {
  mdkPackageCounts.set(name, (mdkPackageCounts.get(name) ?? 0) + 1);
}
for (const [name, count] of mdkPackageCounts) {
  if (count !== 1) {
    throw new Error(
      `${name} MDK source: expected exactly one package, found ${count}`,
    );
  }
}

for (const { name, source } of mdkPackages) {
  requirePinnedGitSource(
    name,
    source,
    expectedMdkRepository,
    pins.mdk_fork_rev,
    "MDK source",
  );
}

const openMlsPackages = metadata.packages.filter(({ name }) =>
  /^openmls(?:_|$)/.test(name),
);

if (openMlsPackages.length === 0) {
  throw new Error("cargo metadata contains no OpenMLS packages");
}

const expectedOpenMlsRepository = normalizeGitRepository(pins.openmls_repo);
for (const { name, source } of openMlsPackages) {
  requirePinnedGitSource(
    name,
    source,
    expectedOpenMlsRepository,
    pins.openmls_rev,
    "OpenMLS source",
  );
}

const packageLock = JSON.parse(await readFile(join(repoRoot, "package-lock.json"), "utf8"));
const torJsPackage = packageLock.packages?.["node_modules/tor-js"];
if (!torJsPackage) {
  throw new Error("package lock contains no tor-js package");
}
if (torJsPackage.version !== pins.tor_js_npm) {
  throw new Error(
    `tor-js lock version ${torJsPackage.version} does not match ${pins.tor_js_npm}`,
  );
}
if (torJsPackage.resolved !== pins.tor_js_package_url) {
  throw new Error("tor-js lock does not resolve to the pinned fork release artifact");
}
if (torJsPackage.integrity !== pins.tor_js_package_integrity) {
  throw new Error("tor-js lock integrity does not match the pinned release artifact");
}

const releaseResponse = await fetch(pins.tor_js_package_url, { redirect: "follow" });
if (!releaseResponse.ok) {
  throw new Error(`could not download pinned tor-js artifact: HTTP ${releaseResponse.status}`);
}
const releaseBytes = Buffer.from(await releaseResponse.arrayBuffer());
const releaseSha256 = createHash("sha256").update(releaseBytes).digest("hex");
if (releaseSha256 !== pins.tor_js_package_sha256) {
  throw new Error("downloaded tor-js artifact does not match the pinned SHA-256");
}
const releaseIntegrity =
  "sha512-" + createHash("sha512").update(releaseBytes).digest("base64");
if (releaseIntegrity !== pins.tor_js_package_integrity) {
  throw new Error("downloaded tor-js artifact does not match the pinned npm integrity");
}

const releaseDir = await mkdtemp(join(tmpdir(), "deaddrop-tor-js-release-"));
try {
  const archive = join(releaseDir, "tor-js.tgz");
  await writeFile(archive, releaseBytes);
  run("tar", ["-xzf", archive, "-C", releaseDir]);

  const releasePackage = JSON.parse(
    await readFile(join(releaseDir, "package", "package.json"), "utf8"),
  );
  if (releasePackage.version !== pins.tor_js_npm) {
    throw new Error("pinned tor-js artifact contains the wrong package version");
  }

  const releaseWasm = await readFile(
    join(releaseDir, "package", "dist", "tor_js_bg.wasm"),
  );
  if (!releaseWasm.includes(Buffer.from(pins.tor_js_fork_rev, "ascii"))) {
    throw new Error("pinned tor-js WASM does not embed the pinned fork revision");
  }
} finally {
  await rm(releaseDir, { recursive: true, force: true });
}
