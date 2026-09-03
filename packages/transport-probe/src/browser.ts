import { sha3_256 } from "@noble/hashes/sha3.js";
import { TorClient, parseAddress, storage } from "tor-js/wasm-base64";

import type { ProbeResult } from "./result.js";

const ONION_ORIGIN = /^http:\/\/[a-z2-7]{56}\.onion\/?$/;
const FETCH_TIMEOUT_MS = 120_000;

export async function fetchOnionFromBrowser(
  onionUrl: string,
  gateway: string,
): Promise<ProbeResult> {
  const origin = parseBrowserOnionOrigin(onionUrl);
  parseAddress(gateway);

  const started = performance.now();
  const abort = new AbortController();
  const storageName = "deaddrop-feasibility-tor";
  const client = new TorClient({
    gateway,
    storage: storage.addLocking(
      new storage.IndexedDBStorage(storageName),
      storageName,
    ),
  });

  try {
    const body = await withTimeout(async () => {
      await client.ready();
      const response = await client.fetch(new URL("/health", origin).href, {
        signal: abort.signal,
      });
      if (!response.ok) {
        throw new Error(`onion health returned ${response.status}`);
      }

      const value: unknown = await response.json();
      if (!isHealthBody(value)) {
        throw new Error("onion health returned an invalid response body");
      }
      return value;
    }, FETCH_TIMEOUT_MS, abort);

    return {
      status: "PASS",
      transport: "tor-js-browser-kps",
      body,
      durationMs: Math.round(performance.now() - started),
    };
  } finally {
    client.close();
  }
}

export function parseBrowserOnionOrigin(value: string): URL {
  if (!ONION_ORIGIN.test(value)) {
    throw new Error("onionUrl must be a v3 onion HTTP origin");
  }

  const url = new URL(value);
  if (
    !isValidV3Onion(url.hostname) ||
    url.port !== "" ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    throw new Error("onionUrl must be a v3 onion HTTP origin");
  }
  return url;
}

function isValidV3Onion(hostname: string): boolean {
  const decoded = decodeBase32(hostname.slice(0, -".onion".length));
  if (decoded.length !== 35 || decoded[34] !== 3) return false;

  const checksumInput = new Uint8Array(15 + 32 + 1);
  checksumInput.set(new TextEncoder().encode(".onion checksum"));
  checksumInput.set(decoded.subarray(0, 32), 15);
  checksumInput[47] = decoded[34];
  const expected = sha3_256(checksumInput);
  return decoded[32] === expected[0] && decoded[33] === expected[1];
}

function decodeBase32(value: string): Uint8Array {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  const output: number[] = [];
  let buffer = 0;
  let bits = 0;

  for (const character of value) {
    const digit = alphabet.indexOf(character);
    if (digit < 0) return new Uint8Array();
    buffer = (buffer << 5) | digit;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      output.push((buffer >>> bits) & 0xff);
      buffer &= (1 << bits) - 1;
    }
  }

  return Uint8Array.from(output);
}

async function runFromHash(): Promise<void> {
  const resultElement = document.querySelector<HTMLElement>("[data-result]");
  const output = document.querySelector<HTMLElement>("pre");
  if (!resultElement || !output) throw new Error("browser fixture is incomplete");

  try {
    const raw = decodeURIComponent(location.hash.slice(1));
    const input: unknown = JSON.parse(raw);
    if (!isProbeInput(input)) throw new Error("invalid browser probe input");

    const result = await fetchOnionFromBrowser(input.onionUrl, input.gateway);
    output.textContent = JSON.stringify(result, null, 2);
    resultElement.dataset.result = result.status;
    resultElement.textContent = "PASS";
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    output.textContent = JSON.stringify({ status: "FAIL", error: message }, null, 2);
    resultElement.dataset.result = "FAIL";
    resultElement.textContent = "FAIL";
    console.error(error);
  }
}

function isProbeInput(
  value: unknown,
): value is { onionUrl: string; gateway: string } {
  if (typeof value !== "object" || value === null) return false;
  const input = value as Record<string, unknown>;
  return typeof input.onionUrl === "string" && typeof input.gateway === "string";
}

function isHealthBody(
  value: unknown,
): value is { service: string; status: string } {
  if (typeof value !== "object" || value === null) return false;
  const body = value as Record<string, unknown>;
  return body.service === "deaddrop-feasibility" && body.status === "ok";
}

async function withTimeout<T>(
  operation: () => Promise<T>,
  timeoutMs: number,
  abort: AbortController,
): Promise<T> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timeout = setTimeout(() => {
      const error = new Error(`Tor request timed out after ${timeoutMs}ms`);
      abort.abort(error);
      reject(error);
    }, timeoutMs);
  });

  try {
    return await Promise.race([operation(), deadline]);
  } finally {
    clearTimeout(timeout);
  }
}

if (typeof document !== "undefined") {
  void runFromHash();
}
