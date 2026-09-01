import { createHash } from "node:crypto";

import { ArtiSocketProvider, TorClient, storage } from "tor-js/wasm-file";

import type { ProbeResult } from "./result.js";

const ONION_HOST = /^[a-z2-7]{56}\.onion$/;
const FETCH_TIMEOUT_MS = 120_000;

export async function fetchOnionFromNode(
  onionUrl: string,
): Promise<ProbeResult> {
  const origin = parseOnionOrigin(onionUrl);
  const started = performance.now();
  const client = new TorClient({
    socketProvider: new ArtiSocketProvider({ strategies: ["direct"] }),
    storage: new storage.MemoryStorage(),
  });

  try {
    const abort = new AbortController();
    const body = await withTimeout(async () => {
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
      transport: "tor-js-node-direct",
      body,
      durationMs: Math.round(performance.now() - started),
    };
  } finally {
    client.close();
  }
}

export function parseOnionOrigin(value: string): URL {
  const url = new URL(value);
  const isOrigin =
    url.protocol === "http:" &&
    ONION_HOST.test(url.hostname) &&
    isValidV3Onion(url.hostname) &&
    url.port === "" &&
    url.username === "" &&
    url.password === "" &&
    (url.pathname === "" || url.pathname === "/") &&
    url.search === "" &&
    url.hash === "";

  if (!isOrigin) {
    throw new Error("onionUrl must be a v3 onion HTTP origin");
  }
  return url;
}

function isValidV3Onion(hostname: string): boolean {
  const decoded = decodeBase32(hostname.slice(0, -".onion".length));
  if (decoded.length !== 35 || decoded[34] !== 3) return false;

  const expected = createHash("sha3-256")
    .update(".onion checksum")
    .update(decoded.subarray(0, 32))
    .update(decoded.subarray(34))
    .digest();
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
      abort.abort(new Error(`Tor request timed out after ${timeoutMs}ms`));
      reject(new Error(`Tor request timed out after ${timeoutMs}ms`));
    }, timeoutMs);
  });

  try {
    return await Promise.race([operation(), deadline]);
  } finally {
    clearTimeout(timeout);
  }
}
