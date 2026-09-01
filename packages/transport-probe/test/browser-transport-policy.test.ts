import { readFile } from "node:fs/promises";
import { describe, expect, test } from "vitest";

describe("the pinned browser KPS transport", () => {
  test("creates WebRTC without STUN or TURN configuration", async () => {
    const entry = import.meta.resolve("tor-js/wasm-base64");
    const source = await readFile(new URL(entry), "utf8");

    expect(source).toContain("new RTCPeerConnection({})");
    expect(source).not.toMatch(/iceServers|stun:|turn:/i);
  });
});
