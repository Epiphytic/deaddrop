import { describe, expect, test } from "vitest";

import { parseBrowserOnionOrigin } from "../src/browser.js";

const ONION =
  "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion";

describe("parseBrowserOnionOrigin", () => {
  test("accepts a checksum-valid bare v3 onion HTTP origin", () => {
    expect(parseBrowserOnionOrigin(`http://${ONION}`).href).toBe(
      `http://${ONION}/`,
    );
  });

  test.each([
    `https://${ONION}`,
    `http://${ONION}:8080`,
    `http://${ONION}/health`,
    `http://user:password@${ONION}`,
    "http://example.onion",
    "http://example.com",
    `http://${"a".repeat(56)}.onion`,
  ])("rejects %s", (value) => {
    expect(() => parseBrowserOnionOrigin(value)).toThrow(
      "onionUrl must be a v3 onion HTTP origin",
    );
  });
});
