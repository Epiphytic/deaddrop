import { readFile } from "node:fs/promises";

const text = await readFile(new URL("../upstream-pins.toml", import.meta.url), "utf8");
const required = {
  mdk_rev: /^[0-9a-f]{40}$/,
  openmls_rev: /^[0-9a-f]{40}$/,
  tor_js_gateway_rev: /^[0-9a-f]{40}$/,
  tor_js_npm: /^0\.4\.1$/,
  hypertor: /^0\.3\.0$/,
};

for (const [name, pattern] of Object.entries(required)) {
  const match = text.match(new RegExp(`^${name} = "([^"]+)"$`, "m"));
  if (!match || !pattern.test(match[1])) {
    throw new Error(`invalid or missing pin: ${name}`);
  }
}
