const NPROFILE_FRAGMENT = /^#(nprofile1[023456789acdefghjklmnpqrstuvwxyz]+)$/;

export function recognizeBootstrap(hash) {
  const match = NPROFILE_FRAGMENT.exec(hash);
  if (!match) {
    return { detected: false, nprofile: null };
  }
  return { detected: true, nprofile: match[1] };
}

export function describeLocation(locationValue) {
  const bootstrap = recognizeBootstrap(locationValue.hash);
  const relayProtocol = locationValue.protocol === "https:" ? "wss:" : "ws:";
  const relayUrl = `${relayProtocol}//${locationValue.host}/relay`;
  const canonicalBootstrap = new URL("/", locationValue.origin);
  if (bootstrap.detected) {
    canonicalBootstrap.hash = bootstrap.nprofile;
  }
  return {
    bootstrap,
    relayUrl,
    command: bootstrap.detected
      ? `npx deaddrop chat '${canonicalBootstrap.href}'`
      : "Open a recipient's Deaddrop link to prepare a future CLI command.",
  };
}

export function renderShell(locationValue, root) {
  const view = describeLocation(locationValue);
  const relay = requiredElement(root, "relay-url");
  const bootstrap = requiredElement(root, "bootstrap-state");
  const command = requiredElement(root, "cli-command");

  relay.textContent = view.relayUrl;
  bootstrap.textContent = view.bootstrap.detected
    ? "An nprofile-shaped fragment was detected locally. Its details remain in this page fragment."
    : "No recipient link detected. Open a shared Deaddrop link to continue later.";
  command.textContent = view.command;
}

function requiredElement(root, name) {
  const element = root.querySelector(`[data-shell="${name}"]`);
  if (!element) {
    throw new Error(`The landing shell is missing ${name}.`);
  }
  return element;
}

if (typeof document !== "undefined" && typeof location !== "undefined") {
  renderShell(location, document);
}
