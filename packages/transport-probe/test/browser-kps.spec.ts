import { expect, test } from "@playwright/test";
import { writeFile } from "node:fs/promises";

test("browser builds Tor locally and reaches the onion through KPS", async ({
  page,
}) => {
  const onionUrl = process.env.DEADDROP_ONION_URL;
  const gateway = process.env.DEADDROP_KPS_GATEWAY;
  test.skip(!onionUrl || !gateway, "set the live browser probe environment");

  const input = encodeURIComponent(JSON.stringify({ onionUrl, gateway }));
  const browserErrors: string[] = [];
  const httpRequests: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") browserErrors.push(message.text());
  });
  page.on("pageerror", (error) => browserErrors.push(error.message));
  page.on("request", (request) => httpRequests.push(request.url()));
  await page.goto(`/index.html#${input}`);

  await expect(page.locator("[data-result]")).toHaveAttribute(
    "data-result",
    "PASS",
    { timeout: 180_000 },
  );
  const output = page.locator("pre");
  await expect(output).toContainText('"status": "ok"');

  const fixtureOrigin = new URL(page.url()).origin;
  expect(
    httpRequests.filter((url) => new URL(url).origin !== fixtureOrigin),
  ).toEqual([]);
  expect(browserErrors).toEqual([]);

  const result = JSON.parse(await output.innerText());
  expect(result.transport).toBe("tor-js-browser-kps");
  if (process.env.DEADDROP_RESULT_PATH) {
    await writeFile(
      process.env.DEADDROP_RESULT_PATH,
      `${JSON.stringify(result, null, 2)}\n`,
      "utf8",
    );
  }
});
