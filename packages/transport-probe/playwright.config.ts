import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./test",
  timeout: 210_000,
  expect: { timeout: 180_000 },
  fullyParallel: false,
  workers: 1,
  reporter: "line",
  use: {
    baseURL: process.env.DEADDROP_FIXTURE_URL ?? "http://127.0.0.1:4173",
    browserName: "chromium",
    trace: "retain-on-failure",
  },
});
