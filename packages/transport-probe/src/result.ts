export type ProbeTransport = "tor-js-node-direct" | "tor-js-browser-kps";

export interface ProbeResult {
  status: "PASS";
  transport: ProbeTransport;
  body: { service: string; status: string };
  durationMs: number;
}
