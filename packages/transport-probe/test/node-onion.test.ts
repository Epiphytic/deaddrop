import { expect, test } from "vitest";
import { writeFile } from "node:fs/promises";

import { fetchOnionFromNode } from "../src/node.js";

test.runIf(process.env.DEADDROP_LIVE_TOR === "1")(
  "fetches the embedded onion service without KPS",
  async () => {
    const result = await fetchOnionFromNode(process.env.DEADDROP_ONION_URL!);

    expect(result.status).toBe("PASS");
    expect(result.transport).toBe("tor-js-node-direct");
    expect(result.body).toEqual({
      service: "deaddrop-feasibility",
      status: "ok",
    });

    if (process.env.DEADDROP_RESULT_PATH) {
      await writeFile(
        process.env.DEADDROP_RESULT_PATH,
        JSON.stringify(result),
        "utf8",
      );
    }
  },
  180_000,
);
