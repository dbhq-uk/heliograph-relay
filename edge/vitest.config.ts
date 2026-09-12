import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

/**
 * Why the Worker has tests of its own, when conformance/ already runs against
 * it over HTTP.
 *
 * conformance/ is asserted over HTTP against a base URL, so it sees only what a
 * client sees. A storage model is not one of those things: a relay that holds a
 * message in memory and a relay that writes it to Durable Object storage answer
 * every request in that suite identically. That is how the two implementations
 * came to disagree behind one README sentence while both passed.
 *
 * These tests run inside the Workers runtime, so they can read Durable Object
 * storage directly and evict a Durable Object to force a lifecycle transition.
 * Neither is reachable from outside, and both are load-bearing claims.
 */
export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.toml" },
      miniflare: {
        // The same two estates the conformance suite expects, so one set of
        // credentials is documented once and works in both places.
        bindings: {
          HELIOGRAPH_RELAY_ESTATES: "e1:ctl:stn,e2:other-ctl:other-stn",
        },
      },
    }),
  ],
});
