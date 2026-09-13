import { env as testEnv } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker from "../src/worker";
import type { Env } from "../src/worker";

/**
 * Per-station scope at the edge, asserted here because conformance/ reaches the
 * remote-authoriser path and not this one.
 *
 * `HELIOGRAPH_RELAY_STATIONS` is the configuration a self-hoster writes when
 * their one relay carries more than one customer, and it is parsed in this
 * Worker rather than answered by a control plane. The contract cannot see it,
 * because the contract talks to a relay that was already started with whatever
 * configuration it has. So it is asserted where it lives.
 *
 * scope_test.go is the Go half of the same pair.
 *
 * heliograph-io/heliograph-cloud#71.
 */

// Two customers under ONE estate identifier, which is the case an estate-wide
// credential gets wrong.
const ESTATE = "e-tenancy";
const SCOPES = [
  `${ESTATE}:alpha-01:station:alpha-stn`,
  `${ESTATE}:alpha-01:control:alpha-ctl`,
  `${ESTATE}:bravo-07:station:bravo-stn`,
  `${ESTATE}:bravo-07:control:bravo-ctl`,
].join(",");

const CIPHERTEXT = "Y2lwaGVydGV4dA==";

/**
 * The handler is called directly rather than through SELF, because each case
 * needs its own bindings.
 *
 * SELF.fetch runs the Worker with the bindings from vitest.config.ts and there
 * is no per-request override, so a first attempt at this file passed three
 * arguments to SELF.fetch, had the third ignored, and asserted every case
 * against the same estate-wide configuration. Eleven tests failed at once,
 * which is the only reason it was noticed rather than reported as a pass.
 *
 * The Durable Object namespace comes from the test environment, because a real
 * one is needed and nothing here is asserting anything about it.
 */
async function call(
  method: "GET" | "POST",
  route: string,
  credential: string,
  bindings: Partial<Env>,
): Promise<{ status: number; reason: string }> {
  const url = `https://relay.test/v1/${route}${method === "GET" ? "?wait=0" : ""}`;
  const req = new Request(url, {
    method,
    headers: { authorization: `Bearer ${credential}` },
    body: method === "POST" ? JSON.stringify({ seq: 1, body: CIPHERTEXT }) : undefined,
  });
  const env = {
    QUEUE: testEnv.QUEUE,
    HELIOGRAPH_RELAY_ESTATES: "",
    ...bindings,
  } as Env;
  const resp = await worker.fetch(req, env);
  let reason = "";
  if (resp.status !== 202 && resp.status !== 200) {
    reason = ((await resp.json()) as { reason?: string }).reason ?? "";
  }
  return { status: resp.status, reason };
}

describe("per-station scope", () => {
  const scoped = { HELIOGRAPH_RELAY_STATIONS: SCOPES };

  it("lets each customer do its own work", async () => {
    expect((await call("POST", `${ESTATE}/alpha-01/c2s`, "alpha-ctl", scoped)).status).toBe(202);
    expect((await call("GET", `${ESTATE}/alpha-01/c2s`, "alpha-stn", scoped)).status).toBe(200);
    expect((await call("POST", `${ESTATE}/alpha-01/s2c`, "alpha-stn", scoped)).status).toBe(202);
  });

  // The test that tries. Every combination of the two customers' station names
  // and directions, with the other one's credentials.
  it("refuses one customer's credential against another's queues", async () => {
    for (const credential of ["alpha-stn", "alpha-ctl"]) {
      for (const dir of ["c2s", "s2c"]) {
        const route = `${ESTATE}/bravo-07/${dir}`;
        const wrote = await call("POST", route, credential, scoped);
        expect(wrote.status, `${credential} wrote to ${route}`).not.toBe(202);
        expect(wrote.reason).toBe("out-of-scope");
        const read = await call("GET", route, credential, scoped);
        expect(read.status, `${credential} read ${route}`).not.toBe(200);
      }
    }
  });

  // The asymmetry survives scoping. A station credential still may not queue a
  // request, even for its own station.
  it("still refuses a station credential queueing a request for itself", async () => {
    const r = await call("POST", `${ESTATE}/alpha-01/c2s`, "alpha-stn", scoped);
    expect(r.status).not.toBe(202);
    expect(r.reason).toBe("out-of-scope");
  });

  it("refuses a credential it has never heard of", async () => {
    const r = await call("POST", `${ESTATE}/alpha-01/c2s`, "not-a-credential", scoped);
    expect(r.reason).toBe("bad-credential");
  });
});

describe("a hosted tenant", () => {
  // The estate-wide configuration, behind a tenant that refuses estate-wide
  // credentials. Correct for a self-hoster, where one estate is one customer,
  // and a tenant boundary failure the moment an account holds two.
  const hosted = {
    HELIOGRAPH_RELAY_ESTATES: "shared-account:ctl:stn",
    HELIOGRAPH_RELAY_HOSTED: "1",
  };

  it("refuses an estate-wide credential, and says that is why", async () => {
    const r = await call("POST", "shared-account/st1/c2s", "ctl", hosted);
    expect(r.status).not.toBe(202);
    expect(r.reason).toBe("estate-wide-credential");
  });

  it("allows a station-scoped credential", async () => {
    const r = await call("POST", `${ESTATE}/alpha-01/c2s`, "alpha-ctl", {
      HELIOGRAPH_RELAY_STATIONS: SCOPES,
      HELIOGRAPH_RELAY_HOSTED: "1",
    });
    expect(r.status).toBe(202);
  });
});

describe("scope configuration", () => {
  // Refused rather than skipped. A skipped entry fails closed and is far harder
  // to diagnose: the relay starts, answers 401 for that station, and sends the
  // reader to the far side of a gap they cannot cross.
  const bad = [
    "e1:st1:station", // too few fields
    "e1:st1:wizard:cred", // not a role
    "e1::station:cred", // no station
    ":st1:station:cred", // no estate
    "e1:st1:station:", // no credential
    "e1:st1:station:same,e1:st1:control:same", // one credential, both roles
  ];

  it.each(bad)("refuses %s rather than skipping it", async (spec) => {
    const r = await call("POST", "e1/st1/c2s", "cred", {
      HELIOGRAPH_RELAY_STATIONS: spec,
    });
    // A configuration this relay could not read is not a statement about the
    // caller's credential, so it must not be reported as one.
    expect(r.reason).toBe("internal");
    expect(r.status).toBe(500);
  });
});
