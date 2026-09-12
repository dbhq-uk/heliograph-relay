import { env, runInDurableObject, SELF } from "cloudflare:test";
import { expect, it } from "vitest";

/**
 * The storage model, asserted here because conformance/ has no way to see it.
 *
 * The README's Storage table claims this implementation keeps its queue in
 * Durable Object storage, "which is persistent", and deletes on collection.
 * Both halves are read here from storage directly, because a client cannot tell
 * the difference over HTTP - which is how heliograph-io/heliograph-cloud#47
 * happened.
 *
 * storage_test.go is the Go half of the same pair.
 */

const CIPHERTEXT = "Y2lwaGVydGV4dA==";

// A fresh station per test, as the conformance suite does, so one test never
// reads another's leftovers and reports a pass it did not earn.
let n = 0;
function route(): string {
  return `e1/storage-${++n}/c2s`;
}

interface StoredMsg {
  seq: number;
  body: string;
  at: number;
}

function queued(route: string): Promise<StoredMsg[] | undefined> {
  const stub = env.QUEUE.get(env.QUEUE.idFromName(route));
  return runInDurableObject(stub, (_instance, state) =>
    state.storage.get<StoredMsg[]>("q"),
  );
}

async function put(route: string, seq: number, body: string): Promise<number> {
  const resp = await SELF.fetch(`https://relay.test/v1/${route}`, {
    method: "POST",
    headers: { authorization: "Bearer ctl" },
    body: JSON.stringify({ seq, body }),
  });
  return resp.status;
}

async function take(route: string): Promise<number> {
  const resp = await SELF.fetch(`https://relay.test/v1/${route}?wait=0`, {
    headers: { authorization: "Bearer stn" },
  });
  const got = (await resp.json()) as unknown[];
  return got.length;
}

it("puts an accepted message in Durable Object storage, not in memory", async () => {
  const r = route();
  expect(await put(r, 1, CIPHERTEXT)).toBe(202);

  const stored = await queued(r);
  expect(stored?.map((m) => ({ seq: m.seq, body: m.body }))).toEqual([
    { seq: 1, body: CIPHERTEXT },
  ]);
});

it("keeps nothing in storage once the message has been collected", async () => {
  const r = route();
  expect(await put(r, 1, CIPHERTEXT)).toBe(202);
  expect(await take(r)).toBe(1);

  // Not an empty array left behind: the key itself goes, because "deleted on
  // collection" is the claim and a retained empty queue would still be a row
  // in somebody's storage bill.
  expect(await queued(r)).toBeUndefined();
});
