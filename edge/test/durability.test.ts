import { evictDurableObject } from "cloudflare:test";
import { expect, it } from "vitest";
import { CIPHERTEXT, put, route, stub, take } from "./helpers";

/**
 * A message the sender was told had been accepted survives a Durable Object
 * lifecycle transition.
 *
 * This is the claim the hosted relay's promise rests on, and until now it rested
 * on reading worker.ts. A Durable Object can be torn down at any time - a
 * deploy, an eviction, the platform moving it - and the sender is not told. If
 * the queue lived in the instance rather than in storage, a station that pushed
 * an hour-long capture, got its 202 and deleted its own copy would be the last
 * holder of a message that no longer exists.
 *
 * `evictDurableObject` is the transition, forced: it tears the instance down,
 * resetting in-memory state, and preserves durable storage. Nothing reachable
 * over HTTP can do that, which is why this assertion is here rather than in
 * conformance/ - see heliograph-io/heliograph-cloud#8.
 */

it("keeps an accepted message across a forced Durable Object eviction", async () => {
  const r = route("evict");
  expect(await put(r, 7, CIPHERTEXT)).toBe(202);

  await evictDurableObject(stub(r));

  expect(await take(r)).toEqual([{ seq: 7, body: CIPHERTEXT }]);
});

it("keeps every queued message across the transition, in order", async () => {
  const r = route("evict");
  for (const seq of [1, 2, 3]) {
    expect(await put(r, seq, CIPHERTEXT)).toBe(202);
  }

  await evictDurableObject(stub(r));

  // Order matters here for a reason that is not about the relay: seq is signed
  // end to end and the recipient enforces it, so a queue that came back
  // reordered would be a queue the far side rejects rather than one it
  // silently mis-reads.
  expect((await take(r)).map((m) => m.seq)).toEqual([1, 2, 3]);
});
