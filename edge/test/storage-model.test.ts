import { expect, it } from "vitest";
import { CIPHERTEXT, put, queued, route, take } from "./helpers";

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

it("puts an accepted message in Durable Object storage, not in memory", async () => {
  const r = route("storage");
  expect(await put(r, 1, CIPHERTEXT)).toBe(202);

  const stored = await queued(r);
  expect(stored?.map((m) => ({ seq: m.seq, body: m.body }))).toEqual([
    { seq: 1, body: CIPHERTEXT },
  ]);
});

it("keeps nothing in storage once the message has been collected", async () => {
  const r = route("storage");
  expect(await put(r, 1, CIPHERTEXT)).toBe(202);
  expect(await take(r)).toHaveLength(1);

  // Not an empty array left behind: the key itself goes, because "deleted on
  // collection" is the claim and a retained empty queue would still be a row
  // in somebody's storage bill.
  expect(await queued(r)).toBeUndefined();
});
