import { expect, it } from "vitest";
import { CIPHERTEXT, put, queued, route, stored, take } from "./helpers";

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

it("keeps no message in storage once it has been collected", async () => {
  const r = route("storage");
  expect(await put(r, 1, CIPHERTEXT)).toBe(202);
  expect(await take(r)).toHaveLength(1);

  // No messages, and no ciphertext anywhere in what is left.
  //
  // What IS left is the record's counters, and that is a deliberate change from
  // deleting the key outright. An id must never be reused - a collector
  // deduplicates on it, so a new message wearing a retired id would be dropped as
  // a duplicate of something unrelated - and a counter that restarts when a queue
  // empties reuses ids. About thirty bytes per route, and none of it is anybody's
  // data. See heliograph-io/heliograph-cloud#9.
  const left = await stored(r);
  expect(left?.msgs).toEqual([]);
  expect(JSON.stringify(left)).not.toContain(CIPHERTEXT);
  expect(left?.n).toBeGreaterThan(1);
});
