import { evictDurableObject } from "cloudflare:test";
import { expect, it } from "vitest";
import {
  ack,
  CIPHERTEXT,
  leaseStatus,
  put,
  queued,
  route,
  seedLegacyQueue,
  sleep,
  stub,
  take,
  takeLeased,
} from "./helpers";

/**
 * Leased collection in the Worker: the same contract the Go server implements,
 * because two implementations that disagree about when a message is deleted are
 * two products.
 *
 * The assertions that need to be here rather than in conformance/ are the ones
 * that read Durable Object storage - that a leased message is still IN storage,
 * and that a lease survives the instance being torn down - because a client
 * cannot see either.
 *
 * heliograph-io/heliograph-cloud#9.
 */

it("holds a leased message in storage instead of deleting it", async () => {
  const r = route("lease");
  expect(await put(r, 1, CIPHERTEXT)).toBe(202);

  const held = await takeLeased(r);
  expect(held.messages).toHaveLength(1);
  expect(held.lease).not.toBe("");
  expect(held.until).not.toBe("");

  const still = await queued(r);
  expect(still?.map((m) => m.body)).toEqual([CIPHERTEXT]);
  expect(still?.[0].lease).toBe(held.lease);
});

it("deletes the message from storage when the lease is acknowledged", async () => {
  const r = route("lease");
  expect(await put(r, 1, CIPHERTEXT)).toBe(202);
  const held = await takeLeased(r);

  expect(await ack(r, held.lease)).toEqual({ status: 200, deleted: 1 });
  // No messages left. The record itself stays, holding the counters that stop an
  // id being reused, and nothing else - see storage-model.test.ts.
  expect(await queued(r)).toEqual([]);
});

it("gives the messages back when a collector dies without acknowledging", async () => {
  const r = route("lease");
  expect(await put(r, 5, CIPHERTEXT)).toBe(202);

  const held = await takeLeased(r, "300ms");
  expect(held.messages).toHaveLength(1);

  // The collector dies here. Nobody else may have the message yet.
  expect((await takeLeased(r)).messages).toHaveLength(0);

  await sleep(400);

  const back = await takeLeased(r);
  expect(back.messages).toHaveLength(1);
  // The same id, which is what lets a collector tell a redelivery from a second
  // message. Without it, deduplication has nothing to key on.
  expect(back.messages[0].id).toBe(held.messages[0].id);
  expect(back.lease).not.toBe(held.lease);
});

it("keeps a lease across a forced Durable Object eviction", async () => {
  const r = route("lease-evict");
  expect(await put(r, 1, CIPHERTEXT)).toBe(202);
  const held = await takeLeased(r);

  // The Worker keeps leases in storage, so an eviction does not release them.
  // The Go server keeps them in memory and a restart does release them; both
  // satisfy the contract, because both fail towards redelivery rather than loss.
  await evictDurableObject(stub(r));

  expect((await takeLeased(r)).messages).toHaveLength(0);
  expect(await ack(r, held.lease)).toEqual({ status: 200, deleted: 1 });
});

it("does not let a collection without a lease take what is leased", async () => {
  const r = route("lease");
  expect(await put(r, 1, CIPHERTEXT)).toBe(202);
  await takeLeased(r);

  expect(await take(r)).toHaveLength(0);
});

it("answers a collection without a lease exactly as before", async () => {
  const r = route("plain");
  for (const seq of [1, 2]) expect(await put(r, seq, CIPHERTEXT)).toBe(202);

  // A bare array, not an object: a station parsing this with jq '.[]' must not
  // have to know that leasing exists.
  const got = await take(r);
  expect(Array.isArray(got)).toBe(true);
  expect(got.map((m) => m.seq)).toEqual([1, 2]);
  expect(await queued(r)).toEqual([]);
});

it("refuses a lease that is too long, or not a duration", async () => {
  const r = route("badlease");
  expect(await put(r, 1, CIPHERTEXT)).toBe(202);

  for (const bad of ["nonsense", "1h", "-5s", "600", "1m30s"]) {
    expect(await leaseStatus(r, bad), bad).toBe(400);
  }
  // And the queue is untouched by a refused request.
  expect((await queued(r))?.length).toBe(1);
});

it("refuses an acknowledgement for a lease it is not holding", async () => {
  const r = route("ack");
  expect(await put(r, 1, CIPHERTEXT)).toBe(202);
  const held = await takeLeased(r);

  expect((await ack(r, "not-a-lease")).status).toBe(410);
  expect(await ack(r, held.lease)).toEqual({ status: 200, deleted: 1 });
  // A repeat of an acknowledgement that already worked, which is what a
  // collector retrying a request whose response it never saw sends.
  expect((await ack(r, held.lease)).status).toBe(410);
});

it("needs the collecting credential to acknowledge, and no other", async () => {
  const r = route("ack-scope");
  expect(await put(r, 1, CIPHERTEXT)).toBe(202);
  const held = await takeLeased(r);

  expect((await ack(r, held.lease, "")).status).toBe(401);
  expect((await ack(r, held.lease, "other-stn")).status).toBe(401);
  expect((await ack(r, held.lease, "stn")).status).toBe(200);
});

it("gives every message an id, leased or not", async () => {
  const r = route("ids");
  for (const seq of [1, 2]) expect(await put(r, seq, CIPHERTEXT)).toBe(202);

  const got = await take(r);
  expect(got).toHaveLength(2);
  expect(got[0].id).toBeTruthy();
  expect(got[1].id).toBeTruthy();
  expect(got[0].id).not.toBe(got[1].id);
});

// An id is never reused, including after the queue has been emptied. A collector
// deduplicates on it, so a second message wearing a retired id would be dropped
// as a duplicate of something it has nothing to do with.
it("does not reuse an id after the queue empties", async () => {
  const r = route("ids");
  expect(await put(r, 1, CIPHERTEXT)).toBe(202);
  const first = await take(r);
  expect(await queued(r)).toEqual([]);

  expect(await put(r, 2, CIPHERTEXT)).toBe(202);
  const second = await take(r);
  expect(second[0].id).not.toBe(first[0].id);
});

// The hosted relay may be holding queued messages when this is deployed, and they
// are stored in the shape that existed before leasing: a bare array, no ids, no
// counters. Losing them would be the defect this whole issue is about.
it("upgrades a queue stored in the shape that existed before leasing", async () => {
  const r = route("legacy");
  await seedLegacyQueue(r, [
    { seq: 41, body: CIPHERTEXT, at: Date.now() },
    { seq: 42, body: CIPHERTEXT, at: Date.now() },
  ]);

  const held = await takeLeased(r);
  expect(held.messages.map((m) => m.seq)).toEqual([41, 42]);
  expect(held.messages[0].id).toBeTruthy();
  expect(held.messages[0].id).not.toBe(held.messages[1].id);
  expect(await ack(r, held.lease)).toEqual({ status: 200, deleted: 2 });
});
