import { runInDurableObject } from "cloudflare:test";
import { expect, it } from "vitest";
import { put, route, stub } from "./helpers";

/**
 * What a retained message costs in Durable Object storage, measured rather than
 * assumed.
 *
 * Durable Object storage is billed, so durability is the moment the broker stops
 * being free memory and starts being a line on a bill. The cost model issue
 * (heliograph-io/heliograph-cloud#12) needs a number per retained message, and
 * the only honest way to get one is to ask the storage how big it got.
 *
 * These print their measurements, so a CI run carries the figures rather than
 * only a pass. The assertions are bounds rather than exact sizes: SQLite page
 * sizes and its own bookkeeping are not this repository's business, but "roughly
 * the message, once" is, and a regression to storing several copies of a body
 * would break it.
 */

/** Durable Object storage in bytes, as the platform itself reports it. */
function databaseSize(r: string): Promise<number> {
  return runInDurableObject(stub(r), (_instance, state) =>
    Number(state.storage.sql.databaseSize),
  );
}

// base64 of n raw bytes, which is what a sealed body arrives as and what is
// stored. The inflation is part of the cost and is reported as part of it.
function base64Body(raw: number): string {
  return btoa("x".repeat(raw));
}

const KIB = 1024;

it.each([
  { raw: 1 * KIB },
  { raw: 64 * KIB },
  { raw: 512 * KIB },
])("costs about the message itself to retain $raw raw bytes", async ({ raw }) => {
  const r = route("cost");
  const body = base64Body(raw);
  const empty = await databaseSize(r);

  expect(await put(r, 1, body)).toBe(202);
  const held = await databaseSize(r);

  const cost = held - empty;
  const perStored = cost / body.length;
  // eslint-disable-next-line no-console -- the measurement is the point
  console.log(
    `retained: raw ${raw} B, stored as base64 ${body.length} B, ` +
      `Durable Object storage grew ${cost} B (${perStored.toFixed(2)}x the stored form, ` +
      `${(cost / raw).toFixed(2)}x the raw body)`,
  );

  // It stored the message, once, and not a second copy of it.
  expect(cost).toBeGreaterThan(body.length * 0.9);
  expect(cost).toBeLessThan(body.length * 1.5 + 16 * KIB);
});

// The cost that is not per message but per put, and the one that matters more
// for a deep queue: the whole queue is one stored value, so every put rewrites
// every message already in it.
it("rewrites the whole queue on every put, which is what a deep queue costs", async () => {
  const r = route("cost-depth");
  const body = base64Body(16 * KIB);
  const sizes: number[] = [];
  for (let i = 1; i <= 8; i++) {
    expect(await put(r, i, body)).toBe(202);
    sizes.push(await databaseSize(r));
  }
  // eslint-disable-next-line no-console -- the measurement is the point
  console.log(
    `storage after each of 8 puts of ${body.length} B: ${sizes.join(", ")} B`,
  );

  // Storage grows linearly with depth, as it must. The write amplification is
  // not visible in the size, and is stated in the README instead: put number n
  // writes a value holding all n messages, so filling a queue to DefaultMaxQueue
  // writes O(n squared) bytes. That is a cost, not a defect, and the cost model
  // issue is where it is being sized.
  expect(sizes[7]).toBeGreaterThan(sizes[0]);
  expect(sizes[7]).toBeGreaterThan(8 * body.length * 0.9);
});
