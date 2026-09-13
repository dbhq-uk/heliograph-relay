import { env, runInDurableObject, SELF } from "cloudflare:test";

/**
 * The little that both test files need, in one place so the two cannot drift
 * about what a put or a take is.
 *
 * Requests go through SELF rather than straight to the Durable Object, so the
 * auth path, the route parsing and the object lookup are all exercised: a test
 * that talks to the object directly proves the object works and nothing about
 * the Worker in front of it.
 */

export const CIPHERTEXT = "Y2lwaGVydGV4dA==";

/** A stored queue entry, as the Worker writes it. */
export interface StoredMsg {
  id: string;
  seq: number;
  body: string;
  at: number;
  /** The collector currently holding it, if any, and until when. */
  lease?: string;
  until?: number;
}

/** The whole stored value for one route. */
export interface StoredQueue {
  v: number;
  n: number;
  l: number;
  msgs: StoredMsg[];
}

/** A collected message, as a client sees it. */
export interface TakenMsg {
  id: string;
  seq: number;
  body: string;
}

/** A leased collection, as a client sees it. */
export interface LeaseReply {
  lease: string;
  until: string;
  messages: TakenMsg[];
}

// A fresh station per test, as the conformance suite does, so one test never
// reads another's leftovers and reports a pass it did not earn.
let n = 0;
export function route(what: string): string {
  return `e1/${what}-${++n}/c2s`;
}

export function stub(route: string) {
  return env.QUEUE.get(env.QUEUE.idFromName(route));
}

/** What is actually in Durable Object storage for a route, if anything. */
export function stored(route: string): Promise<StoredQueue | undefined> {
  return runInDurableObject(stub(route), (_instance, state) =>
    state.storage.get<StoredQueue>("q"),
  );
}

/** The messages in Durable Object storage for a route, if any. */
export async function queued(route: string): Promise<StoredMsg[] | undefined> {
  return (await stored(route))?.msgs;
}

/**
 * Writes the storage shape a queue had before leasing existed: a bare array of
 * messages with no ids and no counters. The hosted relay may be holding exactly
 * this when the change is deployed, and those messages must not be lost.
 */
export function seedLegacyQueue(
  route: string,
  msgs: { seq: number; body: string; at: number }[],
): Promise<void> {
  return runInDurableObject(stub(route), (_instance, state) =>
    state.storage.put("q", msgs),
  );
}

export async function put(
  route: string,
  seq: number,
  body: string,
): Promise<number> {
  const resp = await SELF.fetch(`https://relay.test/v1/${route}`, {
    method: "POST",
    headers: { authorization: "Bearer ctl" },
    body: JSON.stringify({ seq, body }),
  });
  return resp.status;
}

export async function take(route: string, query = ""): Promise<TakenMsg[]> {
  const resp = await SELF.fetch(
    `https://relay.test/v1/${route}?wait=0${query}`,
    { headers: { authorization: "Bearer stn" } },
  );
  return (await resp.json()) as TakenMsg[];
}

/** Collect under a lease, which holds the messages rather than deleting them. */
export async function takeLeased(
  route: string,
  lease = "30s",
  query = "",
): Promise<LeaseReply> {
  const resp = await SELF.fetch(
    `https://relay.test/v1/${route}?wait=0&lease=${lease}${query}`,
    { headers: { authorization: "Bearer stn" } },
  );
  if (resp.status !== 200) {
    throw new Error(`lease ${route}: ${resp.status} ${await resp.text()}`);
  }
  return (await resp.json()) as LeaseReply;
}

/** The status of a leased collection, for the cases that are meant to fail. */
export async function leaseStatus(
  route: string,
  lease: string,
): Promise<number> {
  const resp = await SELF.fetch(
    `https://relay.test/v1/${route}?wait=0&lease=${lease}`,
    { headers: { authorization: "Bearer stn" } },
  );
  return resp.status;
}

export async function ack(
  route: string,
  lease: string,
  token = "stn",
): Promise<{ status: number; deleted?: number }> {
  const resp = await SELF.fetch(`https://relay.test/v1/${route}/ack`, {
    method: "POST",
    headers: token === "" ? {} : { authorization: `Bearer ${token}` },
    body: JSON.stringify({ lease }),
  });
  if (resp.status !== 200) return { status: resp.status };
  const body = (await resp.json()) as { deleted: number };
  return { status: resp.status, deleted: body.deleted };
}

/** Real time, because the Workers runtime's clock is not ours to move. */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
