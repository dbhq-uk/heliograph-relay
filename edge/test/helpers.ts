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
  seq: number;
  body: string;
  at: number;
}

/** A collected message, as a client sees it. */
export interface TakenMsg {
  seq: number;
  body: string;
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
export function queued(route: string): Promise<StoredMsg[] | undefined> {
  return runInDurableObject(stub(route), (_instance, state) =>
    state.storage.get<StoredMsg[]>("q"),
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

export async function take(route: string): Promise<TakenMsg[]> {
  const resp = await SELF.fetch(`https://relay.test/v1/${route}?wait=0`, {
    headers: { authorization: "Bearer stn" },
  });
  return (await resp.json()) as TakenMsg[];
}
