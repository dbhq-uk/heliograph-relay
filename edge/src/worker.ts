/**
 * The heliograph relay, on Cloudflare's edge.
 *
 * A second implementation of the same contract as the Go server in this
 * repository. It exists because the shapes genuinely differ: a Durable Object
 * is how you hold a queue at the edge, and a Go binary is how you run one
 * anywhere else. Neither is a port of the other.
 *
 * The cost of a second implementation is drift, and drift is only dangerous
 * when it is untested. `conformance/` holds the contract, asserted over HTTP,
 * and CI runs it against BOTH. An implementation that has not passed it is not
 * permitted to be deployed.
 *
 * THERE IS NO CRYPTOGRAPHY HERE EITHER, and for the same reason. Every message
 * arrives already sealed and signed by the client. This code sees a base64
 * string, a routing key and a length. There is no key to leak and no plaintext
 * to subpoena, in this language or the other one.
 */

export interface Env {
  QUEUE: DurableObjectNamespace;
  /** estate:controlToken:stationToken, comma separated. A secret, not a var. */
  HELIOGRAPH_RELAY_ESTATES: string;
  /**
   * When set, decisions are fetched from here rather than read out of
   * HELIOGRAPH_RELAY_ESTATES. This is the seam the hosted service lives behind:
   * tenants, estates, quota and billing belong to whatever answers this URL,
   * and none of it is added to the code in the data path.
   *
   * The Go server's RemoteAuth speaks the same wire shape, and the conformance
   * suite runs the same assertions against both. heliograph-io/heliograph-cloud#7.
   */
  HELIOGRAPH_RELAY_AUTHORISER?: string;
  /**
   * The commit this was deployed from. A var rather than a secret, because the
   * entire point is that anybody can read it and compare it against `main`.
   * Set at deploy: `wrangler deploy --var VERSION:$(git rev-parse HEAD)`.
   */
  VERSION?: string;
}

const WHAT_IT_IS =
  "Stores and forwards opaque ciphertext between a control and a station. " +
  "It holds no keys, does no crypto, and never sees plaintext.";
const SOURCE_URL = "https://github.com/dbhq-uk/heliograph-relay";
const DOCS_URL = "https://heliograph.dbhq.uk/relay";

// A browser asking for / must get a page, not a download prompt. Returning
// application/json makes mobile Safari offer the response as a file, which is
// what somebody who pasted this hostname into a phone actually saw. Machines
// still get JSON, because the endpoint is also how a check reads the version.
function wantsHTML(req: Request): boolean {
  const accept = req.headers.get("accept") ?? "";
  return accept.includes("text/html");
}

function landingHTML(version: string): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>heliograph relay</title>
<style>
 body{background:#111;color:#eee;font:15px/1.7 ui-monospace,SFMono-Regular,Menlo,monospace;margin:0;padding:2.5rem 1.25rem;max-width:34rem}
 h1{font-size:1rem;margin:0;font-weight:600}
 p{color:#8b8b8b;margin:.25rem 0 1.75rem}
 a{color:#6cf;display:block}
 code{color:#8b8b8b;word-break:break-all}
</style></head><body>
<h1>heliograph relay</h1>
<p>Stores and forwards ciphertext it cannot read.</p>
<code>${version}</code>
<a href="${SOURCE_URL}">source</a>
<a href="${DOCS_URL}">docs</a>
</body></html>`;
}

function html(body: string): Response {
  return new Response(body, {
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

// Never an empty string. A deploy with no version stamped says "unknown",
// which is a true answer an operator can act on, where a blank field reads as
// a bug in whatever asked.
function reportedVersion(env: Env): string {
  return env.VERSION && env.VERSION !== "" ? env.VERSION : "unknown";
}

const MAX_BODY_BYTES = 8 << 20; // 8 MiB, as the Go server
const MAX_QUEUE = 256;
const TTL_MS = 7 * 24 * 60 * 60 * 1000;
const HOLD_MS = 25_000;

interface Msg {
  seq: number;
  body: string; // base64, exactly as it arrives and leaves
  at: number;
}

/** Constant-time comparison, so a token is not discoverable by timing. */
function sameToken(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

interface Tokens {
  control: string;
  station: string;
}

function parseEstates(spec: string): Map<string, Tokens> {
  const out = new Map<string, Tokens>();
  for (const entry of (spec ?? "").split(",")) {
    const parts = entry.trim().split(":");
    if (parts.length !== 3) continue;
    const [estate, control, station] = parts;
    if (!estate || !control || !station) continue;
    // One token for both sides collapses the only scope separation there is,
    // and a station credential could then queue requests. Refused here as the
    // Go server refuses it at startup.
    if (control === station) continue;
    out.set(estate, { control, station });
  }
  return out;
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/**
 * Why a request was refused.
 *
 * The same set of strings the Go server uses, because a client that has to
 * learn two vocabularies to talk to two relays is a client that learns one and
 * breaks on the other.
 *
 * The distinction that carries weight is the last group against the first. A
 * 401 sends somebody to check a token on a machine they cannot reach; if the
 * real fault is that the authoriser is down, that is hours on the wrong side of
 * the gap, on a transport whose entire proposition is reaching machines when
 * things are broken.
 */
type Reason =
  | "no-credential"
  | "bad-credential"
  | "wrong-direction"
  | "authoriser-unavailable"
  | "bad-route"
  | "unreadable-request"
  | "too-large"
  | "queue-full"
  | "internal";

const STATUS: Record<Reason, number> = {
  "no-credential": 401,
  "bad-credential": 401,
  "wrong-direction": 401,
  "authoriser-unavailable": 503,
  "bad-route": 400,
  "unreadable-request": 400,
  "too-large": 413,
  "queue-full": 429,
  internal: 500,
};

const DETAIL: Record<Reason, string> = {
  "no-credential": "not authorised for this estate",
  "bad-credential": "not authorised for this estate",
  "wrong-direction": "not authorised to write that direction for this estate",
  "authoriser-unavailable":
    "the authoriser could not be reached, so this request was neither allowed nor refused",
  "bad-route": "a message must name an estate, a station and a direction of c2s or s2c",
  "unreadable-request": "could not read the message",
  "too-large": "message is larger than the relay will carry",
  "queue-full": "this queue is full: the recipient is not collecting",
  internal: "could not accept the message",
};

/**
 * Every refusal carries a sentence for a person and a reason for a program.
 *
 * Two fields rather than one, because a caller that has to match on English
 * prose is a caller that breaks when the prose improves.
 */
function fail(reason: Reason, detail?: string): Response {
  return json({ error: detail ?? DETAIL[reason], reason }, STATUS[reason]);
}

function bearer(req: Request): string {
  const h = req.headers.get("authorization") ?? "";
  return h.startsWith("Bearer ") ? h.slice(7).trim() : "";
}

/**
 * What an authoriser is told about an attempt.
 *
 * Note what is absent, and permanently absent: the message body, any stream
 * that could yield one, and the Request it arrived on. Routing, an operation
 * and a length, and there is no field here anybody could follow to content.
 * `bytes` is a size, not a sample.
 */
interface DecisionRequest {
  credential: string;
  estate: string;
  station: string;
  dir: string;
  op: "read" | "write";
  bytes: number;
}

interface Grant {
  allow: boolean;
  /** Absent when allowed. A refusal always names one. */
  reason?: Reason;
}

/** Decisions held between requests, so an idle poll is not an authz call. */
interface CachedGrant {
  grant: Grant;
  until: number;
}

const POSITIVE_MS = 30_000;
const NEGATIVE_MS = 5_000;
/**
 * A cap, because this Map outlives a request and an isolate that never forgets
 * a decision is an isolate that eventually forgets everything at once. Clearing
 * wholesale rather than evicting cleverly: the cost of a cold cache is one
 * round trip, and the cost of an eviction policy is code in the data path.
 */
const MAX_CACHED = 4096;
const decisions = new Map<string, CachedGrant>();

function decisionKey(d: DecisionRequest): string {
  return [d.credential, d.estate, d.station, d.dir, d.op].join("|");
}

/** The static answer, read out of HELIOGRAPH_RELAY_ESTATES. */
function admitStatic(env: Env, d: DecisionRequest): Grant {
  if (!d.credential) return { allow: false, reason: "no-credential" };
  const tokens = parseEstates(env.HELIOGRAPH_RELAY_ESTATES).get(d.estate);
  // An estate with no configured tokens must refuse, rather than treating an
  // absent entry as a match. That would authorise everybody.
  if (!tokens) return { allow: false, reason: "bad-credential" };

  const isControl = sameToken(d.credential, tokens.control);
  const isStation = sameToken(d.credential, tokens.station);
  if (!isControl && !isStation) return { allow: false, reason: "bad-credential" };
  // Reading is symmetric; writing is not. A station credential sits on a
  // machine nobody can reach and cannot be rotated quickly, so it must not be
  // able to queue a request, even for its own station.
  if (d.op === "read") return { allow: true };
  const mayWrite = d.dir === "c2s" ? isControl : isStation;
  // A good credential used in the wrong direction is not a bad credential, and
  // reporting it as one is what gets a station rotated on a machine nobody can
  // reach, for nothing.
  return mayWrite ? { allow: true } : { allow: false, reason: "wrong-direction" };
}

/**
 * The fetched answer.
 *
 * Only 200 is a decision. A 401 or a 403 from the authoriser is about the
 * relay's own credential to it, and a 500 is about the authoriser, and neither
 * is a statement about the caller. Treating them as refusals is exactly how a
 * deployment fault gets reported as a token fault.
 *
 * Unavailability is never cached. Caching it would extend our outage past its
 * own end, which is the opposite of what the cache is for.
 */
async function admitRemote(url: string, d: DecisionRequest): Promise<Grant> {
  const key = decisionKey(d);
  const held = decisions.get(key);
  if (held && held.until > Date.now()) return held.grant;

  let grant: Grant;
  try {
    const resp = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(d),
      // Short, because this sits in front of every request including a long
      // poll. A slow authoriser must become an outage quickly rather than
      // holding the caller's connection open alongside our own.
      signal: AbortSignal.timeout(3_000),
    });
    if (resp.status !== 200) return { allow: false, reason: "authoriser-unavailable" };
    const out = (await resp.json()) as { allow?: boolean; reason?: string };
    grant = {
      allow: out.allow === true,
      // A refusal with no reason still refuses, and names itself, because a
      // blank reason would leave the caller guessing which side is broken.
      reason: (out.reason as Reason) || "bad-credential",
    };
  } catch {
    return { allow: false, reason: "authoriser-unavailable" };
  }

  if (decisions.size >= MAX_CACHED) decisions.clear();
  // A no expires sooner than a yes, because reusing a stale yes keeps a revoked
  // credential alive and reusing a stale no keeps a repaired one dead. Neither
  // number removes the trade.
  decisions.set(key, {
    grant,
    until: Date.now() + (grant.allow ? POSITIVE_MS : NEGATIVE_MS),
  });
  return grant;
}

async function admit(env: Env, d: DecisionRequest): Promise<Grant> {
  const url = env.HELIOGRAPH_RELAY_AUTHORISER;
  if (!url) return admitStatic(env, d);
  if (!d.credential) return { allow: false, reason: "no-credential" };
  return admitRemote(url, d);
}

/**
 * One queue, for one estate, station and direction.
 *
 * A Durable Object is single-threaded and consistent, which is exactly what a
 * queue wants and exactly what a Worker on its own cannot give you. Splitting
 * by route rather than by estate means one busy estate cannot make another
 * wait.
 */
export class RelayQueue implements DurableObject {
  private state: DurableObjectState;
  /** Requests waiting for a message, so a put can wake them immediately. */
  private waiters: Array<() => void> = [];

  constructor(state: DurableObjectState) {
    this.state = state;
  }

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    if (req.method === "POST") return this.put(req);
    if (req.method === "GET") return this.take(url);
    return json({ error: "method not allowed", reason: "bad-route" }, 405);
  }

  private async load(): Promise<Msg[]> {
    const stored = (await this.state.storage.get<Msg[]>("q")) ?? [];
    const cut = Date.now() - TTL_MS;
    const live = stored.filter((m) => m.at >= cut);
    if (live.length !== stored.length) await this.save(live);
    return live;
  }

  private async save(q: Msg[]): Promise<void> {
    if (q.length === 0) await this.state.storage.delete("q");
    else await this.state.storage.put("q", q);
  }

  private async put(req: Request): Promise<Response> {
    let parsed: { seq?: number; body?: string };
    try {
      parsed = (await req.json()) as { seq?: number; body?: string };
    } catch {
      return fail("unreadable-request");
    }
    const body = parsed.body ?? "";
    // base64 is 4 characters per 3 bytes, so this bounds the decoded size
    // without decoding it. The body is never decoded here at all: decoding it
    // would be the first step towards reading it.
    if ((body.length * 3) / 4 > MAX_BODY_BYTES) {
      return fail("too-large");
    }

    const q = await this.load();
    // A full queue means the recipient has stopped collecting. Refuse the
    // NEWEST rather than dropping the oldest: silently discarding an earlier
    // message leaves the recipient a gap it reads as a delivered sequence and
    // never learns about, while a refusal reaches the sender, which is the
    // side that can act on it.
    if (q.length >= MAX_QUEUE) {
      return fail("queue-full");
    }
    q.push({ seq: parsed.seq ?? 0, body, at: Date.now() });
    await this.save(q);

    const woken = this.waiters;
    this.waiters = [];
    for (const wake of woken) wake();
    return new Response(null, { status: 202 });
  }

  private async take(url: URL): Promise<Response> {
    let q = await this.load();
    if (q.length === 0 && url.searchParams.get("wait") !== "0") {
      // Long-poll rather than WebSocket. A station runs behind a corporate
      // proxy that may strip an upgrade header, and a transport that fails on
      // those estates fails on exactly the estates this exists for.
      await new Promise<void>((resolve) => {
        const timer = setTimeout(() => {
          this.waiters = this.waiters.filter((w) => w !== wake);
          resolve();
        }, HOLD_MS);
        const wake = () => {
          clearTimeout(timer);
          resolve();
        };
        this.waiters.push(wake);
      });
      q = await this.load();
    }
    const limit = Number(url.searchParams.get("limit") ?? "0");
    let out = q;
    if (limit > 0 && q.length > limit) {
      out = q.slice(0, limit);
      await this.save(q.slice(limit));
    } else {
      await this.save([]);
    }
    // Delete on collection, not on a separate acknowledgement. A second round
    // trip would mean holding ciphertext longer in exchange for surviving a
    // client that crashes mid-read, and that client can ask for the step
    // again - a cost heliograph already accepts everywhere else.
    return json(out.map((m) => ({ seq: m.seq, body: m.body })));
  }
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname === "/health") return json({ ok: true });

    // /version exists so that "the relay you are talking to is the relay you
    // read" is checkable rather than asserted. Without it nobody, including
    // whoever deployed it, can tell which commit is answering.
    if (url.pathname === "/version") {
      return json({
        service: "heliograph-relay",
        implementation: "worker",
        version: reportedVersion(env),
        source: SOURCE_URL,
      });
    }

    // The one request a human makes. Somebody who found this hostname in a
    // config file and pasted it into a browser used to get a bare 404, which
    // tells them nothing about what they have found or whether it is theirs.
    if (url.pathname === "/") {
      if (wantsHTML(req)) return html(landingHTML(reportedVersion(env)));
      return json({
        service: "heliograph-relay",
        implementation: "worker",
        version: reportedVersion(env),
        what: WHAT_IT_IS,
        source: SOURCE_URL,
        docs: DOCS_URL,
      });
    }

    // /v1/{estate}/{station}/{dir}
    const parts = url.pathname.split("/").filter(Boolean);
    if (parts.length !== 4 || parts[0] !== "v1") {
      return json({ error: "no such route", reason: "bad-route" }, 404);
    }
    const [, estate, station, dir] = parts;
    // The direction is route shape, not credential scope, so it is refused
    // before the authoriser is asked and refused as a 400. Asking about a
    // direction that does not exist would bill a decision for a typo.
    if (dir !== "c2s" && dir !== "s2c") return fail("bad-route");

    const grant = await admit(env, {
      credential: bearer(req),
      estate,
      station,
      dir,
      op: req.method === "POST" ? "write" : "read",
      // A length, never a sample. Absent means the client did not say, which
      // the Go server reports the same way.
      bytes: Number(req.headers.get("content-length") ?? -1),
    });
    if (!grant.allow) return fail(grant.reason ?? "bad-credential");

    const id = env.QUEUE.idFromName(`${estate}/${station}/${dir}`);
    return env.QUEUE.get(id).fetch(req);
  },
} satisfies ExportedHandler<Env>;
