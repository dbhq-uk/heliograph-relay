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

function fail(status: number, error: string): Response {
  return json({ error }, status);
}

function bearer(req: Request): string {
  const h = req.headers.get("authorization") ?? "";
  return h.startsWith("Bearer ") ? h.slice(7).trim() : "";
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
    return fail(405, "method not allowed");
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
      return fail(400, "could not read the message");
    }
    const body = parsed.body ?? "";
    // base64 is 4 characters per 3 bytes, so this bounds the decoded size
    // without decoding it. The body is never decoded here at all: decoding it
    // would be the first step towards reading it.
    if ((body.length * 3) / 4 > MAX_BODY_BYTES) {
      return fail(413, "message is larger than the relay will carry");
    }

    const q = await this.load();
    // A full queue means the recipient has stopped collecting. Refuse the
    // NEWEST rather than dropping the oldest: silently discarding an earlier
    // message leaves the recipient a gap it reads as a delivered sequence and
    // never learns about, while a refusal reaches the sender, which is the
    // side that can act on it.
    if (q.length >= MAX_QUEUE) {
      return fail(429, "this queue is full: the recipient is not collecting");
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
    if (parts.length !== 4 || parts[0] !== "v1") return fail(404, "no such route");
    const [, estate, station, dir] = parts;
    if (dir !== "c2s" && dir !== "s2c") {
      return fail(400, "a message must name a direction of c2s or s2c");
    }

    const estates = parseEstates(env.HELIOGRAPH_RELAY_ESTATES);
    const tokens = estates.get(estate);
    const tok = bearer(req);
    if (!tokens || !tok) {
      // An estate with no configured tokens must refuse, rather than treating
      // an absent entry as a match. That would authorise everybody.
      return fail(401, "not authorised for this estate");
    }
    const isControl = sameToken(tok, tokens.control);
    const isStation = sameToken(tok, tokens.station);
    if (!isControl && !isStation) return fail(401, "not authorised for this estate");

    if (req.method === "POST") {
      // Reading is symmetric; writing is not. A station credential sits on a
      // machine nobody can reach and cannot be rotated quickly, so it must not
      // be able to queue a request, even for its own station.
      const mayWrite = dir === "c2s" ? isControl : isStation;
      if (!mayWrite) {
        return fail(401, "not authorised to write that direction for this estate");
      }
    }

    const id = env.QUEUE.idFromName(`${estate}/${station}/${dir}`);
    return env.QUEUE.get(id).fetch(req);
  },
} satisfies ExportedHandler<Env>;
