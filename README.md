<div align="center">

# heliograph-relay

**Stores and forwards ciphertext it cannot read**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Part of [heliograph](https://github.com/dbhq-uk/heliograph), by [DBHQ](https://dbhq.uk)

</div>

---

## What this is

The relay for [heliograph](https://github.com/dbhq-uk/heliograph): a queue that
lets a control and a station reach each other when neither can reach the other
directly. Both sides dial **out** over ordinary HTTPS, so an estate needs no git
host, no storage account, no VNet and no inbound firewall rule.

## What it can and cannot do

**There is no cryptography in this repository.** That is the design, not an
omission. Every message arrives already sealed by the client and bound to its
estate, station, direction and sequence number, and signed. This server sees a
byte slice, a routing key and a length.

That is what makes the claim checkable: there is no key here to leak, no
plaintext to subpoena, and no code path that could be persuaded to produce
either. You can establish it by reading `relay.go` and `server.go` rather than
by trusting whoever is running it.

**It can:**

- see which estate is talking to which station, how often, and how big the messages are
- refuse to deliver, or delay delivery

**It cannot:**

- read a message
- alter one without the recipient noticing
- forge one, in either direction
- replay one, because sequence numbers are signed and enforced by the recipient

The last one matters most. A relay that could forge a request would have code
execution inside every estate at once, through a channel the customer installed
deliberately and trusts. That is a far worse position than reading logs, and it
is why authenticity comes before confidentiality in the design.

### What is NOT hidden

Message sizes and timing. The relay knows roughly how long a log was and roughly
how long a step took. Padding was considered and rejected for now: it costs
bandwidth on links that are often poor, and the leak is coarse. It is stated
here rather than implied away.

## Tokens are not the security boundary for content or execution

Content and execution are settled by signatures this server cannot make. Every
message arrives already sealed, and every request is signed by a key the relay
does not hold, so **a stolen token yields no plaintext and cannot cause a
station to run anything.** Saying so plainly matters, because "we use scoped
tokens" is exactly the kind of claim that gets mistaken for the real protection.

**They are the boundary for four other things, and all four matter to whoever
is paying for the transport:**

| a stolen token lets somebody | and the cost is |
|---|---|
| **collect** a queue | ciphertext they cannot read - and the legitimate collector never gets it, because collecting deletes. Silent loss, not silent disclosure |
| **fill** a queue to `DefaultMaxQueue` | the real sender gets a 429 and delivery stops |
| **spend** whatever the operator is metering | denial of service, on somebody else's bill |
| **cross a tenant boundary**, wherever one authoriser serves several customers | one customer's routing keys reachable with another's credential |

The first row is the one that changed. This section used to say "a stolen token
yields denial of service and metadata", and that sentence was written when a
lost message cost a re-run. `Store.Take` (`relay.go:131`) deletes in the same
breath as it returns, and on this transport the sender is often a station nobody
can log into, holding the only copy of an hour-long capture. A re-run is not
always available, because the state that produced the log has moved on.

Leased collection would change that row from "silent loss" to "a nuisance", and
it is open work rather than something this server does today. See
[What is still outstanding](#what-is-still-outstanding).

So treat a station token as a credential worth protecting, even though it cannot
read anything.

Tokens are asymmetric on purpose: a **station** token may read requests and
write status and logs, and may **not** queue a request, even for its own
station. A station credential sits on a machine nobody can reach and cannot be
rotated quickly.

## Run it

```bash
CTL=$(head -c 32 /dev/urandom | base64)
STN=$(head -c 32 /dev/urandom | base64)

docker run -p 8080:8080 \
  -e HELIOGRAPH_RELAY_ESTATES="payments:$CTL:$STN" \
  ghcr.io/dbhq-uk/heliograph-relay:latest
```

Or from source:

```bash
go build ./cmd/heliograph-relay
HELIOGRAPH_RELAY_ESTATES="payments:$CTL:$STN" ./heliograph-relay
```

Put it behind a TLS terminator. The relay speaks plain HTTP on purpose: TLS
belongs to whatever is already terminating it, and a server that also managed
certificates would be a bigger thing to audit for no gain.

## Configuration

| | |
|---|---|
| `HELIOGRAPH_RELAY_ADDR` | listen address, default `:8080` |
| `HELIOGRAPH_RELAY_ESTATES` | `estate:controlToken:stationToken`, comma separated |
| `HELIOGRAPH_RELAY_AUTHORISER` | a URL that answers authorisation decisions. When set, estates are that service's business and `HELIOGRAPH_RELAY_ESTATES` is not read |

It **refuses to start** with neither configured. Starting and answering 401
to everything looks exactly like a credential problem at the far end, and sends
the reader to the wrong side of the gap.

It also refuses an estate whose two tokens are identical, since that collapses
the only scope separation there is.

## Bring your own authoriser

Set `HELIOGRAPH_RELAY_AUTHORISER` and the relay asks that URL instead of reading
tokens from its environment. Accounts, estates, quota, policy and metering
become whatever answers it, and none of that is added to the code in the path.

```
POST https://authz.example/decide
{"credential":"...","estate":"e1","station":"st1","dir":"c2s","op":"write","bytes":812}

200 OK
{"allow":false,"reason":"wrong-direction","detail":"optional sentence for the caller"}
```

The request is routing, an operation and a length. **No body, no stream, nothing
that could be followed to content.** `bytes` is a size, not a sample.

**Only a 200 is a decision.** Anything else - a refused connection, a timeout, a
500, a 403 about the relay's own credential to the authoriser - is treated as
the authoriser being unreachable, and the relay answers **503** with
`"reason":"authoriser-unavailable"`. It does not answer 401. A 401 sends
somebody to check a token on a machine they cannot reach while the fault is on
this side, which is the worst hour this transport can cost anybody.

Decisions are cached: 30 seconds for a yes, 5 for a no. A no expires sooner
because reusing a stale yes keeps a revoked credential alive and reusing a stale
no keeps a repaired one dead, and neither number removes the trade.
Unavailability is **not** cached at all, so the relay recovers as soon as the
authoriser does.

The Worker takes the same variable and speaks the same wire, and CI runs the
same conformance suite against both, including an outage the suite causes
itself.

### The authoriser never touches a message

Not as a rule it is asked to follow, but as something the types make impossible.
The seam is three interfaces in `auth.go`, and none of them can carry bytes:

| | |
|---|---|
| `Admission` | may this proceed, and what does it reserve. Can cap one operation below the server's own limit |
| `Accounting` | what it actually cost: bytes moved, messages, outcome, duration. Settled after the fact, because a declared size is a number the payer chose |
| `Sessions` | whether the authority behind something already open has been withdrawn. A long poll is held for 25 seconds, and "authorise every call" says nothing about a call still in progress |

`TestAnAuthoriserCannotObtainAMessageBody` walks every parameter and every
return value on that surface by reflection and fails on anything that could
carry, reference or yield bytes. It is an allowlist rather than a denylist,
because the thing nobody thought of is how this sort of claim usually breaks.

The conformance suite checks the same thing against a **running** relay: it puts
a recognisable pattern of bytes through, then reads back every byte the
authoriser was sent and fails if the pattern is in there. Both implementations
run it.

This is what lets the claim sharpen rather than weaken when an operator's
authoriser is proprietary: **the thing that touches your ciphertext is readable,
and the thing that is not readable never touches it.**

### Why this rather than a fork

The relay a hosted operator deploys is built from this source with nothing
added, so a customer can compare a hash instead of trusting an operator. That is
only true while everything a hosted service needs fits behind this seam, which
is why the seam is here and published rather than kept private. See
[CONTRIBUTING.md](CONTRIBUTING.md).

### Every refusal says why

Beside the sentence, in a field a program can read.

| `reason` | status | |
|---|---|---|
| `no-credential` | 401 | no bearer token |
| `bad-credential` | 401 | the token is not one this relay knows |
| `wrong-direction` | 401 | a good token used for the other side's half |
| `authoriser-unavailable` | 503 | **our** fault, not yours |
| `bad-route` | 400 | not an estate, a station and `c2s` or `s2c` |
| `unreadable-request` | 400 | the envelope would not parse |
| `too-large` | 413 | over `MaxBodyBytes` |
| `queue-full` | 429 | the recipient has stopped collecting |

The sentence is for a person and the reason is for a program, because a client
that has to match on English prose breaks when the prose improves.

## Where to run it

Two implementations, one contract. `conformance/` holds it, asserted over HTTP,
and CI runs it against **both**. An implementation that has not passed it does
not get deployed.

| | |
|---|---|
| **Cloudflare Worker + Durable Object** (`edge/`) | cheapest, global, and the one to reach for |
| **Go binary or container** (this repository) | anywhere else: a VM, Fly, Cloud Run, or inside a customer's own estate |

### Why a Worker rather than the Go binary in a Container

Cloudflare Containers would run the Go binary unmodified, and it was rejected on
cost rather than capability. Every long poll holds a request open, which is
exactly the "idle in memory but unable to hibernate" case that bills Durable
Object wall-clock time **anyway** - so you would pay the DO cost *and* the
container cost, plus egress, for the same behaviour.

A Durable Object is also simply the right shape: single-threaded and consistent,
which is what a queue wants, with one object per estate, station and direction so
that one busy estate cannot make another wait.

### Why a second implementation is acceptable here

Because this server is trivial. It is a queue with a TTL and a token check, and
it holds no keys, so the whole of it can still be audited in an afternoon in
either language. The end-to-end guarantee is untouched: it cannot read a message
in TypeScript any more than it can in Go.

The real cost is drift, and that is answered the same way heliograph answers it
everywhere else - one specification, several implementations, and none of them
trusted until it has passed.

The hosted relay deploys **on a tag**, through
[`.github/workflows/deploy.yml`](.github/workflows/deploy.yml):

```bash
git tag v0.3.0 && git push --tags
```

The workflow runs the contract first, deploys, then **polls the live relay until
`/version` reports the commit it just built**. A green deploy step with the old
code still answering is exactly the drift this is meant to catch, so deploying
and having deployed are checked separately.

Pushing to `main` deploys nothing. The relay other people's stations are talking
to should change on a deliberate act.

Secrets required: `CLOUDFLARE_API_TOKEN` scoped to Workers deploy on this account,
and `CLOUDFLARE_ACCOUNT_ID`. `HELIOGRAPH_RELAY_ESTATES` stays a wrangler secret,
set once and never in CI.

### Deploying by hand, if you must

```bash
cd edge
npx wrangler secret put HELIOGRAPH_RELAY_ESTATES   # estate:controlToken:stationToken
npx wrangler deploy --var VERSION:"$(git rev-parse HEAD)"
```

**Do not drop the `--var`.** Without it the deployment answers
`{"version":"unknown"}` and nobody, including whoever deployed it, can tell which
commit is running. A relay whose proposition is that you can read it before you
run it ought to be able to say which "it" you are reading.

This is also why the workflow exists: a human can pass the wrong commit to
`--var` and the endpoint will repeat it confidently. CI stamps the commit it
actually built.

## Identity

Two endpoints, neither of which needs a token, because "the relay you are talking
to is the relay you read" is not checkable if you need a credential to ask which
relay it is.

```bash
curl https://heliograph-relay.dbhq.uk/version
{"service":"heliograph-relay","implementation":"worker","version":"<commit>",...}
```

`GET /version` gives the service, which implementation is answering, the commit
it was built from, and where the source is. `GET /` gives the same plus a
sentence on what this server is and a link to the documentation, because
somebody who found the hostname in a config file and pasted it into a browser
deserves better than a bare 404.

**`version` is never an empty string.** An unstamped build reports `unknown`,
which is a true answer somebody can act on, where a blank field reads as a fault
in whatever asked.

**What this does not yet do**, said plainly because the gap matters: a version
string is a claim by the deployment about itself. It is not provenance. It does
not prove the running code was built from that commit, and nothing here signs an
artefact or verifies one before it is promoted. That is open work, and until it
lands the honest statement is "the relay reports which commit it believes it is",
not "the relay is provably the source you read".

## Storage

**Held only until collected, or seven days, whichever comes first.** Then
deleted. Nothing is kept after either.

**The two implementations differ in how they hold it, and that matters enough to
state rather than average over:**

| | how | what a restart does |
|---|---|---|
| **Worker + Durable Object** (`edge/`) | Durable Object storage, which is persistent | nothing. A message you were told was accepted is still there |
| **Go binary** (this repository) | in memory | drops undelivered messages, which costs a re-run |

The Worker is the one deployed at `heliograph-relay.dbhq.uk`, so the hosted
relay **does write to disk** inside that window.

This documentation previously said "in memory ... never written to disk" of both,
which was true of the Go binary and false of the Worker. That is corrected here
rather than quietly edited, because the sentence was offered as a reason to trust
the design and somebody may have relied on it.

### Why persisting in that window is the better answer anyway

The original argument was that a relay which persisted would be a relay with a
backup, and a backup of ciphertext is a liability that has to be explained to
every customer who asks what happens to their data. That argument is right about
**long** retention and it was wrong to express as "never to disk".

A Durable Object can lose in-memory state on a lifecycle transition. So an
in-memory queue means a sender can receive a 200, delete its own copy believing
the message delivered, and lose it - and on this transport the sender is often a
station nobody can log into, holding the only copy of an hour-long capture. A
re-run is not always available, because the state that produced the log has moved
on.

So the honest promise is not "we never write it down". It is **"we write it down
only for as long as it takes you to collect it, and then we delete it"** - which
is a shorter window than most systems and, unlike the previous sentence, is
actually kept.

### What is still outstanding

- the Go binary is **not** durable, so a self-hoster running the container gets
  the weaker guarantee. Making the two agree is open work
- collection is destructive on acknowledgement rather than leased, so the window
  between the relay deleting and the collector durably storing is still a place a
  message can be lost. Leasing is open work
- `conformance/` cannot assert any of this: it is asserted over HTTP, and the
  storage model is not observable to a client. So storage claims are **not**
  conformance-enforced, and each implementation asserts its own instead:
  [`storage_test.go`](storage_test.go) for the Go server, and
  [`edge/test/storage-model.test.ts`](edge/test/storage-model.test.ts) for the
  Worker, which reads Durable Object storage directly because nothing over HTTP
  can

## API

```
POST /v1/{estate}/{station}/{dir}    queue a message   (dir: c2s | s2c)
GET  /v1/{estate}/{station}/{dir}    collect, long-polling by default
GET  /health                         liveness, no token
GET  /version                        which commit is answering, no token
GET  /                               the same, plus what this server is
```

`GET` on a queue holds the connection for up to 25 seconds waiting for a
message. Add `?wait=0` to return immediately.

**The long poll is available; the bash station does not use it.** It fetches
`?wait=0` on an interval that defaults to five seconds. This README used to say
"an idle station costs one held connection rather than a request every few
seconds", which is the opposite of what the shipped station does, and the
sentence was being quoted as the basis for cost reasoning. Corrected here rather
than edited away, because a wrong reason is worse than no reason once somebody
has built on it.

What an idle station actually costs has not been measured, and the two shapes
are not close enough to guess between: a held connection bills wall-clock
duration on a Durable Object, where a short poll bills a request. Neither number
belongs in this file until somebody has run it.

Long-poll rather than WebSocket, deliberately. A station runs behind a corporate
proxy that may strip an upgrade header, and a transport that fails on those
estates fails on exactly the estates this exists for.

## Licence

[MIT](LICENSE) (c) 2026 DBHQ Consulting Ltd
