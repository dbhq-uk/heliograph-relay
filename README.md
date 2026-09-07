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

## Tokens are not the security boundary

The bearer tokens exist for routing, rate limiting and abuse control. They carry
no confidentiality or authenticity role whatsoever.

**A stolen token yields denial of service and metadata, never content and never
execution.** Saying so plainly matters, because "we use scoped tokens" is
exactly the kind of claim that gets mistaken for the real protection.

They are asymmetric on purpose: a **station** token may read requests and write
status and logs, and may **not** queue a request, even for its own station. A
station credential sits on a machine nobody can reach and cannot be rotated
quickly.

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

It **refuses to start** with no estates configured. Starting and answering 401
to everything looks exactly like a credential problem at the far end, and sends
the reader to the wrong side of the gap.

It also refuses an estate whose two tokens are identical, since that collapses
the only scope separation there is.

## Storage

In memory. Deleted on collection, expired after seven days, never written to
disk.

A relay that persisted would be a relay with a backup, and a backup of
ciphertext is a liability that has to be explained to every customer who asks
what happens to their data. The cost is that a restart drops undelivered
messages, which costs a re-run - a price heliograph already accepts everywhere
else.

## API

```
POST /v1/{estate}/{station}/{dir}    queue a message   (dir: c2s | s2c)
GET  /v1/{estate}/{station}/{dir}    collect, long-polling by default
GET  /health
```

`GET` holds the connection for up to 25 seconds waiting for a message, so an
idle station costs one held connection rather than a request every few seconds.
Add `?wait=0` to return immediately.

Long-poll rather than WebSocket, deliberately. A station runs behind a corporate
proxy that may strip an upgrade header, and a transport that fails on those
estates fails on exactly the estates this exists for.

## Licence

[MIT](LICENSE) (c) 2026 DBHQ Consulting Ltd
