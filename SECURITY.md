# Security

## Reporting a vulnerability

Email <dan@dbhq.uk> rather than opening a public issue. Include what you found,
how to reproduce it, and what an attacker could do with it. You will get a first
response within 48 hours.

## What happens next

The timeline is Google Project Zero's, because it is the one the industry already
recognises and there is no reason to invent another.

A report is **urgent** when there is a credible way to exploit it today *and* the
damage would be material. Both, not either.

| | fixed within | advisory published |
|---|---|---|
| **urgent** | 7 days | 30 days after the fix, and never later than day 60 |
| **everything else** | 90 days | 30 days after the fix, and never later than day 120 |

**The 30 days between the fix and the advisory is for you.** It is there so an
operator can upgrade before the details are public. This runs in estates with
slow change control, and publishing the day a patch exists would expose exactly
the people the patch was for.

If something is still unfixed when its deadline arrives, a **defensive notice**
goes out anyway: affected versions, what it lets an attacker do, how to spot it
and how to mitigate it, without a working exploit.

**These are commitments rather than aspirations.** If one is missed, the advisory
says so and says why.

Every confirmed finding is published once its fix has shipped, **in full rather
than summarised**, including the reasoning about why the old design was the wrong
shape. Where something is removed the advisory names the category, so you can
tell a redaction from an argument that was never made.

**Nobody is ahead of you in the queue.** Hosted users get no earlier warning of a
relay vulnerability than self-hosters do.

### A published claim that turns out to be false

A claim in the documentation can be wrong in the way code can, and this process
covers it. Report one the same way, privately, rather than opening a public
issue: until it is corrected, a public issue is a signpost to the gap between
what the documentation promises and what the service does.

Which clock applies turns on exposure, not on how bad the sentence reads:

| | clock |
|---|---|
| the documentation described a protection that is not there | the table above, and an advisory is published |
| the service was already doing the stronger thing and the documentation described the weaker one | none. Nobody was exposed by the gap, so there is nothing to disclose on a deadline |

Either way the correction is **published in the document that carried the
claim**, and says what that document used to say. A sentence offered as a reason
to trust the design does not get quietly edited, because somebody may have
approved this relay on the strength of it.

The Storage section of the [README](README.md) is this in practice. It had said
messages were held in memory and "never written to disk", which was true of the
Go binary and false of the Worker that is actually deployed, and that Worker was
persisting every message so that an accepted one could not be lost. The second
clock applied: the correction states the old sentence, why it was wrong, and
what each implementation does now
([#1](https://github.com/dbhq-uk/heliograph-relay/pull/1)).

The same policy, in full, is in
[heliograph's `SECURITY.md`](https://github.com/dbhq-uk/heliograph/blob/main/SECURITY.md).

## What this server is, and what it is not

The relay stores and forwards **opaque ciphertext** between a control and a
station. It holds **no private key**, never sees plaintext, and touches
cryptography in exactly one place and in one direction: it **verifies**
authorisation lease signatures and cannot produce one. That is the whole design,
and the files that have to be true for it are small enough to read in one
sitting: `relay.go`, `server.go` and `verify.go`.

> **This section used to say the relay "holds no keys, does no crypto".** It is
> corrected here rather than quietly edited, under the policy above.
>
> Which clock applies: **the second one, so no advisory and no deadline.** The
> old sentence described the relay as doing *less* than it does, and nobody was
> exposed by the gap. Verifying a signature with a public key adds no key worth
> stealing, and the change was published with the reasoning before it shipped
> ([heliograph-io/heliograph-cloud#75](https://github.com/dbhq-uk/heliograph-relay/blob/main/CONTRIBUTING.md)).
>
> What changed and why: an authorisation lease is minted by a control plane and
> handed to a relay that has never seen it before, so honouring one means
> checking a signature. Without that the relay would have to refuse every lease,
> which would remove the control-plane outage protection from the hosted relay
> almost every customer uses. HMAC was rejected: it is symmetric, so a relay able
> to verify would be a relay able to **mint**, and that ends the claim rather
> than narrowing the sentence.

This matters more than usual, because the relay is the one component that a
compromise would put in the middle of somebody's estate.

### Tokens are not the security boundary for content

The bearer tokens exist for routing, rate limiting and abuse control. **A stolen
token yields denial of service and metadata, never content and never execution.**

Content is protected by the sealing layer, which the relay has no part in. A
request is signed by the control's Ed25519 key and verified at the station. The
relay cannot forge one, because it does not hold the signing half.

**But "not the security boundary" is only true of content.** Collection,
availability, tenant isolation and metadata all rest on the token, and a
destructive collection means a stolen token can cause silent loss rather than
silent disclosure. Anybody reasoning about this should read that sentence with
its qualifier attached.

Leased collection does not change that, and it is worth being exact about why.
A lease means a collector that **dies** loses nothing, because the messages come
back when the lease expires. It is requested by the client, so a thief holding a
stolen token simply does not request one and collects destructively exactly as
before. The lease removes accidental loss, which is the common case; the
deliberate case still needs the token not to be stolen.

### The two scopes are asymmetric on purpose

A **station** token may read requests and write status and logs. A **control**
token may write requests and read logs. Neither may do the other's half, so a
station token lifted from a machine nobody can reach cannot be used to queue a
request, even for its own station. `server.go` is where that is enforced and why.

An estate whose two tokens are identical is refused, because that collapses the
only scope separation there is. The Go server refuses to start and names the
estate (`cmd/heliograph-relay/main.go:107-112`). The Worker skips that estate
(`edge/src/worker.ts:125`), which fails closed but is harder to diagnose.

### Storage

Held only until collected, or seven days, whichever comes first. See the Storage
section of the [README](README.md) for what each implementation actually does,
including where they differ, because they do.

**Both can hold it durably, and for the Go binary that is now a deployment
choice.** The Worker writes to Durable Object storage; the Go binary writes one
file per message to `HELIOGRAPH_RELAY_SPOOL` when that is set, and holds messages
in memory only when it is not. Durable means written before the sender is told the
message was accepted, and deleted on collection or at seven days, whichever comes
first. It does not mean archived, and there is no second copy anywhere.

Each claim there is asserted in that implementation's own tests -
`storage_test.go` for the Go server, `edge/test/storage-model.test.ts` for the
Worker. Not in `conformance/`, which is asserted over HTTP: a storage model is
not observable to a client, so a conformance run cannot tell memory from disk and
a green one is not evidence about either.

### What a compromised relay could still do

Stated rather than implied, because "it cannot read your logs" is the interesting
half and not the whole answer. A relay that was fully compromised could:

- **deny service**, by dropping, delaying or refusing messages
- **see metadata**: which estates and stations are active, when, how often, and
  how large their messages are
- **replay** a message it previously accepted, which the station's replay counter
  is there to catch

It could **not** read a message, forge one a station will accept, or cause a
station to run anything, because all three need key material it does not have.

If you need the metadata half covered too, run your own. That is why it is one
container with no keys, and no state worth backing up: a spool holds ciphertext
nobody here can read, only until the recipient has it. Losing it loses the
messages not yet collected, which is an availability cost; reading it reveals
nothing, because the bodies are sealed and the keys are not here. A backup would
protect against the first and extend the exposure of the second, which is why the
window is shortened instead.
