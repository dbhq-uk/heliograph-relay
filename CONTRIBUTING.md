# Contributing

This server is deliberately small. Most of what follows exists to keep it that
way, because the claim it makes about itself is only checkable while it stays
readable in an afternoon.

## Run what CI runs, before you open a pull request

```bash
gofmt -l .                        # must print nothing
go vet ./...
go test ./... -count=1 -race

cd edge && npm install && npx tsc --noEmit
```

And drive the real thing, because tests passing is not the same as the thing
working:

```bash
go build ./cmd/heliograph-relay
HELIOGRAPH_RELAY_ESTATES="e1:ctl:stn,e2:other-ctl:other-stn" ./heliograph-relay &
go run ./cmd/conformance http://localhost:8080 "go binary"
```

## The three rules that are not style

These are enforced by [`.github/workflows/validate.yml`](.github/workflows/validate.yml),
and they are the reasons anybody trusts this component.

### No dependencies at all

`go.sum` must not exist. This server stores bytes and moves them. Anything it
needed a library for would be something it should not be doing, and every
dependency is a third party who can change what is in the path of somebody
else's estate.

### No cryptography beyond a constant-time token comparison

`crypto/sha256` and `crypto/subtle` only, in Go, and none at all in the Worker.
The security claim is that there is no key here to leak and no plaintext to
subpoena, and the way that claim stays checkable is that a reviewer can grep for
it.

**Do not weaken this rule to make a feature fit.** If something genuinely needs
a primitive the rule forbids, say so in the issue with the options and their
costs, and let somebody decide. Hand-rolling a primitive in order to pass the
grep is worse than importing one, because it evades the check rather than
satisfying it.

### One contract, every implementation

There are two implementations: the Go server here and the Cloudflare Worker in
`edge/`. [`conformance/`](conformance/) holds the contract, asserted over HTTP,
and CI runs it against both. An implementation that has not passed it is not
permitted to be deployed.

A change to one implementation's behaviour is a change to the other's, or it is
drift, and drift is the defect. Add the assertion to `conformance/` first and
watch both go red.

## The no-fork discipline

**The relay we deploy is built from this source with nothing added.**

Anything a hosted service needs - accounts, estates, quota, policy, metering -
lives behind the `Authoriser` seam in [`auth.go`](auth.go) and is reached over
HTTP by `RemoteAuth`. It does not live in this repository, and it does not live
in a private branch of this repository either.

Three things die at once if that is broken, and it is worth being precise about
which:

1. **The claim stops being checkable.** A customer can compare the hash of the
   running binary against a build of this source. "Trust us" becomes "here is
   the hash". A fork makes that unprovable for ever, and it cannot be recovered
   later by promising harder.
2. **The licence does not save anybody.** There is no copyleft here, so nothing
   legally obliges a hosted operator to keep the relay stock. That is exactly
   why the discipline has to be written down rather than left to the licence.
3. **Self-hosting stays complete.** A self-hoster runs the same binary with
   `StaticAuth`, or with `RemoteAuth` pointed at their own directory, and gets
   the whole transport. Nothing is withheld in the carrier.

The practical form of the rule: **if a hosted service needs something, widen the
interface here and publish it.** `RemoteAuth` is in this repository, tested by
this repository's conformance suite, and usable by anybody with an authoriser of
their own. That is the shape every future addition takes.

## Test first, and watch the test fail

A check nobody has watched fail is a check nobody knows works.

For every new assertion: write the test, run it, **watch it fail**, put that
failure in the pull request, then make it pass. For a test that guards a claim,
break the claim on purpose once and watch the guard catch it.

Two examples of what this catches, both real. `TestARefusalWithNoReasonStillRefuses`
exists because the zero value of `Reason` is "allowed", so a refusal that named
no reason answered **200 with an error body in it**. Nothing else would have
found that, because every test that refuses also names a reason.

## House style

- British English
- Plain hyphens. No em dashes and no en dashes
- No trailing full stops on headings
- **Cite, do not assert.** Every claim about code carries a `file:line`. If you
  have not opened the file, do not describe what is in it
- **Never state an inference as an observation.** "A 4m12s gap in output", not
  "stalled for 4m12s"
- **Never write "cannot" where the truth is "does not currently"**
- A commit message title is a sentence stating the finding, not a noun phrase,
  and the body says what changed and what it cost

## Reporting a vulnerability

Email rather than opening a public issue. See [SECURITY.md](SECURITY.md).
