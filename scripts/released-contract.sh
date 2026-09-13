#!/bin/sh
# Run the contract as it was at the last release against the relay as it is now.
#
# WHY THIS EXISTS. conformance/ moves with the code, so a change that alters the
# wire and updates the suite in the same commit passes it. That is the whole
# defect class this guards: every station already deployed speaks the RELEASED
# contract, and it does not get recompiled when this repository does.
#
# So the released suite is extracted from its tag and run unchanged. If it fails,
# a deployed station would have failed too.
#
#   ./scripts/released-contract.sh http://localhost:8787 "worker"
#   HELIOGRAPH_RELAY_RELEASE=v0.1.1 ./scripts/released-contract.sh ...
#
# Needs tags: in CI that means actions/checkout with fetch-depth 0, or a
# `git fetch --tags`. If there is no tag it says so and stops rather than passing
# quietly, because a compatibility check that silently checked nothing is how a
# station breaks on a Tuesday.
#
# When the wire deliberately changes in a way the old suite cannot accept, the fix
# is to release, not to weaken this: the tag moves forward and the old contract
# goes with it.
set -eu

base=${1:?usage: released-contract.sh <base-url> [name]}
name=${2:-released contract}
tag=${HELIOGRAPH_RELAY_RELEASE:-}

if [ -z "$tag" ]; then
  tag=$(git describe --tags --abbrev=0 2>/dev/null || true)
fi
if [ -z "$tag" ]; then
  echo "released-contract: no tag found, so there is no released contract to check" >&2
  echo "released-contract: fetch tags (git fetch --tags), or set HELIOGRAPH_RELAY_RELEASE" >&2
  exit 1
fi

dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
git archive "$tag" | tar -x -C "$dir"

echo "released-contract: running $tag's own suite against $base" >&2
cd "$dir"
go run ./cmd/conformance "$base" "$name, against $tag's contract"
