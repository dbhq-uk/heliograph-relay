#!/usr/bin/env bash
# =============================================================================
#  reproduce.sh - build the Worker bundle and print its hash
# =============================================================================
#     edge/reproduce.sh              # bundle into edge/dist, print the sha256
#     edge/reproduce.sh /tmp/out     # somewhere else
#
#  THE DEPLOY WORKFLOW RUNS THIS FILE, and the number it prints is what the
#  deployed Worker reports at /health as `hash`. So the check a stranger makes
#  is a real comparison rather than a restatement:
#
#     git clone --branch v0.1.0 https://github.com/dbhq-uk/heliograph-relay
#     cd heliograph-relay && edge/reproduce.sh
#     curl -s https://relay.heliograph.io/health
#
#  Same hash, and the bundle serving your traffic is the source you just read.
#  A different hash means the deployment is not this tag, and that is worth
#  knowing loudly.
#
#  WHAT MAKES IT DETERMINISTIC:
#
#    npm ci        installs the lockfile exactly. `npm install` is allowed to
#                  resolve wrangler within ^4 and pick up a newer bundler, and
#                  a different esbuild emits a different bundle
#    --dry-run     builds and uploads nothing, so this needs no credential and
#                  no account. Anybody can run it
#    no timestamps the bundle carries none. Measured: the same source built in
#                  two directories, with no shared node_modules, produced
#                  identical bytes
#
#  WHAT IS NOT PROMISED. That the bundle Cloudflare is serving is this one.
#  The Worker cannot read its own code, so /health reports the hash the deploy
#  workflow computed from the source it deployed - a public log of a public
#  workflow, which is a weaker thing than a self-attesting binary and is said
#  plainly rather than dressed up. What this script gives you is the other
#  half: the number that hash has to equal if the deployment is the tag.
#
#  Full account: https://heliograph.dbhq.uk/provenance
# =============================================================================
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${1:-$here/dist}"
cd "$here"

command -v npm >/dev/null 2>&1 || {
  echo "reproduce.sh: npm is needed to build the Worker bundle" >&2
  exit 2
}

# Quiet, because the interesting output of this script is one line and a
# thousand lines of npm above it is how a hash gets missed.
npm ci --no-fund --no-audit --silent

rm -rf "$out"
npx wrangler deploy --dry-run --outdir "$out" >/dev/null

bundle="$out/worker.js"
[ -f "$bundle" ] || {
  echo "reproduce.sh: wrangler produced no $bundle" >&2
  exit 1
}

echo "wrangler: $(npx wrangler --version 2>/dev/null | tail -1)"
echo "bundle:   $bundle ($(wc -c < "$bundle") bytes)"
echo "sha256:   $(sha256sum "$bundle" | cut -d' ' -f1)"
