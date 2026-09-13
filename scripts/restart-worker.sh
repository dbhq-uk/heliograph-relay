#!/bin/sh
# Start `wrangler dev --local`, or restart it keeping its Durable Object storage.
#
# The disruptor for `conformance -restart` against the Worker. Run it once to
# start, again to restart, which is what the suite does. Works from the repository
# root or from edge/.
#
#   WRANGLER_PORT      the port to serve on     (default 8787)
#   WRANGLER_PERSIST   the state directory      (default .wrangler/conformance-state)
#   WRANGLER_ESTATES   estate tokens            (default the conformance pair)
#   WRANGLER_LEASE_KEY authorisation lease key  (default the contract's public key)
#   WRANGLER_LOG       where to append output   (default /tmp/wrangler.log)
#   WRANGLER_PIDFILE   where the pid is kept    (default /tmp/wrangler-dev.pid)
#
# SIGINT rather than SIGKILL, and then wait for it to go. That is not politeness.
# Killing the whole process tree at once was observed to lose a message that had
# already been acknowledged: `wrangler dev --local` keeps Durable Object storage
# in miniflare's SQLite, and the write-ahead log had not been checkpointed. That
# is a property of the local emulator and not of Cloudflare's Durable Object
# storage, but it turns a hard kill into a test of miniflare rather than of the
# relay.
#
# What a graceful restart still proves: the process dies and every Durable Object
# instance dies with it, so the message either comes back from storage or does not
# come back at all.
#
# A pidfile rather than pgrep, for the reason in restart-go-relay.sh: pgrep -f
# matches command lines, and a caller that merely mentions the pattern gets
# killed by it.
set -eu

port=${WRANGLER_PORT:-8787}
persist=${WRANGLER_PERSIST:-.wrangler/conformance-state}
estates=${WRANGLER_ESTATES:-e1:ctl:stn,e2:other-ctl:other-stn}
# The contract's published Ed25519 PUBLIC key, so a worker started by this
# script honours the leases the suite mints. A test fixture rather than a
# secret: the matching seed is a constant in conformance/, and the relay holds
# only this half. heliograph-io/heliograph-cloud#75.
lease_key=${WRANGLER_LEASE_KEY:-79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664}
log=${WRANGLER_LOG:-/tmp/wrangler.log}
pidfile=${WRANGLER_PIDFILE:-/tmp/wrangler-dev.pid}

# `[ -d edge ] && cd edge` would have exited 1 here under set -e when already
# inside edge/, which reads as the restart having failed.
if [ -d edge ]; then cd edge; fi

if [ -f "$pidfile" ]; then
  pid=$(cat "$pidfile")
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    kill -INT "$pid" 2>/dev/null || true
    i=0
    while [ "$i" -lt 300 ] && kill -0 "$pid" 2>/dev/null; do
      sleep 0.1
      i=$((i + 1))
    done
    if kill -0 "$pid" 2>/dev/null; then
      echo "restart-worker: pid $pid did not exit" >&2
      exit 1
    fi
  fi
  rm -f "$pidfile"
fi

# node_modules/.bin/wrangler rather than npx, so the recorded pid is wrangler's
# own and a signal reaches it rather than a wrapper that may not pass it on.
./node_modules/.bin/wrangler dev --port "$port" --local --persist-to "$persist" \
  --var HELIOGRAPH_RELAY_ESTATES:"$estates" \
  --var HELIOGRAPH_RELAY_LEASE_KEY:"$lease_key" >>"$log" 2>&1 &
echo $! >"$pidfile"
echo "restart-worker: pid $(cat "$pidfile"), port $port, state $persist" >&2
