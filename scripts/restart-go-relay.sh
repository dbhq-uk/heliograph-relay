#!/bin/sh
# Start the Go relay, or restart it keeping its spool.
#
# This is the disruptor for `conformance -restart`. Durability is the one property
# in the contract a client cannot check for itself: it needs somebody to take the
# relay away between the put and the take. The suite deliberately cannot do that,
# so the mechanism lives here, next to the deployment it understands.
#
# Run it once to start the relay and again to restart it, which is what the suite
# does. Both paths go through the same pidfile, so nothing has to guess which
# process is the relay.
#
#   HELIOGRAPH_RELAY_BIN      the binary to run       (default ./heliograph-relay)
#   HELIOGRAPH_RELAY_SPOOL    the spool directory     (required: no spool, no durability)
#   HELIOGRAPH_RELAY_ADDR     listen address          (default :8080)
#   HELIOGRAPH_RELAY_ESTATES  estate tokens           (required)
#   HELIOGRAPH_RELAY_LOG      where to append output  (default /tmp/heliograph-relay.log)
#   HELIOGRAPH_RELAY_PIDFILE  where the pid is kept   (default /tmp/heliograph-relay.pid)
#
# A PIDFILE RATHER THAN pgrep. The first version of this matched the binary path
# with `pgrep -f` and killed everything it found, which included the shell that
# had started the suite, because that shell's command line mentioned the path.
# A test that can kill its own harness is worse than no test.
#
# SIGTERM and then wait, rather than SIGKILL. A relay that only survives a clean
# shutdown is not durable - but a run that cannot tell "the message was lost" from
# "the old process still held the port" proves nothing either way, and the second
# one is what a race for the port looks like.
set -eu

bin=${HELIOGRAPH_RELAY_BIN:-./heliograph-relay}
log=${HELIOGRAPH_RELAY_LOG:-/tmp/heliograph-relay.log}
pidfile=${HELIOGRAPH_RELAY_PIDFILE:-/tmp/heliograph-relay.pid}

: "${HELIOGRAPH_RELAY_SPOOL:?set it, or there is no durability to assert}"
: "${HELIOGRAPH_RELAY_ESTATES:?set it, or nothing can authenticate}"

if [ -f "$pidfile" ]; then
  pid=$(cat "$pidfile")
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    i=0
    while [ "$i" -lt 100 ] && kill -0 "$pid" 2>/dev/null; do
      sleep 0.1
      i=$((i + 1))
    done
    if kill -0 "$pid" 2>/dev/null; then
      echo "restart-go-relay: pid $pid did not exit" >&2
      exit 1
    fi
  fi
  rm -f "$pidfile"
fi

"$bin" >>"$log" 2>&1 &
echo $! >"$pidfile"
echo "restart-go-relay: pid $(cat "$pidfile"), spool $HELIOGRAPH_RELAY_SPOOL" >&2
