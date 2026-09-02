#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
AUDIT_TMP_BASE=${TMPDIR:-/tmp}
AUDIT_TMP_BASE=${AUDIT_TMP_BASE%/}
AUDIT_ROOT=$(mktemp -d "$AUDIT_TMP_BASE/deaddrop-listeners.XXXXXX")
SERVER_PID=
WATCHDOG_PID=

fail() {
    echo "listener audit failed: $*" >&2
    exit 1
}

cleanup() {
    if [ -n "$WATCHDOG_PID" ] && kill -0 "$WATCHDOG_PID" 2>/dev/null; then
        kill -TERM "$WATCHDOG_PID" 2>/dev/null || true
        wait "$WATCHDOG_PID" 2>/dev/null || true
    fi
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    case "$AUDIT_ROOT" in
        "$AUDIT_TMP_BASE"/deaddrop-listeners.*)
            if [ -d "$AUDIT_ROOT" ]; then
                rm -rf -- "$AUDIT_ROOT"
            fi
            ;;
        *)
            echo "refusing to clean unexpected audit path: $AUDIT_ROOT" >&2
            ;;
    esac
}
trap cleanup EXIT HUP INT TERM

command -v cargo >/dev/null 2>&1 || fail "cargo is required"
command -v lsof >/dev/null 2>&1 || fail "lsof is required"

cd "$REPO_ROOT"
cargo build --locked --target-dir "$REPO_ROOT/target" -p deaddrop-server --bin deaddrop

SERVER_LOG="$AUDIT_ROOT/server.stderr"
"$REPO_ROOT/target/debug/deaddrop" debug \
    --bind 127.0.0.1:0 \
    --data-dir "$AUDIT_ROOT/state" \
    2>"$SERVER_LOG" &
SERVER_PID=$!

ATTEMPT=0
while ! grep -q '"event":"debug_listener_started"' "$SERVER_LOG"; do
    kill -0 "$SERVER_PID" 2>/dev/null || {
        sed -n '1,20p' "$SERVER_LOG" >&2
        fail "debug server exited before reporting readiness"
    }
    ATTEMPT=$((ATTEMPT + 1))
    [ "$ATTEMPT" -lt 200 ] || fail "debug server did not become ready within ten seconds"
    sleep 0.05
done

LISTENERS=$(lsof -nP -a -p "$SERVER_PID" -iTCP -sTCP:LISTEN -Fn 2>/dev/null \
    | sed -n 's/^n//p')
LISTENER_COUNT=$(printf '%s\n' "$LISTENERS" | sed '/^$/d' | wc -l | tr -d ' ')
[ "$LISTENER_COUNT" -eq 1 ] || fail "expected one TCP listener for PID $SERVER_PID, found $LISTENER_COUNT: $LISTENERS"

LISTENER=$(printf '%s\n' "$LISTENERS" | sed -n '1p')
case "$LISTENER" in
    127.0.0.1:*) ;;
    *) fail "listener is not IPv4 loopback: $LISTENER" ;;
esac
PORT=${LISTENER##*:}
case "$PORT" in
    ''|*[!0-9]*) fail "listener port is not numeric: $LISTENER" ;;
esac
[ "$PORT" -gt 0 ] || fail "listener used port zero after bind"

REPORTED_BIND=$(sed -n 's/.*"bind":"\([^"]*\)".*/\1/p' "$SERVER_LOG" | tail -n 1)
[ "$REPORTED_BIND" = "$LISTENER" ] || fail "reported bind $REPORTED_BIND does not match lsof $LISTENER"

kill -INT "$SERVER_PID"
(
    sleep 10
    if kill -0 "$SERVER_PID" 2>/dev/null; then
        : >"$AUDIT_ROOT/shutdown-timeout"
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        sleep 1
        kill -KILL "$SERVER_PID" 2>/dev/null || true
    fi
) &
WATCHDOG_PID=$!
SERVER_STATUS=0
wait "$SERVER_PID" || SERVER_STATUS=$?
kill -TERM "$WATCHDOG_PID" 2>/dev/null || true
wait "$WATCHDOG_PID" 2>/dev/null || true
WATCHDOG_PID=
[ ! -e "$AUDIT_ROOT/shutdown-timeout" ] || fail "debug server exceeded the ten-second SIGINT deadline"
[ "$SERVER_STATUS" -eq 0 ] || fail "debug server exited with status $SERVER_STATUS after SIGINT"
SERVER_PID=

echo "listener audit passed: $LISTENER"
