#!/usr/bin/env bash
# Create, verify, and destroy the isolated rayscan lab.
#
# Requires Linux root because it creates a network namespace and veth pair.
# The lab never touches the host's default route or public interfaces.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE="$ROOT/lab/state"
NS="rayscan-srv"
HOST_IF="rs-host"
SRV_IF="rs-srv"
HOST_IP="10.77.0.1"
TARGET_IP="10.77.0.2"
OPEN_PORTS="80,443,8080,8081,3306"
RATE_LIMITED_PORT="8081"
TARPIT_PORT="9000"
FILTERED_PORT="9001"
SYNPROXY_PORT="9003"
READY="$STATE/ready"
TARGETS_PID_FILE="$STATE/targets.pid"
NETEM_LOSS="${LAB_LOSS:-0%}"
NETEM_DELAY="${LAB_DELAY:-1ms}"
NETEM_JITTER="${LAB_JITTER:-200us}"

usage() {
    cat <<'EOF'
usage: lab.sh {up|down|check|cycle|status|logs}

Environment:
  LAB_LOSS=0%       netem loss (0%, 5%, 20% are the intended profiles)
  LAB_DELAY=1ms     netem one-way delay
  LAB_JITTER=200us  netem delay jitter
EOF
}

need_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        echo "lab.sh must run as root; use: sudo -E make lab" >&2
        exit 2
    fi
}

cleanup() {
    if [[ -f "$TARGETS_PID_FILE" ]]; then
        local pid
        pid="$(cat "$TARGETS_PID_FILE" 2>/dev/null || true)"
        if [[ -n "$pid" ]]; then
            kill "$pid" 2>/dev/null || true
        fi
        rm -f "$TARGETS_PID_FILE"
    fi

    if ip netns list 2>/dev/null | awk '{print $1}' | grep -qx "$NS"; then
        ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
        sleep 0.1
        ip netns del "$NS" 2>/dev/null || true
    fi

    ip link del "$HOST_IF" 2>/dev/null || true
    rm -f "$READY" "$STATE/env"
}

wait_ready() {
    local pid
    pid="$(cat "$TARGETS_PID_FILE")"

    for _ in $(seq 1 100); do
        if [[ -f "$READY" ]]; then
            return 0
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "lab target process exited before becoming ready" >&2
            cat "$STATE/targets.log" >&2 || true
            return 1
        fi
        sleep 0.1
    done

    echo "lab target did not become ready within 10 seconds" >&2
    cat "$STATE/targets.log" >&2 || true
    return 1
}

up() {
    need_root
    trap cleanup ERR

    if [[ ! "$NETEM_LOSS" =~ ^[0-9]+%$ ]]; then
        echo "LAB_LOSS must look like 0%%, 5%%, or 20%%" >&2
        exit 2
    fi

    for command in ip iptables tc python3; do
        if ! command -v "$command" >/dev/null 2>&1; then
            echo "missing required command: $command" >&2
            exit 2
        fi
    done

    cleanup
    mkdir -p "$STATE"

    ip netns add "$NS"
    ip link add "$HOST_IF" type veth peer name "$SRV_IF"
    ip link set "$SRV_IF" netns "$NS"
    ip addr add "$HOST_IP/24" dev "$HOST_IF"
    ip link set "$HOST_IF" up

    ip netns exec "$NS" ip link set lo up
    ip netns exec "$NS" ip addr add "$TARGET_IP/24" dev "$SRV_IF"
    ip netns exec "$NS" ip link set "$SRV_IF" up

    ip netns exec "$NS" iptables -A INPUT -p tcp --dport "$FILTERED_PORT" -j DROP

    # Rate-limited service: accept only five new connections per second.
    ip netns exec "$NS" iptables -A INPUT -p tcp --dport "$RATE_LIMITED_PORT" \
        -m conntrack --ctstate NEW -m limit --limit 5/second --limit-burst 10 \
        -j ACCEPT
    ip netns exec "$NS" iptables -A INPUT -p tcp --dport "$RATE_LIMITED_PORT" \
        -m conntrack --ctstate NEW -j DROP

    # SYN proxy: terminate the handshake in the kernel, with no backend.
    ip netns exec "$NS" iptables -t raw -A PREROUTING -p tcp \
        --dport "$SYNPROXY_PORT" -j CT --notrack
    ip netns exec "$NS" iptables -A INPUT -p tcp --dport "$SYNPROXY_PORT" \
        -m state --state INVALID,UNTRACKED -j SYNPROXY \
        --sack-perm --timestamp --mss 1460
    ip netns exec "$NS" iptables -A INPUT -p tcp --dport "$SYNPROXY_PORT" \
        -m state --state INVALID -j DROP
    ip netns exec "$NS" iptables -A INPUT -p tcp --dport "$SYNPROXY_PORT" \
        -j ACCEPT

    ip netns exec "$NS" tc qdisc replace dev "$SRV_IF" root netem \
        delay "$NETEM_DELAY" "$NETEM_JITTER" loss "$NETEM_LOSS"

    nohup ip netns exec "$NS" python3 "$ROOT/lab/targets.py" \
        --open "$OPEN_PORTS" \
        --tarpit "$TARPIT_PORT" \
        --ready-file "$READY" \
        >"$STATE/targets.log" 2>&1 </dev/null &
    echo "$!" >"$TARGETS_PID_FILE"

    if ! wait_ready; then
        cleanup
        exit 1
    fi

    cat >"$STATE/env" <<EOF
TARGET_IP=$TARGET_IP
OPEN_PORTS=$OPEN_PORTS
TARPIT_PORT=$TARPIT_PORT
FILTERED_PORT=$FILTERED_PORT
NETEM_LOSS=$NETEM_LOSS
EOF

    echo "lab up"
    echo "  target      $TARGET_IP"
    echo "  open        $OPEN_PORTS"
    echo "  tarpit      $TARPIT_PORT"
    echo "  filtered    $FILTERED_PORT"
    echo "  rate limit  $RATE_LIMITED_PORT (5/s)"
    echo "  syn proxy   $SYNPROXY_PORT"
    echo "  netem       delay $NETEM_DELAY $NETEM_JITTER loss $NETEM_LOSS"
    echo "  state       $STATE"
    trap - ERR
}

down() {
    need_root
    cleanup
    echo "lab down"
}

check() {
    need_root
    if ! ip netns list 2>/dev/null | awk '{print $1}' | grep -qx "$NS"; then
        echo "lab is not running; run 'make lab' first" >&2
        exit 2
    fi
    python3 "$ROOT/lab/verify_lab.py"
}

status() {
    if ip netns list 2>/dev/null | awk '{print $1}' | grep -qx "$NS"; then
        if [[ -f "$TARGETS_PID_FILE" ]]; then
            local pid
            pid="$(cat "$TARGETS_PID_FILE")"
            if ! kill -0 "$pid" 2>/dev/null; then
                echo "lab broken: namespace=$NS target pid=$pid is not running"
                exit 1
            fi
            echo "lab up: namespace=$NS target=$TARGET_IP pid=$pid"
        else
            echo "lab up: namespace=$NS target=$TARGET_IP"
        fi
    else
        echo "lab down"
        exit 1
    fi
}

logs() {
    cat "$STATE/targets.log" 2>/dev/null || {
        echo "no lab log at $STATE/targets.log" >&2
        exit 1
    }
}

case "${1:-}" in
    up) up ;;
    down) down ;;
    check) check ;;
    cycle)
        up
        trap cleanup EXIT
        check
        cleanup
        trap - EXIT
        ;;
    status) status ;;
    logs) logs ;;
    *) usage; exit 2 ;;
esac
