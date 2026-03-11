#!/bin/bash
# loophole-e2e.sh — End-to-end loophole snapshot/clone flow in a 2-pane tmux session.
#
# Run this inside the Lima/Linux VM where Firecracker can access /dev/kvm.
# It creates a tmux session with:
#   pane 0: original guest serial console
#   pane 1: clone-1 guest serial console
#   pane 2: clone-2 guest serial console
# and proves restored live memory across two generations:
#   original -> clone-1 (full loophole-backed snapshot)
#   clone-1  -> clone-2 (diff loophole-backed snapshot)

set -euo pipefail

FIRECRACKER_SRC="${FIRECRACKER_SRC:-/Users/ramon/src/firecracker}"
WORK_DIR="${WORK_DIR:-/tmp/loophole-demo}"
SESSION_NAME="${SESSION_NAME:-loophole-e2e}"
WINDOW_NAME="${WINDOW_NAME:-flow}"
CLONE1_ID="${CLONE1_ID:-1}"
CLONE2_ID="${CLONE2_ID:-2}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-180}"
CLONE_TIMEOUT="${CLONE_TIMEOUT:-120}"
PROMPT_TIMEOUT="${PROMPT_TIMEOUT:-30}"
STABILITY_TIMEOUT="${STABILITY_TIMEOUT:-10}"

DEMO_SCRIPT="${FIRECRACKER_SRC}/tools/loophole-demo.sh"
CLONE_SCRIPT="${FIRECRACKER_SRC}/tools/loophole-clone.sh"
FC_BIN="${WORK_DIR}/firecracker/build/cargo_target/debug/firecracker"
FC_SOCK="${WORK_DIR}/fc.sock"
CLONE1_SOCK="${WORK_DIR}/fc-clone-${CLONE1_ID}.sock"
CLONE2_SOCK="${WORK_DIR}/fc-clone-${CLONE2_ID}.sock"
NETNS1="fc-clone-${CLONE1_ID}"
NETNS2="fc-clone-${CLONE2_ID}"
SNAP1_PATH="${WORK_DIR}/snap-${CLONE1_ID}"
SNAP2_PATH="${WORK_DIR}/snap-${CLONE2_ID}"
MEM1_PATH="${WORK_DIR}/mem-${CLONE1_ID}"
MEM2_PATH="${WORK_DIR}/mem-${CLONE2_ID}"
ORIG_HEARTBEAT='while true; do echo ORIG-HEARTBEAT $(date -Ins); sleep 1; done'
CLONE1_HEARTBEAT='while true; do echo CLONE1-HEARTBEAT $(date -Ins); sleep 1; done'

SKIP_BUILD=false
ATTACH=false
FORCE=false

log() { echo "=== $* ===" >&2; }

usage() {
    cat <<EOF
Usage: $0 [--skip-build] [--attach] [--force]

  --skip-build  Reuse existing loophole/firecracker build artifacts.
  --attach      Attach to tmux after setup completes.
  --force       Kill any existing tmux session and demo processes first.
EOF
}

for arg in "$@"; do
    case "$arg" in
        --skip-build) SKIP_BUILD=true ;;
        --attach) ATTACH=true ;;
        --force) FORCE=true ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown arg: $arg" >&2
            usage >&2
            exit 1
            ;;
    esac
done

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "Missing required command: $1" >&2
        exit 1
    }
}

capture_pane() {
    local pane="$1"
    tmux capture-pane -t "$pane" -p -S -200
}

wait_for_pattern() {
    local pane="$1" pattern="$2" timeout="$3" label="$4"
    local elapsed=0
    while [ "$elapsed" -lt "$timeout" ]; do
        if capture_pane "$pane" | grep -Fq -- "$pattern"; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    echo "ERROR: timed out waiting for ${label}" >&2
    echo "--- ${pane} tail ---" >&2
    capture_pane "$pane" | tail -n 80 >&2
    exit 1
}

assert_pane_not_contains() {
    local pane="$1" pattern="$2" label="$3"
    if capture_pane "$pane" | grep -Fq -- "$pattern"; then
        echo "ERROR: detected ${label}" >&2
        echo "--- ${pane} tail ---" >&2
        capture_pane "$pane" | tail -n 120 >&2
        exit 1
    fi
}

kill_matching() {
    local pattern="$1"
    pkill -f -- "$pattern" 2>/dev/null || true
}

cleanup_old_run() {
    log "Cleaning up previous demo state"
    kill_matching "$FC_BIN --api-sock $FC_SOCK"
    kill_matching "$FC_BIN --api-sock $CLONE1_SOCK"
    kill_matching "$FC_BIN --api-sock $CLONE2_SOCK"
    kill_matching "${WORK_DIR}/loophole -p demo start --foreground"
    sudo ip netns del "$NETNS1" 2>/dev/null || true
    sudo ip netns del "$NETNS2" 2>/dev/null || true
    sudo ip link del "veth-h${CLONE1_ID}" 2>/dev/null || true
    sudo ip link del "veth-h${CLONE2_ID}" 2>/dev/null || true
    rm -f "$FC_SOCK" "$CLONE1_SOCK" "$CLONE2_SOCK"
    rm -f "${WORK_DIR}/.mem-base-created"
    rm -f "${WORK_DIR}"/snap-* "${WORK_DIR}"/snap-*.mem-clone "${WORK_DIR}"/mem-* 2>/dev/null || true
    sudo rm -rf "${WORK_DIR}/store"
}

require_cmd tmux
require_cmd sudo
require_cmd grep

if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
    if [ "$FORCE" = true ]; then
        log "Removing existing tmux session '$SESSION_NAME'"
        tmux kill-session -t "$SESSION_NAME"
    else
        echo "tmux session '$SESSION_NAME' already exists; use --force to replace it" >&2
        exit 1
    fi
fi

if [ "$FORCE" = true ]; then
    cleanup_old_run
fi

log "Creating tmux session '$SESSION_NAME'"
tmux new-session -d -s "$SESSION_NAME" -n "$WINDOW_NAME" "bash"
tmux split-window -h -t "${SESSION_NAME}:${WINDOW_NAME}" "bash"
tmux select-layout -t "${SESSION_NAME}:${WINDOW_NAME}" even-horizontal
tmux set-option -g mouse on

PANE_ORIG="${SESSION_NAME}:${WINDOW_NAME}.0"
PANE_CLONE1="${SESSION_NAME}:${WINDOW_NAME}.1"

DEMO_CMD="cd ${FIRECRACKER_SRC} && bash tools/loophole-demo.sh"
if [ "$SKIP_BUILD" = true ]; then
    DEMO_CMD="${DEMO_CMD} --skip-build"
fi

log "Starting original VM in pane 0"
tmux send-keys -t "$PANE_ORIG" "$DEMO_CMD" C-m

wait_for_pattern "$PANE_ORIG" "root@ubuntu-fc-uvm:~#" "$BOOT_TIMEOUT" "guest root prompt in pane 0"

log "Starting guest heartbeat loop in pane 0"
tmux send-keys -t "$PANE_ORIG" "$ORIG_HEARTBEAT" C-m
wait_for_pattern "$PANE_ORIG" "ORIG-HEARTBEAT " 20 "original heartbeat output in pane 0"

log "Starting original -> clone-1 flow in pane 1"
tmux send-keys -t "$PANE_CLONE1" \
    "cd ${FIRECRACKER_SRC} && CLONE_ID=${CLONE1_ID} FC_SOCK=${FC_SOCK} CLONE_SOCK=${CLONE1_SOCK} SNAP_PATH=${SNAP1_PATH} MEM_PATH=${MEM1_PATH} SNAP_TYPE=Full bash tools/loophole-clone.sh" \
    C-m

wait_for_pattern "$PANE_CLONE1" "Clone VM restored and running" "$CLONE_TIMEOUT" "clone-1 restore completion"
wait_for_pattern "$PANE_CLONE1" "ORIG-HEARTBEAT " 30 "restored original heartbeat output in pane 1"

log "Switching clone-1 to its own heartbeat loop"
tmux send-keys -t "$PANE_CLONE1" C-c
wait_for_pattern "$PANE_CLONE1" "root@ubuntu-fc-uvm:~#" "$PROMPT_TIMEOUT" "clone-1 root prompt after stopping inherited heartbeat"
tmux send-keys -t "$PANE_CLONE1" "$CLONE1_HEARTBEAT" C-m
wait_for_pattern "$PANE_CLONE1" "CLONE1-HEARTBEAT " 20 "clone-1 heartbeat output in pane 1"

log "Creating pane 2 for clone-2"
tmux split-window -v -t "$PANE_CLONE1" "bash"
tmux select-layout -t "${SESSION_NAME}:${WINDOW_NAME}" tiled
PANE_CLONE2="${SESSION_NAME}:${WINDOW_NAME}.2"

MEM_VOL_CLONE1=$(cat "${SNAP1_PATH}.mem-clone")
log "Starting clone-1 -> clone-2 diff flow in pane 2"
tmux send-keys -t "$PANE_CLONE2" \
    "cd ${FIRECRACKER_SRC} && CLONE_ID=${CLONE2_ID} FC_SOCK=${CLONE1_SOCK} CLONE_SOCK=${CLONE2_SOCK} SNAP_PATH=${SNAP2_PATH} MEM_PATH=${MEM2_PATH} MEM_VOL_NAME=${MEM_VOL_CLONE1} SNAP_TYPE=Diff bash tools/loophole-clone.sh" \
    C-m

wait_for_pattern "$PANE_CLONE2" "Clone VM restored and running" "$CLONE_TIMEOUT" "clone-2 restore completion"
wait_for_pattern "$PANE_CLONE2" "CLONE1-HEARTBEAT " 30 "restored clone-1 heartbeat output in pane 2"
sleep "$STABILITY_TIMEOUT"
assert_pane_not_contains "$PANE_CLONE2" "Segmentation fault" "guest userspace crash in pane 2"
assert_pane_not_contains "$PANE_CLONE2" "Unable to handle kernel NULL pointer dereference" "guest kernel crash in pane 2"

log "E2E multi-generation clone heartbeat verified"
echo
echo "tmux session: ${SESSION_NAME}"
echo "attach with: tmux attach -t ${SESSION_NAME}"
echo "pane 0: original guest serial console"
echo "pane 1: clone-1 guest serial console"
echo "pane 2: clone-2 guest serial console"

if [ "$ATTACH" = true ]; then
    exec tmux attach -t "$SESSION_NAME"
fi
