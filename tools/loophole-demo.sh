#!/bin/bash
# loophole-demo.sh — End-to-end demo of Firecracker booting from a loophole volume.
#
# This script runs inside a Lima VM (or any aarch64 Linux host with KVM).
# It builds the loophole C library and import tool, downloads a kernel
# and rootfs, imports the rootfs into a loophole volume, builds firecracker
# with loophole support, and boots a VM.
#
# Prerequisites:
#   - Go toolchain (snap install go --classic)
#   - Rust toolchain (rustup)
#   - KVM access (/dev/kvm)
#   - loophole source at $LOOPHOLE_SRC (default: /Users/ramon/src/loophole)
#   - firecracker source at $FIRECRACKER_SRC (default: /Users/ramon/src/firecracker)
#
# Usage:
#   ./tools/loophole-demo.sh              # full run
#   ./tools/loophole-demo.sh --skip-build # skip building, just import + boot

set -euo pipefail

LOOPHOLE_SRC="${LOOPHOLE_SRC:-/Users/ramon/src/loophole}"
FIRECRACKER_SRC="${FIRECRACKER_SRC:-/Users/ramon/src/firecracker}"
WORK_DIR="${WORK_DIR:-/tmp/loophole-demo}"
LOOPHOLE_LIB_DIR="${LOOPHOLE_LIB_DIR:-/tmp}"
ARCH=$(uname -m)
SKIP_BUILD=false

# Networking config.
TAP_DEV="${TAP_DEV:-tap0}"
TAP_IP="172.16.0.1"
GUEST_IP="172.16.0.2"
GUEST_MAC="06:00:c0:a8:00:02"
MASK_CIDR="24"

for arg in "$@"; do
    case "$arg" in
        --skip-build) SKIP_BUILD=true ;;
        *) echo "Unknown arg: $arg"; exit 1 ;;
    esac
done

# Files modified in firecracker for loophole support.
FC_MODIFIED_FILES=(
    src/firecracker/src/api_server/request/snapshot.rs
    src/firecracker/src/main.rs
    src/vmm/Cargo.toml
    src/vmm/build.rs
    src/vmm/src/devices/virtio/block/virtio/device.rs
    src/vmm/src/devices/virtio/block/virtio/io/loophole_io.rs
    src/vmm/src/devices/virtio/block/virtio/io/mod.rs
    src/vmm/src/devices/virtio/block/virtio/mod.rs
    src/vmm/src/devices/virtio/block/virtio/persist.rs
    src/vmm/src/devices/virtio/block/virtio/test_utils.rs
    src/vmm/src/persist.rs
    src/vmm/src/vmm_config/snapshot.rs
    src/vmm/src/vstate/vm.rs
    tools/loophole-clone.sh
    tools/loophole-demo.sh
)

KERNEL_URL="https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.15/${ARCH}/vmlinux-6.1.155"
ROOTFS_URL="https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.15/${ARCH}/ubuntu-24.04.squashfs"

log() { echo "=== $* ===" >&2; }

wait_for_socket_gone() {
    local sock="$1"
    local retries="${2:-50}"
    local delay="${3:-0.1}"
    local i
    for ((i = 0; i < retries; i++)); do
        [ ! -S "$sock" ] && return 0
        sleep "$delay"
    done
    return 1
}

mkdir -p "$WORK_DIR"

# ─── Step 1: Build loophole C library (libloophole.a) ────────────────────────

if [ "$SKIP_BUILD" = false ]; then
    log "Building loophole (CLI + libloophole.a)"
    cd "$LOOPHOLE_SRC"
    make loophole libloophole.a
    GO_PLATFORM="$(go env GOOS)-$(go env GOARCH)"
    rm -f "${WORK_DIR}/loophole"
    cp "bin/loophole-${GO_PLATFORM}" "${WORK_DIR}/loophole"
    cp "build/${GO_PLATFORM}/libloophole.a" "${LOOPHOLE_LIB_DIR}/libloophole.a"
    echo "  -> ${WORK_DIR}/loophole"
    echo "  -> ${LOOPHOLE_LIB_DIR}/libloophole.a"
fi

# ─── Step 3: Build firecracker with loophole support ─────────────────────────

if [ "$SKIP_BUILD" = false ]; then
    log "Syncing modified firecracker source files"
    FC_BUILD_DIR="${WORK_DIR}/firecracker"
    if [ ! -d "$FC_BUILD_DIR" ]; then
        log "Cloning firecracker source tree"
        cp -a "$FIRECRACKER_SRC" "$FC_BUILD_DIR"
    fi
    for f in "${FC_MODIFIED_FILES[@]}"; do
        cp "$FIRECRACKER_SRC/$f" "$FC_BUILD_DIR/$f"
        echo "  copied $f"
    done
    chmod +x "$FC_BUILD_DIR/tools/loophole-demo.sh" "$FC_BUILD_DIR/tools/loophole-clone.sh"

    log "Building firecracker"
    cd "$FC_BUILD_DIR"
    source "$HOME/.cargo/env" 2>/dev/null || true
    LOOPHOLE_LIB_DIR="$LOOPHOLE_LIB_DIR" cargo build -p firecracker --features vmm/loophole 2>&1
    FC_BIN="$FC_BUILD_DIR/build/cargo_target/debug/firecracker"
    echo "  -> $FC_BIN"
fi

FC_BIN="${FC_BIN:-${WORK_DIR}/firecracker/build/cargo_target/debug/firecracker}"

# ─── Step 4: Download kernel and rootfs ──────────────────────────────────────

KERNEL="${WORK_DIR}/vmlinux"
ROOTFS_SQUASHFS="${WORK_DIR}/ubuntu.squashfs"
ROOTFS_EXT4="${WORK_DIR}/ubuntu.ext4"

if [ ! -f "$KERNEL" ]; then
    log "Downloading kernel"
    wget -q --show-progress -O "$KERNEL" "$KERNEL_URL"
fi

if [ ! -f "$ROOTFS_SQUASHFS" ]; then
    log "Downloading rootfs (squashfs)"
    wget -q --show-progress -O "$ROOTFS_SQUASHFS" "$ROOTFS_URL"
fi

# ─── Step 5: Convert squashfs → ext4 ────────────────────────────────────────

if [ ! -f "$ROOTFS_EXT4" ]; then
    log "Converting squashfs to ext4"
    SQUASH_TMP="${WORK_DIR}/squashfs-root"
    rm -rf "$SQUASH_TMP"
    sudo unsquashfs -d "$SQUASH_TMP" "$ROOTFS_SQUASHFS"
    # Set up DNS resolution inside the rootfs.
    sudo rm -f "$SQUASH_TMP/etc/resolv.conf"
    echo "nameserver 8.8.8.8" | sudo tee "$SQUASH_TMP/etc/resolv.conf" >/dev/null

    # Write a netplan config so systemd-networkd keeps eth0 configured.
    sudo mkdir -p "$SQUASH_TMP/etc/netplan"
    sudo rm -f "$SQUASH_TMP"/etc/netplan/*.yaml
    cat <<NETPLAN | sudo tee "$SQUASH_TMP/etc/netplan/99-fc.yaml" >/dev/null
network:
  version: 2
  ethernets:
    eth0:
      addresses:
        - ${GUEST_IP}/${MASK_CIDR}
      routes:
        - to: default
          via: ${TAP_IP}
      nameservers:
        addresses:
          - 8.8.8.8
NETPLAN

    # Create 1 GiB ext4 image from the squashfs contents.
    truncate -s 1G "$ROOTFS_EXT4"
    sudo mkfs.ext4 -d "$SQUASH_TMP" -F "$ROOTFS_EXT4"
    sudo rm -rf "$SQUASH_TMP"
    echo "  -> $ROOTFS_EXT4"
fi

# ─── Step 6: Import rootfs into loophole volume ─────────────────────────────

STORE_DIR="${WORK_DIR}/store"
LOOPHOLE_DIR="${WORK_DIR}/loophole-config"
VOLUME_NAME="rootfs"
LOOPHOLE_BIN="${WORK_DIR}/loophole"

log "Writing loophole config"
mkdir -p "$LOOPHOLE_DIR"
cat > "$LOOPHOLE_DIR/config.toml" <<TOML
default_profile = "demo"

[profiles.demo]
local_dir = "${STORE_DIR}"
mode = "inprocess"
TOML

export LOOPHOLE_HOME="$LOOPHOLE_DIR"

log "Importing rootfs into loophole volume '${VOLUME_NAME}'"
DEMO_SOCK="${LOOPHOLE_DIR}/demo.sock"
DEMO_NBD_SOCK="${LOOPHOLE_DIR}/demo.nbd.sock"
DEMO_GRPC_SOCK="${LOOPHOLE_DIR}/demo.grpc.sock"

"$LOOPHOLE_BIN" stop >/dev/null 2>&1 || true
if ! wait_for_socket_gone "$DEMO_SOCK"; then
    log "Removing stale loophole sockets"
    rm -f "$DEMO_SOCK" "$DEMO_NBD_SOCK" "$DEMO_GRPC_SOCK"
fi

rm -f \
    "${WORK_DIR}/.mem-base-created" \
    "${WORK_DIR}"/snap-* \
    "${WORK_DIR}"/snap-*.mem-clone \
    "${WORK_DIR}"/mem-* \
    "${WORK_DIR}"/fc-clone-*.sock
rm -rf "$STORE_DIR"
mkdir -p "$STORE_DIR"
"$LOOPHOLE_BIN" device dd if="$ROOTFS_EXT4" of="$VOLUME_NAME:"

# ─── Step 7: Set up host networking (TAP + NAT) ──────────────────────────────

log "Setting up host networking"

# Find the default route's outbound interface for masquerade.
HOST_IFACE=$(ip -j route show default | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['dev'])")
echo "  host iface: $HOST_IFACE"

# Create TAP device if it doesn't already exist.
if ! ip link show "$TAP_DEV" &>/dev/null; then
    sudo ip tuntap add dev "$TAP_DEV" mode tap
fi
sudo ip addr replace "${TAP_IP}/${MASK_CIDR}" dev "$TAP_DEV"
sudo ip link set dev "$TAP_DEV" up
echo "  tap: $TAP_DEV ($TAP_IP/$MASK_CIDR)"

# Enable IP forwarding.
sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Set up NAT masquerade (idempotent — check before adding).
if ! sudo iptables -t nat -C POSTROUTING -o "$HOST_IFACE" -j MASQUERADE 2>/dev/null; then
    sudo iptables -t nat -A POSTROUTING -o "$HOST_IFACE" -j MASQUERADE
fi
if ! sudo iptables -C FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
    sudo iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
fi
if ! sudo iptables -C FORWARD -i "$TAP_DEV" -o "$HOST_IFACE" -j ACCEPT 2>/dev/null; then
    sudo iptables -A FORWARD -i "$TAP_DEV" -o "$HOST_IFACE" -j ACCEPT
fi
echo "  NAT masquerade via $HOST_IFACE"

# ─── Step 8: Write firecracker config ───────────────────────────────────────

FC_CONFIG="${WORK_DIR}/fc-config.json"
cat > "$FC_CONFIG" <<EOF
{
  "boot-source": {
    "kernel_image_path": "${KERNEL}",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw net.ifnames=0 ip=${GUEST_IP}::${TAP_IP}:255.255.255.0::eth0:off"
  },
  "drives": [
    {
      "drive_id": "rootfs",
      "path_on_host": "${VOLUME_NAME}",
      "is_root_device": true,
      "is_read_only": false,
      "io_engine": "Loophole"
    }
  ],
  "network-interfaces": [
    {
      "iface_id": "eth0",
      "host_dev_name": "${TAP_DEV}",
      "guest_mac": "${GUEST_MAC}"
    }
  ],
  "machine-config": {
    "vcpu_count": 2,
    "mem_size_mib": 512
  }
}
EOF

# ─── Step 9: Boot firecracker ───────────────────────────────────────────────

log "Booting Firecracker VM"
echo "  kernel:  $KERNEL"
echo "  rootfs:  loophole volume '${VOLUME_NAME}'"
echo "  network: ${GUEST_IP} via ${TAP_DEV} (NAT to ${HOST_IFACE})"
echo "  config:  $FC_CONFIG"

export LOOPHOLE_INIT=1
export LOOPHOLE_CONFIG_DIR="$LOOPHOLE_DIR"
export LOOPHOLE_PROFILE="demo"
FC_SOCK="${WORK_DIR}/fc.sock"
rm -f "$FC_SOCK"
exec "$FC_BIN" --api-sock "$FC_SOCK" --no-seccomp --config-file "$FC_CONFIG"
