# cladefs

[cladefs](https://github.com/semistrict/cladefs)'s extent-store device and what it needs of
Firecracker, behind the `cladefs` Cargo feature of the `firecracker` and `vmm` crates. A build
without the feature is upstream's but for the general fixes at the series' base, which stand alone
and change nothing of cladefs's.

## Series structure

On top of upstream Firecracker `v1.18.0`, the series is split into independent commits so a
downstream fork carrying its own fixes can cherry-pick or drop individual commits cleanly:

1. `fix(vcpu)`: send the vCPU exit code before signalling the exit event (standalone).
2. `fix(signal)`: async-signal-safe fatal signal handlers on alternate stacks (standalone; also
   used by the `cladefs` commit for worker signal stacks and fault logging).
3. `fix(virtio)`: replace a features page on rewrite while preserving `device_acked_features()`
   such as `VhostUserVirtioFeatures::PROTOCOL_FEATURES` (standalone).
4. `fix(vsock)`: reset connections in the RX queue on snapshot ahead of `TRANSPORT_RESET`
   (standalone).
5. `fix(jailer)`: parse `/proc/misc` minors regardless of padding and warn on errors (standalone).
6. `virtio-pci`: shared memory regions as a BAR with `SHARED_MEMORY_CFG` capabilities and device
   types past 63 (standalone on `v1.18.0`; required by the `cladefs` commit).
7. `cladefs`: the `cladefs` Cargo feature (depends on commits 2 and 6; commits 1, 3, 4 and 5 may
   be omitted without conflict).

## Building with the feature

The feature builds against cladefs's crates, `crates/cladefs` and `crates/virtio_extent` in an
cladefs checkout, which no manifest here names: Cargo resolves every dependency a manifest
declares, optional or not, so a declared one would break, or fetch cladefs for, every build
outside cladefs's tree. `virtio_extent` is the extent device but its transport, which every VMM
hosting the device shares; `src/vmm/src/devices/virtio/extent` is Firecracker's adapter, what
the crate's README asks of one. cladefs's build supplies them, from a copy of this tree:

1. appends to `src/vmm/Cargo.toml`

   ```toml
   [dependencies.cladefs]
   path = "<cladefs checkout>/crates/cladefs"
   [dependencies.virtio_extent]
   path = "<cladefs checkout>/crates/virtio_extent"
   ```

2. replaces `Cargo.lock` with cladefs's, which holds cladefs's dependencies too;
3. builds with `--features cladefs`, e.g.
   `cargo build --release -p firecracker --features cladefs --target x86_64-unknown-linux-musl`.

cladefs's `scripts/firecracker-cargo.sh` does all three, with the frame pointers cladefs's own
`.cargo/config.toml` sets for everything it builds. Without step 1, `--features cladefs` fails
at `extern crate cladefs` in `src/vmm/src/lib.rs`.

## What the feature adds

- `seccomp/<target>.json`: rules for the VMM thread, which the extent device's threads run
  under, put before each thread's rules of `resources/seccomp/<target>.json` as
  `src/firecracker/build.rs` compiles the target's filter. The files upstream ships stay as
  they are. The device's threads also use upstream's `sigaltstack` and `mprotect` rules, for
  their alternate signal stacks' guard pages.
- `swagger.yaml`: the API the feature adds to `src/firecracker/swagger/firecracker.yaml`:
  `PUT /cladefs/{id}`, `PATCH /cladefs/{id}`, `PUT /memory-cell`, `for_migration` and
  `memory_cell` in `PUT /snapshot/create`, and `cladefs_overrides` and `memory_cell` (with
  optional `diff_files`) in `PUT /snapshot/load`. Without the feature, the first three are unknown
  paths and the fields are unknown, as upstream has them; so are `cladefs` and `memory-cell` in a
  VM's configuration file.
- The extent device attaches over virtio-PCI alone (`--enable-pci`): its DAX window is a BAR
  of its own, which a shared memory capability describes. Upstream's MMIO transport is as
  upstream has it, with no way to describe the window, and a VM with the device on it does not
  start (`StartMicrovmError::ExtentDevicesNeedPci`).
- `FcExitCode::CladefsdLost` (158), when an extent device's daemon goes, and
  `FcExitCode::AccessRefused` (159), when a guest's access to its DAX window stays refused.
- Every VM's guest memory is a memory cell's window (`src/vmm/src/cladefs_memory.rs`), by one
  path: a freshly booted VM's a new, empty cell's, where `memory-cell` (`PUT /memory-cell`) says,
  a boot without it refused (board 14415); a restored VM's (`mem_backend` `Cell`) a fork of the
  snapshot's memory's version, or an ephemeral cell reopened. Its pages are the extent daemon's,
  a page the guest stores to a private copy in a memory object of the window's. It is of 4 KiB
  pages: `huge_pages` other than `None` is refused. A VM with a vhost-user device does not boot. What the guest gives back of it, a balloon's inflation or a free page report
  (`discard_range`), is reclaimed through the window (`cladefs::memory_cell::MemoryCell::reclaim`):
  its private pages there end, their memory emptied, and the window names the cell's pages there
  again, which the guest reads next. Upstream's `madvise(MADV_DONTNEED)` freed nothing of that
  memory, the private pages' memory object keeping them.
- `PUT /snapshot/create` accepts `memory_cell` in place of `mem_file_path` (TASK-456.4):
  `memory_cell: {}` writes only the window's private pages into the VM's memory cell, a booted
  VM's as a restored one's, commits, reclaims them back to the newly committed extents, and makes
  a version, or checkpoints an ephemeral cell in place. Returns HTTP 200 with
  `{"tenant", "cell", "version"}`. A VM restored from a `File` or `Uffd` backend has no memory
  cell, and snapshots to `mem_file_path`.
