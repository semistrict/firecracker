# cladefs

[cladefs](https://github.com/semistrict/cladefs)'s extent-store device and what it needs of
Firecracker, behind the `cladefs` Cargo feature of the `firecracker` and `vmm` crates. A build
without the feature is upstream's but for the general fixes, at the series' base and after the
feature ([below](#general-fixes-after-the-feature)), which stand alone and change nothing of
cladefs's.

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
  `PUT /cladefs/{id}`, and `cladefs_overrides` in `PUT /snapshot/load`. Without the feature,
  the first is an unknown path and the second an unknown field, as upstream has them; so is
  `cladefs` in a VM's configuration file.
- The extent device attaches over virtio-PCI alone (`--enable-pci`): its DAX window is a BAR
  of its own, which a shared memory capability describes. Upstream's MMIO transport is as
  upstream has it, with no way to describe the window, and a VM with the device on it does not
  start (`StartMicrovmError::ExtentDevicesNeedPci`).
- `FcExitCode::CladefsdLost` (158), when an extent device's daemon goes, and
  `FcExitCode::AccessRefused` (159), when a guest's access to its DAX window stays refused.
- Guest memory restored from a memory cell (`mem_backend` `Cell`) is the cell's window, its
  pages the extent daemon's, a page the guest stores to a private copy in a memory object of
  the window's. What the guest gives back of it, a balloon's inflation or a free page report
  (`discard_range`), is reclaimed through the window (`cladefs::memory_cell::MemoryCell::reclaim`):
  its private pages there end, their memory emptied, and the window names the cell's pages there
  again, which the guest reads next. Upstream's `madvise(MADV_DONTNEED)` freed nothing of that
  memory, the private pages' memory object keeping them.

## General fixes after the feature

Fixes of upstream's code, each standing alone as those at the series' base, which a rewrite of
the series moves there:

- The jailer finds `/dev/userfaultfd`'s minor in `/proc/misc` whatever its padding: Linux
  right-aligns a minor in three columns, and one below 100, split at each space, read as
  absent, the jail left without the device, silently. A `/proc/misc` it can't read or parse is
  said, as `/dev/urandom`'s failure is, rather than taken for a host without userfaultfd.
- The signal handlers are async-signal-safe (`src/vmm/src/logger/signal_safe.rs`): they format
  their line on the stack and write it with `write(2)` to a duplicate of the logger's target,
  set metrics by atomic stores, and `_exit`, taking no lock and allocating nothing. Upstream's
  logged through `LOGGER`, whose lock, or the allocator's, their thread may hold: a `SIGPIPE`
  raised by the logger's own write to a pipe whose reader went, or a fault in `malloc`, hung the
  VM for ever. A fatal signal's metric is written as a metrics line of its own,
  `{"utc_timestamp_ms":...,"signals":{"sigsegv":1}}` (`"seccomp":{"num_faults":1}` for
  `SIGSYS`), where upstream wrote the whole of `METRICS`, through serde, which takes locks and
  allocates. Their lines' times are UTC, marked `Z`, as the local time zone takes a lock to read.
