# fxdax

[fxdax](https://github.com/semistrict/fxdax)'s extent-store device and what it needs of
Firecracker, behind the `fxdax` Cargo feature of the `firecracker` and `vmm` crates. A build
without the feature is upstream's but for the general fixes at the series' base, which stand
alone and change nothing of fxdax's.

## Building with the feature

The feature builds against fxdax's crate, `crates/fxdax` in an fxdax checkout, which no
manifest here names: Cargo resolves every dependency a manifest declares, optional or not, so a
declared one would break, or fetch fxdax for, every build outside fxdax's tree. fxdax's build
supplies it, from a copy of this tree:

1. appends to `src/vmm/Cargo.toml`

   ```toml
   [dependencies.fxdax]
   path = "<fxdax checkout>/crates/fxdax"
   ```

2. replaces `Cargo.lock` with fxdax's, which holds fxdax's dependencies too;
3. builds with `--features fxdax`, e.g.
   `cargo build --release -p firecracker --features fxdax --target x86_64-unknown-linux-musl`.

fxdax's `scripts/firecracker-cargo.sh` does all three, with the frame pointers fxdax's own
`.cargo/config.toml` sets for everything it builds. Without step 1, `--features fxdax` fails
at `extern crate fxdax` in `src/vmm/src/lib.rs`.

## What the feature adds

- `seccomp/<target>.json`: rules for the VMM thread, which the extent device's threads run
  under, put before each thread's rules of `resources/seccomp/<target>.json` as
  `src/firecracker/build.rs` compiles the target's filter. The files upstream ships stay as
  they are. The device's threads also use upstream's `sigaltstack` and `mprotect` rules, for
  their alternate signal stacks' guard pages.
- `swagger.yaml`: the API the feature adds to `src/firecracker/swagger/firecracker.yaml`:
  `PUT /extent/{id}`, and `extent_overrides` in `PUT /snapshot/load`. Without the feature,
  the first is an unknown path and the second an unknown field, as upstream has them; so is
  `extent` in a VM's configuration file.
- The extent device attaches over virtio-PCI alone (`--enable-pci`): its DAX window is a BAR
  of its own, which a shared memory capability describes. Upstream's MMIO transport is as
  upstream has it, with no way to describe the window, and a VM with the device on it does not
  start (`StartMicrovmError::ExtentDevicesNeedPci`).
- `FcExitCode::ExtentdLost` (158), when an extent device's daemon goes, and
  `FcExitCode::AccessRefused` (159), when a guest's access to its DAX window stays refused.
