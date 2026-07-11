# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance benchmark for snapshot restore."""

import re
import signal
import tempfile
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import pytest

import host_tools.drive as drive_tools
from framework.artifacts import GUEST_KERNEL_DEFAULT, pin_guest_kernel
from framework.microvm import HugePagesConfig, Microvm, Serial, SnapshotType

USEC_IN_MSEC = 1000
NS_IN_MSEC = 1_000_000
BYTES_PER_MIB = 1024 * 1024
BYTES_PER_DISK_BLOCK = 512
ITERATIONS = 30
DIFF_SNAPSHOT_ITERATIONS = 10
DIFF_SNAPSHOT_DIRTY_MIB = [1024, 2048, 4096]
DIFF_SNAPSHOT_MAX_OVERHEAD_MIB = 128

pytestmark = pin_guest_kernel(GUEST_KERNEL_DEFAULT)


@lru_cache
def get_scratch_drives():
    """Create an array of scratch disks."""
    scratchdisks = ["vdb", "vdc", "vdd", "vde"]
    return [
        (drive, drive_tools.FilesystemFile(tempfile.mktemp(), size=64))
        for drive in scratchdisks
    ]


@dataclass
class SnapshotRestoreTest:
    """Dataclass encapsulating properties of snapshot restore tests"""

    vcpus: int = 1
    mem: int = 128
    nets: int = 3
    blocks: int = 3
    all_devices: bool = False
    huge_pages: HugePagesConfig = HugePagesConfig.NONE

    @property
    def id(self):
        """Computes a unique id for this test instance"""
        return "all_dev" if self.all_devices else f"{self.vcpus}vcpu_{self.mem}mb"

    def boot_vm(self, microvm_factory, guest_kernel, rootfs, pci_enabled) -> Microvm:
        """Creates the initial snapshot that will be loaded repeatedly to sample latencies"""
        vm = microvm_factory.build(
            guest_kernel,
            rootfs,
            monitor_memory=False,
            pci=pci_enabled,
        )
        vm.spawn(log_level="Info", emit_metrics=True)
        vm.time_api_requests = False
        vm.basic_config(
            vcpu_count=self.vcpus,
            mem_size_mib=self.mem,
            rootfs_io_engine="Sync",
            huge_pages=self.huge_pages,
        )

        for _ in range(self.nets):
            vm.add_net_iface()

        if self.blocks > 1:
            scratch_drives = get_scratch_drives()
            for name, diskfile in scratch_drives[: (self.blocks - 1)]:
                vm.add_drive(name, diskfile.path, io_engine="Sync")

        if self.all_devices:
            vm.api.balloon.put(
                amount_mib=0, deflate_on_oom=True, stats_polling_interval_s=1
            )
            vm.api.vsock.put(vsock_id="vsock0", guest_cid=3, uds_path="/v.sock")

        vm.start()

        return vm


@pytest.mark.nonci
@pytest.mark.parametrize(
    "test_setup",
    [
        SnapshotRestoreTest(mem=128, vcpus=1),
        SnapshotRestoreTest(mem=1024, vcpus=1),
        SnapshotRestoreTest(mem=2048, vcpus=2),
        SnapshotRestoreTest(mem=4096, vcpus=3),
        SnapshotRestoreTest(mem=6144, vcpus=4),
        SnapshotRestoreTest(mem=8192, vcpus=5),
        SnapshotRestoreTest(mem=10240, vcpus=6),
        SnapshotRestoreTest(mem=12288, vcpus=7),
        SnapshotRestoreTest(all_devices=True),
    ],
    ids=lambda x: x.id,
)
def test_restore_latency(
    microvm_factory, guest_kernel, rootfs, pci_enabled, test_setup, metrics
):
    """
    Restores snapshots with vcpu/memory configuration, roughly scaling according to mem = (vcpus - 1) * 2048MB,
    which resembles firecracker production setups. Also contains a test case for restoring a snapshot will all devices
    attached to it.

    We only test a single guest kernel, as the guest kernel does not "participate" in snapshot restore.
    """
    vm = test_setup.boot_vm(microvm_factory, guest_kernel, rootfs, pci_enabled)

    metrics.set_dimensions(
        {
            "net_devices": str(test_setup.nets),
            "block_devices": str(test_setup.blocks),
            "vsock_devices": str(int(test_setup.all_devices)),
            "balloon_devices": str(int(test_setup.all_devices)),
            "huge_pages_config": str(test_setup.huge_pages),
            "performance_test": "test_restore_latency",
            "uffd_handler": "None",
            **vm.dimensions,
        }
    )

    snapshot = vm.snapshot_full()
    vm.kill()
    for microvm in microvm_factory.build_n_from_snapshot(
        snapshot, ITERATIONS, no_netns_reuse=True
    ):
        value = 0
        # Parse all metric data points in search of load_snapshot time.
        microvm.flush_metrics()
        for data_point in microvm.get_all_metrics():
            cur_value = data_point["latencies_us"]["load_snapshot"]
            if cur_value > 0:
                value = cur_value / USEC_IN_MSEC
                break
        assert value > 0
        metrics.put_metric("latency", value, "Milliseconds")


# When using the fault-all handler, all guest memory will be faulted in way before the helper tool
# wakes up, because it gets faulted in on the first page fault. In this scenario, we are not measuring UFFD
# latencies, but KVM latencies of setting up missing EPT entries.
@pytest.mark.nonci
@pytest.mark.parametrize("uffd_handler", [None, "on_demand", "fault_all"])
@pytest.mark.parametrize("huge_pages", HugePagesConfig)
def test_post_restore_latency(
    microvm_factory,
    rootfs,
    guest_kernel,
    pci_enabled,
    metrics,
    uffd_handler,
    huge_pages,
):
    """Collects latency metric of post-restore memory accesses done inside the guest"""
    if huge_pages != HugePagesConfig.NONE and uffd_handler is None:
        pytest.skip("huge page snapshots can only be restored using uffd")

    test_setup = SnapshotRestoreTest(mem=1024, vcpus=2, huge_pages=huge_pages)
    vm = test_setup.boot_vm(microvm_factory, guest_kernel, rootfs, pci_enabled)

    metrics.set_dimensions(
        {
            "net_devices": str(test_setup.nets),
            "block_devices": str(test_setup.blocks),
            "vsock_devices": str(int(test_setup.all_devices)),
            "balloon_devices": str(int(test_setup.all_devices)),
            "huge_pages_config": str(test_setup.huge_pages),
            "performance_test": "test_post_restore_latency",
            "uffd_handler": str(uffd_handler),
            **vm.dimensions,
        }
    )

    vm.ssh.check_output(
        "nohup /usr/local/bin/fast_page_fault_helper >/dev/null 2>&1 </dev/null &"
    )

    # Give helper time to initialize
    time.sleep(5)

    snapshot = vm.snapshot_full()
    vm.kill()

    for microvm in microvm_factory.build_n_from_snapshot(
        snapshot, ITERATIONS, uffd_handler_name=uffd_handler
    ):
        _, pid, _ = microvm.ssh.check_output("pidof fast_page_fault_helper")

        microvm.ssh.check_output(f"kill -s {signal.SIGUSR1} {pid}")

        _, duration, _ = microvm.ssh.check_output(
            "while [ ! -f /tmp/fast_page_fault_helper.out ]; do sleep 1; done; cat /tmp/fast_page_fault_helper.out"
        )

        metrics.put_metric("fault_latency", int(duration) / NS_IN_MSEC, "Milliseconds")


@pytest.mark.nonci
@pytest.mark.parametrize("huge_pages", HugePagesConfig)
@pytest.mark.parametrize(
    ("vcpus", "mem"), [(1, 128), (1, 1024), (2, 2048), (3, 4096), (4, 6144)]
)
def test_population_latency(
    microvm_factory,
    rootfs,
    guest_kernel,
    pci_enabled,
    metrics,
    huge_pages,
    vcpus,
    mem,
):
    """Collects population latency metrics (e.g. how long it takes UFFD handler to fault in all memory)"""
    test_setup = SnapshotRestoreTest(mem=mem, vcpus=vcpus, huge_pages=huge_pages)
    vm = test_setup.boot_vm(microvm_factory, guest_kernel, rootfs, pci_enabled)

    metrics.set_dimensions(
        {
            "net_devices": str(test_setup.nets),
            "block_devices": str(test_setup.blocks),
            "vsock_devices": str(int(test_setup.all_devices)),
            "balloon_devices": str(int(test_setup.all_devices)),
            "huge_pages_config": str(test_setup.huge_pages),
            "performance_test": "test_population_latency",
            "uffd_handler": "fault_all",
            **vm.dimensions,
        }
    )

    snapshot = vm.snapshot_full()
    vm.kill()

    for microvm in microvm_factory.build_n_from_snapshot(
        snapshot, ITERATIONS, uffd_handler_name="fault_all"
    ):
        # API response times are unreliable while the uffd handler is
        # faulting in all pages — skip the timing validation.
        microvm.time_api_requests = False
        # do _something_ to trigger a pagefault, which will then cause the UFFD handler to fault in _everything_
        microvm.ssh.check_output("true")

        for _ in range(5):
            time.sleep(1)

            match = re.match(
                r"Finished Faulting All: (\d+)us", microvm.uffd_handler.log_data
            )

            if match:
                latency_us = int(match.group(1))

                metrics.put_metric(
                    "populate_latency", latency_us / 1000, "Milliseconds"
                )
                break
        else:
            raise RuntimeError("UFFD handler did not print population latency after 5s")


@pytest.mark.nonci
def test_snapshot_create_latency(
    uvm,
    metrics,
    snapshot_type,
):
    """Measure the latency of creating a Full snapshot"""

    vm = uvm
    vm.spawn()
    vm.basic_config(
        vcpu_count=2,
        mem_size_mib=512,
        track_dirty_pages=snapshot_type.needs_dirty_page_tracking,
    )
    vm.start()
    vm.pin_threads(0)

    metrics.set_dimensions(
        {
            **vm.dimensions,
            "performance_test": "test_snapshot_create_latency",
            "snapshot_type": str(snapshot_type),
        }
    )

    match snapshot_type:
        case SnapshotType.FULL:
            metric = "full_create_snapshot"
        case SnapshotType.DIFF | SnapshotType.DIFF_MINCORE:
            metric = "diff_create_snapshot"

    for _ in range(ITERATIONS):
        vm.make_snapshot(snapshot_type)
        fc_metrics = vm.flush_metrics()

        value = fc_metrics["latencies_us"][metric] / USEC_IN_MSEC
        metrics.put_metric("latency", value, "Milliseconds")


@pytest.mark.nonci
@pytest.mark.timeout(3600)
@pytest.mark.parametrize(
    "dirty_mib",
    DIFF_SNAPSHOT_DIRTY_MIB,
    ids=lambda dirty_mib: f"dirty_{dirty_mib}mb",
)
@pytest.mark.parametrize("precopy", [False, True], ids=["stop_copy", "precopy"])
def test_diff_snapshot_pause_time(uvm, metrics, dirty_mib, precopy, pci_enabled):
    """Measure total and longest VM pauses during incremental snapshots."""

    if pci_enabled:
        pytest.skip("Incremental snapshot pause baseline uses MMIO")

    vm = uvm
    vm.help.enable_console()
    vm.spawn(serial_out_path=None)
    vm.basic_config(vcpu_count=2, mem_size_mib=6144, track_dirty_pages=True)
    serial = Serial(vm)
    # Dirtying several GiB can exceed the console helper's default 60 seconds
    # on nested-virtualization benchmark hosts.
    serial.RX_TIMEOUT_S = 600
    serial.open()
    vm.start()
    serial.rx(vm.distro.shell_prompt)
    vm.pin_threads(0)

    metrics.set_dimensions(
        {
            **vm.dimensions,
            "performance_test": "test_diff_snapshot_pause_time",
            "dirty_memory_mib": str(dirty_mib),
            "snapshot_mode": "precopy" if precopy else "stop_copy",
        }
    )

    # The first incremental snapshot contains all guest memory. Take it outside
    # the measured loop to clear the dirty log and establish an incremental
    # snapshot baseline.
    vm.snapshot_diff(mem_path="base.mem", vmstate_path="base.vmstate")
    vm.resume()

    root = Path(vm.chroot())
    (root / "base.mem").unlink()
    (root / "base.vmstate").unlink()

    total_paused_ns = 0
    longest_pause_ns = 0
    for iteration in range(DIFF_SNAPSHOT_ITERATIONS):
        serial.tx(f"/usr/local/bin/fillmem {dirty_mib}; cat /tmp/fillmem_output.txt")
        fillmem_output = serial.rx(vm.distro.shell_prompt)
        assert "successful" in fillmem_output

        mem_path = f"diff-{iteration}.mem"
        vmstate_path = f"diff-{iteration}.vmstate"

        if precopy:
            vm.api.snapshot_create.put(
                mem_file_path=mem_path,
                snapshot_path=vmstate_path,
                snapshot_type="Diff",
                precopy=True,
            )

        pause_start = time.monotonic_ns()
        vm.pause()

        vm.api.snapshot_create.put(
            mem_file_path=mem_path,
            snapshot_path=vmstate_path,
            snapshot_type="Diff",
        )

        vm.resume()
        paused_ns = time.monotonic_ns() - pause_start

        total_paused_ns += paused_ns
        longest_pause_ns = max(longest_pause_ns, paused_ns)

        allocated_bytes = (root / mem_path).stat().st_blocks * BYTES_PER_DISK_BLOCK
        expected_bytes = dirty_mib * BYTES_PER_MIB
        max_expected_bytes = (
            dirty_mib + DIFF_SNAPSHOT_MAX_OVERHEAD_MIB
        ) * BYTES_PER_MIB

        # Each layer can contain several GiB. Remove completed layers outside
        # the pause window, and before asserting, so a failed size check does
        # not exhaust a tmpfs-backed test host during failure diagnostics.
        (root / mem_path).unlink()
        (root / vmstate_path).unlink()

        assert expected_bytes <= allocated_bytes <= max_expected_bytes, (
            f"Incremental memory layer allocated {allocated_bytes} bytes; expected "
            f"{expected_bytes}..{max_expected_bytes} bytes"
        )

    metrics.put_metric(
        "total_paused_time", total_paused_ns / NS_IN_MSEC, "Milliseconds"
    )
    metrics.put_metric("longest_pause", longest_pause_ns / NS_IN_MSEC, "Milliseconds")
