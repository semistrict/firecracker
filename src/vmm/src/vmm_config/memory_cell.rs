// Copyright 2026 cladefs authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! cladefs: the memory cell a freshly booted VM's memory is the window of (board 14415), which
//! `PUT /memory-cell` and a VM's configuration file's `memory-cell` give. Every VM's memory is a
//! memory cell's window, a booted one's as a restored one's (`crate::cladefs_memory`): a boot
//! without one is refused.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The new memory cell a freshly booted VM's memory is the window of: empty, its image all holes,
/// each page the guest writes made private, which its snapshots write into it.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryCellBootConfig {
    /// Where the extent daemon makes the cell: `"0/0"` (or `"TENANT/0"`), a new cell it places,
    /// whose snapshots make versions; or, `ephemeral`, a directory of the host's. A cell holding
    /// a memory already is refused: a fresh boot's memory is new.
    pub path_on_host: PathBuf,
    /// The extent daemon's socket.
    pub cladefsd_socket: PathBuf,
    /// Whether the cell is a standalone host-local ephemeral one, which writes nothing to the
    /// bucket and whose snapshots checkpoint it in place, making no version.
    #[serde(default)]
    pub ephemeral: bool,
}
