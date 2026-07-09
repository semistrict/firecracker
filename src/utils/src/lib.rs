// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod arg_parser;
pub mod time;
pub mod validators;

/// Environment variable used by the jailer to retain the host's `vm.max_map_count` value after
/// entering the jail.
pub const MAX_MAP_COUNT_ENV_VAR: &str = "FIRECRACKER_MAX_MAP_COUNT";
/// Procfs path that exposes the host's maximum number of memory mappings per process.
pub const PROC_MAX_MAP_COUNT_PATH: &str = "/proc/sys/vm/max_map_count";
