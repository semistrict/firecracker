// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Loophole-backed block I/O engine.
//!
//! Delegates read/write/flush to a loophole volume via C FFI into a
//! statically-linked Go archive (libloophole.a).

use vm_memory::bitmap::BitmapSlice;
use vm_memory::{GuestMemoryError, VolatileMemoryError, VolatileSlice, WriteVolatile};

use crate::vstate::memory::{GuestAddress, GuestMemory, GuestMemoryExtension, GuestMemoryMmap};

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum LoopholeIoError {
    /// Open failed with code {0}
    Open(i64),
    /// Read failed with code {0}
    Read(i32),
    /// Write failed with code {0}
    Write(i32),
    /// Flush failed with code {0}
    Flush(i32),
    /// Guest memory error: {0}
    GuestMemory(GuestMemoryError),
    /// Mmap failed (null pointer returned)
    #[cfg(feature = "loophole_mmap")]
    Mmap,
}

#[cfg(feature = "loophole_mmap")]
/// A contiguous range of pages to write via the direct writeback path.
/// Must match the C struct `loophole_write_range` in capi.go.
#[derive(Debug)]
#[repr(C)]
pub(crate) struct WriteRange {
    offset: u64,
    buf: *const u8,
    count: u32,
}

// FFI declarations — these symbols come from libloophole.a (Go c-archive).
unsafe extern "C" {
    fn loophole_open(
        config_dir: *const std::ffi::c_char,
        profile: *const std::ffi::c_char,
        name: *const u8,
        name_len: u32,
    ) -> i64;
    fn loophole_read(handle: i64, buf: *mut u8, offset: u64, count: u32) -> i32;
    fn loophole_write(handle: i64, buf: *const u8, offset: u64, count: u32) -> i32;
    fn loophole_flush(handle: i64) -> i32;
    fn loophole_clone(handle: i64, clone_name: *const u8, clone_name_len: u32) -> i32;
    fn loophole_size(handle: i64) -> u64;
    fn loophole_close(handle: i64) -> i32;

    #[cfg(feature = "loophole_mmap")]
    fn loophole_write_direct(handle: i64, ranges: *const WriteRange, num_ranges: u32) -> i32;
    #[cfg(feature = "loophole_mmap")]
    fn loophole_mmap(handle: i64, offset: u64, size: u64) -> *mut u8;
}

#[derive(Debug)]
pub struct LoopholeEngine {
    handle: i64,
}

// SAFETY: The Go runtime is thread-safe and the handle is a pointer to a
// Go struct pinned in a map.
unsafe impl Send for LoopholeEngine {}

impl LoopholeEngine {
    /// Open a loophole volume by name, using the default config and profile.
    pub fn open(volume_name: &str) -> Result<Self, LoopholeIoError> {
        Self::open_with(None, None, volume_name)
    }

    /// Open a loophole volume with explicit config dir and profile.
    pub fn open_with(
        config_dir: Option<&str>,
        profile: Option<&str>,
        volume_name: &str,
    ) -> Result<Self, LoopholeIoError> {
        let c_config_dir = config_dir.map(|s| std::ffi::CString::new(s).unwrap());
        let c_profile = profile.map(|s| std::ffi::CString::new(s).unwrap());
        let h = unsafe {
            loophole_open(
                c_config_dir
                    .as_ref()
                    .map_or(std::ptr::null(), |s| s.as_ptr()),
                c_profile.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
                volume_name.as_ptr(),
                volume_name.len() as u32,
            )
        };
        if h < 0 {
            return Err(LoopholeIoError::Open(h));
        }
        Ok(LoopholeEngine { handle: h })
    }

    /// Volume size in bytes.
    pub fn size(&self) -> u64 {
        unsafe { loophole_size(self.handle) }
    }

    /// Read `count` bytes from the volume at `offset` directly into guest
    /// memory at `addr`.
    pub fn read(
        &self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    ) -> Result<u32, LoopholeIoError> {
        let slice = mem
            .get_slice(addr, count as usize)
            .map_err(LoopholeIoError::GuestMemory)?;
        let ptr = slice.ptr_guard_mut().as_ptr();
        let rc = unsafe { loophole_read(self.handle, ptr, offset, count) };
        if rc < 0 {
            return Err(LoopholeIoError::Read(rc));
        }
        mem.mark_dirty(addr, count as usize);
        Ok(rc as u32)
    }

    /// Write `count` bytes from guest memory at `addr` to the volume at
    /// `offset`.
    pub fn write(
        &self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    ) -> Result<u32, LoopholeIoError> {
        let slice = mem
            .get_slice(addr, count as usize)
            .map_err(LoopholeIoError::GuestMemory)?;
        let ptr = slice.ptr_guard_mut().as_ptr();
        let rc = unsafe { loophole_write(self.handle, ptr as *const u8, offset, count) };
        if rc < 0 {
            return Err(LoopholeIoError::Write(rc));
        }
        Ok(rc as u32)
    }

    /// Flush the volume.
    pub fn flush(&self) -> Result<(), LoopholeIoError> {
        let rc = unsafe { loophole_flush(self.handle) };
        if rc < 0 {
            return Err(LoopholeIoError::Flush(rc));
        }
        Ok(())
    }

    /// Clone a volume, creating a writable fork (includes implicit flush).
    pub fn clone_volume(&self, clone_name: &str) -> Result<(), LoopholeIoError> {
        let rc =
            unsafe { loophole_clone(self.handle, clone_name.as_ptr(), clone_name.len() as u32) };
        if rc < 0 {
            return Err(LoopholeIoError::Write(rc));
        }
        Ok(())
    }
}

// --- Memory snapshot support (requires loophole_mmap feature) ---

#[cfg(feature = "loophole_mmap")]
impl LoopholeEngine {
    /// Write from a raw host pointer to the volume at `offset`.
    pub fn write_raw(
        &self,
        offset: u64,
        buf: *const u8,
        count: u32,
    ) -> Result<u32, LoopholeIoError> {
        let rc = unsafe { loophole_write(self.handle, buf, offset, count) };
        if rc < 0 {
            return Err(LoopholeIoError::Write(rc));
        }
        Ok(rc as u32)
    }

    /// Write page ranges through the direct writeback path in a single CGo call.
    pub fn write_direct(&self, ranges: &[WriteRange]) -> Result<(), LoopholeIoError> {
        if ranges.is_empty() {
            return Ok(());
        }
        let rc = unsafe {
            loophole_write_direct(self.handle, ranges.as_ptr(), ranges.len() as u32)
        };
        if rc < 0 {
            return Err(LoopholeIoError::Write(rc));
        }
        Ok(())
    }

    /// Get a demand-paged mmap pointer to the volume's contents.
    pub fn mmap_ptr(&self) -> Result<*mut u8, LoopholeIoError> {
        let size = self.size();
        let ptr = unsafe { loophole_mmap(self.handle, 0, size) };
        if ptr.is_null() {
            return Err(LoopholeIoError::Mmap);
        }
        Ok(ptr)
    }
}

/// Adapter that wraps a `LoopholeEngine` with a cursor, implementing
/// `WriteVolatile + Seek` for memory snapshot dump.
#[cfg(feature = "loophole_mmap")]
#[derive(Debug)]
pub struct LoopholeMemWriter {
    engine: LoopholeEngine,
    cursor: u64,
    direct: bool,
    pending: Vec<WriteRange>,
}

#[cfg(feature = "loophole_mmap")]
impl LoopholeMemWriter {
    pub fn new(engine: LoopholeEngine) -> Self {
        Self {
            engine,
            cursor: 0,
            direct: false,
            pending: Vec::new(),
        }
    }

    pub fn new_direct(engine: LoopholeEngine) -> Self {
        Self {
            engine,
            cursor: 0,
            direct: true,
            pending: Vec::new(),
        }
    }

    pub fn engine(&self) -> &LoopholeEngine {
        &self.engine
    }

    pub fn commit_direct(&mut self) -> Result<(), LoopholeIoError> {
        if self.pending.is_empty() {
            return Ok(());
        }
        self.engine.write_direct(&self.pending)?;
        self.pending.clear();
        Ok(())
    }
}

#[cfg(feature = "loophole_mmap")]
impl std::io::Seek for LoopholeMemWriter {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        let new_pos = match pos {
            std::io::SeekFrom::Start(offset) => Some(offset),
            std::io::SeekFrom::End(offset) => {
                let size = self.engine.size();
                if offset >= 0 {
                    size.checked_add(offset as u64)
                } else {
                    size.checked_sub(offset.unsigned_abs())
                }
            }
            std::io::SeekFrom::Current(offset) => {
                if offset >= 0 {
                    self.cursor.checked_add(offset as u64)
                } else {
                    self.cursor.checked_sub(offset.unsigned_abs())
                }
            }
        };
        match new_pos {
            Some(pos) => {
                self.cursor = pos;
                Ok(self.cursor)
            }
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek to invalid position",
            )),
        }
    }
}

#[cfg(feature = "loophole_mmap")]
impl WriteVolatile for LoopholeMemWriter {
    fn write_volatile<B: BitmapSlice>(
        &mut self,
        buf: &VolatileSlice<B>,
    ) -> Result<usize, VolatileMemoryError> {
        let len = buf.len();
        let to_write = len.min(u32::MAX as usize) as u32;
        let ptr = buf.ptr_guard().as_ptr();

        if self.direct {
            self.pending.push(WriteRange {
                offset: self.cursor,
                buf: ptr,
                count: to_write,
            });
            self.cursor += to_write as u64;
            Ok(to_write as usize)
        } else {
            let written = self
                .engine
                .write_raw(self.cursor, ptr, to_write)
                .map_err(|e| {
                    VolatileMemoryError::IOError(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("{e}"),
                    ))
                })?;
            self.cursor += written as u64;
            Ok(written as usize)
        }
    }
}

impl Drop for LoopholeEngine {
    fn drop(&mut self) {
        unsafe {
            loophole_close(self.handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vm_memory::Bytes;

    use crate::test_utils::single_region_mem;
    use crate::vstate::memory::GuestAddress;

    #[test]
    fn test_loophole_read_write_roundtrip() {
        let tmp = std::env::temp_dir().join("loophole-test-fc");
        let store_dir = tmp.join("store");
        let config_dir = tmp.join("config");
        let cache_dir = config_dir.join("cache").join("test");
        std::fs::create_dir_all(&store_dir).unwrap();
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::create_dir_all(&cache_dir).unwrap();

        let config_toml = format!(
            r#"default_profile = "test"

[profiles.test]
local_dir = "{}"
"#,
            store_dir.display(),
        );
        std::fs::write(config_dir.join("config.toml"), &config_toml).unwrap();

        let vol_size: u64 = 256 << 30;
        let engine = LoopholeEngine::open_with(
            Some(config_dir.to_str().unwrap()),
            Some("test"),
            "test-vol-256g",
        )
        .expect("loophole_open failed");
        assert_eq!(engine.size(), vol_size);

        let buf_size: usize = 1 << 20;
        let mem = single_region_mem(buf_size);

        // Test 1: Write/read at offset 0.
        let pattern: Vec<u8> = (0..512).map(|i| (i % 251) as u8).collect();
        mem.write_slice(&pattern, GuestAddress(0)).unwrap();
        assert_eq!(engine.write(0, &mem, GuestAddress(0), 512).unwrap(), 512);
        engine.flush().unwrap();
        mem.write_slice(&[0u8; 512], GuestAddress(0)).unwrap();
        assert_eq!(engine.read(0, &mem, GuestAddress(0), 512).unwrap(), 512);
        let mut readback = vec![0u8; 512];
        mem.read_slice(&mut readback, GuestAddress(0)).unwrap();
        assert_eq!(readback, pattern);

        // Test 2: Write/read a full 4K page at offset 4K.
        let pattern2: Vec<u8> = (0..4096).map(|i| (i % 199) as u8).collect();
        mem.write_slice(&pattern2, GuestAddress(0)).unwrap();
        assert_eq!(
            engine.write(4096, &mem, GuestAddress(0), 4096).unwrap(),
            4096
        );
        engine.flush().unwrap();
        mem.write_slice(&[0u8; 4096], GuestAddress(0)).unwrap();
        assert_eq!(
            engine.read(4096, &mem, GuestAddress(0), 4096).unwrap(),
            4096
        );
        let mut readback2 = vec![0u8; 4096];
        mem.read_slice(&mut readback2, GuestAddress(0)).unwrap();
        assert_eq!(readback2, pattern2);

        // Test 3: Write/read near the end of the 256 GiB volume.
        let far_offset = vol_size - 8192;
        let pattern3: Vec<u8> = (0..4096).map(|i| (i % 173) as u8).collect();
        mem.write_slice(&pattern3, GuestAddress(0)).unwrap();
        assert_eq!(
            engine
                .write(far_offset, &mem, GuestAddress(0), 4096)
                .unwrap(),
            4096
        );
        engine.flush().unwrap();
        mem.write_slice(&[0u8; 4096], GuestAddress(0)).unwrap();
        assert_eq!(
            engine
                .read(far_offset, &mem, GuestAddress(0), 4096)
                .unwrap(),
            4096
        );
        let mut readback3 = vec![0u8; 4096];
        mem.read_slice(&mut readback3, GuestAddress(0)).unwrap();
        assert_eq!(readback3, pattern3);

        // Test 4: Read an unwritten region — should return zeros.
        let unwritten_offset = 100 << 30;
        assert_eq!(
            engine
                .read(unwritten_offset, &mem, GuestAddress(0), 4096)
                .unwrap(),
            4096
        );
        let mut zeros = vec![0u8; 4096];
        mem.read_slice(&mut zeros, GuestAddress(0)).unwrap();
        assert!(
            zeros.iter().all(|&b| b == 0),
            "unwritten region should be zeros"
        );

        drop(engine);
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
