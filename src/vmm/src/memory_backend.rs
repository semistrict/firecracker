// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The `Mappings` memory backend: a page fault handler that tells Firecracker which mappings make
//! guest memory, and serves the faults on them.
//!
//! The handler lists, for each region of guest memory (and of each pmem device it serves), the
//! `mmap` calls that make it: entries of a file's range, mapped private (copy-on-write), of
//! anonymous memory, of anonymous memory whose first touch faults to the handler (lazy), or of
//! nothing (inaccessible). Its files are its own memory (memfds), which
//! every VM mapping the same pages shares until it stores to one, when the kernel makes that VM a
//! private copy. Firecracker registers each file entry with a userfaultfd for missing and minor
//! faults, which it hands to the handler, so that the first touch of each page reaches the handler
//! however the page came to be in the file, and the handler installs it (`UFFDIO_CONTINUE`).
//!
//! The protocol runs over the backend's Unix stream socket, in frames: a little-endian `u32`
//! length, then that many bytes of JSON, the frame's file descriptors attached to its first
//! `sendmsg` (`SCM_RIGHTS`).
//!
//! - **Start.** Firecracker sends [`ToHandler::Handshake`]: the regions, as the `Uffd` backend's
//!   handshake describes them, with the userfaultfd. The handler sends a [`FromHandler::Map`] for
//!   each region it maps, each answered, then [`FromHandler::Ready`].
//! - **Map.** The handler may send a [`FromHandler::Map`] for a pmem device's region at any time,
//!   applied by the thread reading the socket and answered with [`ToHandler::Mapped`]. Mapping over
//!   a range drops the private pages there. The guest must not touch a range while it is remapped.
//!   Guest memory's regions are mapped at start and while a snapshot is made; while the guest
//!   runs, only over lazy entries, which the handler resolves by mapping them anew, never by
//!   installing pages there. Elsewhere the guest may store to any page at any time, and a map
//!   would drop what it stored. So a handler may list guest memory lazily, piece by piece as the
//!   guest first touches it.
//! - **Persist.** Making a snapshot, once device state is saved, Firecracker sends
//!   [`ToHandler::Persist`] and waits. The handler keeps guest memory's contents as it likes (for
//!   example reading the VM's private pages through `process_vm_readv`), may remap regions so
//!   that what it kept is shared again, and answers [`FromHandler::Persisted`] with a result,
//!   which `/snapshot/create` returns. No memory file is written.
//!
//! The handler going away ends the VM, which has no one to serve its faults: Firecracker exits
//! with [`FcExitCode::MemoryBackendLost`]. A list that fails part-way (`ENOMEM` past
//! `vm.max_map_count`, say) ends it too, as its memory is then neither what it was nor what the
//! handler asked for.
//!
//! Each entry is applied in three steps: mapped inaccessible, registered with the userfaultfd (if
//! of a file), then made accessible. No access, not even a stale one of KVM's asynchronous page
//! fault worker, reaches a file entry before it is registered: in between it fails. Registered
//! too late, a read of a hole in the file would put a zero page in the file, and in this VM's
//! page table, where the handler would never see it.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, Weak};

use libc::iovec;
use serde::{Deserialize, Serialize};
use userfaultfd::{RegisterMode, Uffd, UffdBuilder};
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

use crate::FcExitCode;
use crate::logger::error;
use crate::persist::GuestRegionUffdMapping;
use crate::seccomp::{BpfProgram, apply_filter};

/// The most bytes a frame's JSON may have.
const MAX_FRAME: usize = 64 << 20;
/// The most file descriptors a frame may carry.
const MAX_FDS: usize = 64;

/// What Firecracker sends the handler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ToHandler {
    /// The regions the handler serves, guest memory's first, then those of the pmem devices it
    /// serves (named by `pmem_id`), with the userfaultfd attached. Regions are named by their
    /// index in this list.
    Handshake {
        /// The regions.
        regions: Vec<GuestRegionUffdMapping>,
    },
    /// A [`FromHandler::Map`] applied.
    Mapped {
        /// The map's ID.
        id: u64,
    },
    /// A [`FromHandler::Map`] refused, nothing of it applied: an entry out of its region, not of
    /// whole pages, or naming a file descriptor the frame doesn't carry; or of guest memory while
    /// no snapshot is being made.
    MapRefused {
        /// The map's ID.
        id: u64,
        /// Why.
        error: String,
    },
    /// Device state is saved and the vCPUs paused: persist guest memory, answering
    /// [`FromHandler::Persisted`].
    Persist,
}

/// What the handler sends Firecracker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FromHandler {
    /// Map `entries` over region `region`, each replacing what was there.
    Map {
        /// The map's ID, which its answer names.
        id: u64,
        /// The region's index in the handshake.
        region: usize,
        /// The mappings, applied in order.
        entries: Vec<Entry>,
    },
    /// Every region is mapped: the VM may start.
    Ready,
    /// Guest memory is persisted, as `result` says.
    Persisted {
        /// What `/snapshot/create` returns.
        result: serde_json::Value,
    },
}

/// A mapping of `len` bytes at `offset` in a region, both multiples of the host page size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Entry {
    /// The file the frame's `fd`th descriptor is, from `file_offset`, mapped private.
    File {
        /// The descriptor's index among the frame's.
        fd: usize,
        /// Where in the file the mapping starts.
        file_offset: u64,
        /// Where in the region it starts.
        offset: u64,
        /// Its length.
        len: u64,
    },
    /// Anonymous memory: zeros, made private by a store.
    Zeros {
        /// Where in the region it starts.
        offset: u64,
        /// Its length.
        len: u64,
    },
    /// Nothing: an access fails.
    None {
        /// Where in the region it starts.
        offset: u64,
        /// Its length.
        len: u64,
    },
    /// Anonymous memory registered for missing faults: its first touch reaches the handler, which
    /// maps the range anew (guest memory's while the guest runs too) and wakes the fault.
    Lazy {
        /// Where in the region it starts.
        offset: u64,
        /// Its length.
        len: u64,
    },
}

impl Entry {
    fn range(&self) -> (u64, u64) {
        match *self {
            Entry::File { offset, len, .. }
            | Entry::Zeros { offset, len }
            | Entry::None { offset, len }
            | Entry::Lazy { offset, len } => (offset, len),
        }
    }
}

/// The lazy entries of a region: their ranges, start to end, adjacent ones joined.
#[derive(Debug, Default)]
struct LazyRanges(std::collections::BTreeMap<u64, u64>);

impl LazyRanges {
    /// Whether `[offset, offset + len)` lies within one lazy range.
    fn covers(&self, offset: u64, len: u64) -> bool {
        (self.0.range(..=offset).next_back()).is_some_and(|(_, end)| offset + len <= *end)
    }

    /// Takes `[start, end)` out of the ranges.
    fn remove(&mut self, start: u64, end: u64) {
        let overlapping: Vec<(u64, u64)> = (self.0.range(..end))
            .filter(|(_, e)| **e > start)
            .map(|(s, e)| (*s, *e))
            .collect();
        for (s, e) in overlapping {
            self.0.remove(&s);
            if s < start {
                self.0.insert(s, start);
            }
            if e > end {
                self.0.insert(end, e);
            }
        }
    }

    /// Adds `[start, end)`, joining it to the ranges beside it.
    fn add(&mut self, mut start: u64, mut end: u64) {
        self.remove(start, end);
        if let Some((s, e)) = self.0.range(..start).next_back().map(|(s, e)| (*s, *e))
            && e == start
        {
            self.0.remove(&s);
            start = s;
        }
        if let Some(e) = self.0.remove(&end) {
            end = e;
        }
        self.0.insert(start, end);
    }
}

/// Errors of the `Mappings` memory backend.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum MemoryBackendError {
    /// Cannot connect to the memory backend: {0}
    Connect(io::Error),
    /// Cannot create the userfaultfd: {0}
    Uffd(userfaultfd::Error),
    /// Memory backend socket: {0}
    Io(io::Error),
    /// Memory backend socket: {0}
    Socket(vmm_sys_util::errno::Error),
    /// The memory backend sent a frame of {0} bytes, past the most a frame may have
    FrameSize(usize),
    /// The memory backend's message is not valid: {0}
    Message(serde_json::Error),
    /// The memory backend sent {0:?} where Firecracker expected another message
    Unexpected(FromHandler),
    /// The memory backend went away
    Gone,
    /// The memory backend's map is refused: {0}
    Refused(String),
    /// Applying the memory backend's map failed part-way: {0}
    Apply(io::Error),
    /// Registering a mapping with the userfaultfd failed part-way: {0}
    Register(userfaultfd::Error),
}

/// A region the handler maps, as Firecracker reserved it: where its host memory starts, and its
/// size.
#[derive(Debug, Clone)]
pub struct Region {
    /// Its host memory's address.
    pub host_addr: u64,
    /// Its size.
    pub size: u64,
    /// Whether it is guest memory's, which is mapped while a snapshot is made alone.
    pub guest_memory: bool,
    /// A hold on its host memory's mapping, which keeps the reservation mapped while the backend
    /// may map into it: its device unplugged, a boot failed, or the VM torn down meanwhile, the
    /// address space is never freed under a map and used again.
    pub memory: Arc<dyn std::fmt::Debug + Send + Sync>,
}

/// A connected `Mappings` memory backend.
#[derive(Debug)]
pub struct MemoryBackend {
    /// Frames to the handler, from the VMM thread and the reader.
    writer: Mutex<UnixStream>,
    /// The regions, by index.
    regions: Vec<Region>,
    /// What the reader passes the VMM thread: a persist's result.
    persisted: Mutex<Receiver<serde_json::Value>>,
    /// Whether a snapshot is being made, while guest memory's regions may be remapped.
    persisting: Mutex<bool>,
    /// Each region's lazy entries, by index: what of guest memory may be remapped while the guest
    /// runs.
    lazy: Mutex<Vec<LazyRanges>>,
}

impl MemoryBackend {
    /// Connects to the handler at `path`, hands it `regions` (each described for the handshake by
    /// the mapping beside it) and a new userfaultfd, and applies its maps until it is ready. Then
    /// reads its later messages on a thread of its own, under `filter`, the VMM thread's seccomp
    /// filter, which the thread starts before it is installed.
    pub fn start(
        path: &Path,
        regions: Vec<(Region, GuestRegionUffdMapping)>,
        filter: Arc<BpfProgram>,
    ) -> Result<Arc<Self>, MemoryBackendError> {
        let stream = UnixStream::connect(path).map_err(MemoryBackendError::Connect)?;
        // Kernel faults included (KVM's), which `/dev/userfaultfd` gives an unprivileged process.
        // No events: a remove event would block the VMM thread in `madvise` until the handler read
        // it.
        let uffd = UffdBuilder::new()
            .close_on_exec(true)
            .non_blocking(true)
            .user_mode_only(false)
            .create()
            .map_err(MemoryBackendError::Uffd)?;
        let (described, regions): (Vec<_>, Vec<_>) =
            regions.into_iter().map(|(r, m)| (m, r)).unzip();
        send_frame(
            &stream,
            &ToHandler::Handshake { regions: described },
            &[uffd.as_raw_fd()],
        )?;
        let (persisted_tx, persisted) = mpsc::channel();
        let lazy = Mutex::new(regions.iter().map(|_| LazyRanges::default()).collect());
        let backend = Arc::new(Self {
            writer: Mutex::new(stream.try_clone().map_err(MemoryBackendError::Io)?),
            regions,
            persisted: Mutex::new(persisted),
            persisting: Mutex::new(true),
            lazy,
        });
        let mut reader = Reader {
            backend: Arc::downgrade(&backend),
            stream,
            uffd,
            persisted: persisted_tx,
        };
        // The maps before it applied, the next message must say the handler is ready.
        match reader.next()? {
            FromHandler::Ready => {}
            unexpected => return Err(MemoryBackendError::Unexpected(unexpected)),
        }
        *backend.persisting.lock().expect("Poisoned lock") = false;
        std::thread::Builder::new()
            .name("fc_memory_backend".into())
            .spawn(move || {
                if let Err(err) = apply_filter(&filter) {
                    error!("Memory backend: installing its thread's seccomp filter: {err}");
                    std::process::exit(FcExitCode::BadSyscall as i32);
                }
                reader.run()
            })
            .map_err(MemoryBackendError::Io)?;
        Ok(backend)
    }

    /// Asks the handler to persist guest memory, which device state now holds still, applying the
    /// maps it sends meanwhile: its result.
    pub fn persist(&self) -> Result<serde_json::Value, MemoryBackendError> {
        *self.persisting.lock().expect("Poisoned lock") = true;
        let result = self.send(&ToHandler::Persist).and_then(|()| {
            (self.persisted.lock().expect("Poisoned lock").recv())
                .map_err(|_| MemoryBackendError::Gone)
        });
        *self.persisting.lock().expect("Poisoned lock") = false;
        result
    }

    fn send(&self, message: &ToHandler) -> Result<(), MemoryBackendError> {
        send_frame(&self.writer.lock().expect("Poisoned lock"), message, &[])
    }

    /// Checks `entries` against region `region`, whose lazy ranges are `lazy`, with `fds`
    /// descriptors: nothing is applied of a map refused.
    fn check(
        &self,
        region: usize,
        lazy: &LazyRanges,
        entries: &[Entry],
        fds: usize,
    ) -> Result<&Region, String> {
        let page = host_page_size();
        let r = (self.regions.get(region)).ok_or_else(|| format!("no region {region}"))?;
        let guest_runs = r.guest_memory && !*self.persisting.lock().expect("Poisoned lock");
        for entry in entries {
            let (offset, len) = entry.range();
            if guest_runs && !lazy.covers(offset, len) {
                return Err(format!(
                    "{entry:?} maps guest memory that is not lazy while the guest runs"
                ));
            }
        }
        for entry in entries {
            let (offset, len) = entry.range();
            if offset % page != 0 || len % page != 0 || len == 0 {
                return Err(format!("{entry:?} is not of whole pages"));
            }
            if offset.checked_add(len).is_none_or(|end| end > r.size) {
                return Err(format!(
                    "{entry:?} is past region {region}'s {} bytes",
                    r.size
                ));
            }
            if let Entry::File {
                fd, file_offset, ..
            } = entry
            {
                if *fd >= fds {
                    return Err(format!("{entry:?} names a descriptor of {fds}"));
                }
                if file_offset % page != 0 {
                    return Err(format!("{entry:?} is not of whole pages"));
                }
            }
        }
        Ok(r)
    }
}

/// The thread reading the handler's messages.
#[derive(Debug)]
struct Reader {
    /// The backend, which the VM holds, while it does.
    backend: Weak<MemoryBackend>,
    stream: UnixStream,
    uffd: Uffd,
    persisted: Sender<serde_json::Value>,
}

impl Reader {
    /// The handler's next message other than a map, applying and answering maps.
    fn next(&mut self) -> Result<FromHandler, MemoryBackendError> {
        loop {
            let (message, fds) = recv_frame(&self.stream)?;
            let FromHandler::Map {
                id,
                region,
                entries,
            } = message
            else {
                return Ok(message);
            };
            let backend = self.backend.upgrade().ok_or(MemoryBackendError::Gone)?;
            let answer = {
                let mut lazy = backend.lazy.lock().expect("Poisoned lock");
                let lazy = lazy.get_mut(region);
                match lazy
                    .ok_or_else(|| format!("no region {region}"))
                    .and_then(|lazy| {
                        let r = backend.check(region, lazy, &entries, fds.len())?;
                        Ok((r, lazy))
                    }) {
                    Ok((r, lazy)) => {
                        apply(&self.uffd, r, &entries, &fds)?;
                        for entry in &entries {
                            let (offset, len) = entry.range();
                            match entry {
                                Entry::Lazy { .. } => lazy.add(offset, offset + len),
                                _ => lazy.remove(offset, offset + len),
                            }
                        }
                        ToHandler::Mapped { id }
                    }
                    Err(error) => ToHandler::MapRefused { id, error },
                }
            };
            backend.send(&answer)?;
        }
    }

    /// Serves the handler's messages until it goes, when the VM ends; or until the VM is gone,
    /// when it ends quietly: a process that keeps running with the VM gone (a failed boot, a
    /// test) closes the socket in its own time, the reader blocked on it meanwhile.
    fn run(mut self) {
        let err = loop {
            match self.next() {
                Ok(FromHandler::Persisted { result }) => {
                    if self.persisted.send(result).is_err() {
                        break MemoryBackendError::Gone;
                    }
                }
                Ok(unexpected) => break MemoryBackendError::Unexpected(unexpected),
                Err(err) => break err,
            }
        };
        if self.backend.strong_count() == 0 {
            return;
        }
        error!("Memory backend: {err}; the VM can't go on");
        std::process::exit(FcExitCode::MemoryBackendLost as i32);
    }
}

/// Applies `entries` over region `r`, checked: each mapped inaccessible, registered if of a file,
/// then made accessible.
fn apply(
    uffd: &Uffd,
    r: &Region,
    entries: &[Entry],
    fds: &[File],
) -> Result<(), MemoryBackendError> {
    for entry in entries {
        let (offset, len) = entry.range();
        let addr = r.host_addr + offset;
        let (fd, file_offset, flags) = match *entry {
            Entry::File {
                fd, file_offset, ..
            } => (fds[fd].as_raw_fd(), file_offset, libc::MAP_PRIVATE),
            Entry::Zeros { .. } | Entry::None { .. } | Entry::Lazy { .. } => {
                (-1, 0, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS)
            }
        };
        let file_offset = libc::off_t::try_from(file_offset)
            .map_err(|_| MemoryBackendError::Apply(io::ErrorKind::InvalidInput.into()))?;
        // SAFETY: Replaces a range of the region's own reservation, which nothing in Firecracker
        // holds a reference into but as guest memory, whose contents the handler decides.
        let mapped = unsafe {
            libc::mmap(
                addr as *mut libc::c_void,
                usize::try_from(len).expect("checked against the region"),
                libc::PROT_NONE,
                flags | libc::MAP_FIXED | libc::MAP_NORESERVE,
                fd,
                file_offset,
            )
        };
        if mapped == libc::MAP_FAILED {
            return Err(MemoryBackendError::Apply(io::Error::last_os_error()));
        }
        if matches!(entry, Entry::None { .. }) {
            continue;
        }
        let len = usize::try_from(len).expect("checked against the region");
        // Minor faults are of a file's pages alone: anonymous memory takes missing ones.
        let mode = match entry {
            Entry::File { .. } => Some(RegisterMode::MISSING | RegisterMode::MINOR),
            Entry::Lazy { .. } => Some(RegisterMode::MISSING),
            Entry::Zeros { .. } | Entry::None { .. } => None,
        };
        if let Some(mode) = mode {
            uffd.register_with_mode(addr as *mut libc::c_void, len, mode)
                .map_err(MemoryBackendError::Register)?;
        }
        // SAFETY: Opens the range just mapped.
        if unsafe {
            libc::mprotect(
                addr as *mut libc::c_void,
                len,
                libc::PROT_READ | libc::PROT_WRITE,
            )
        } != 0
        {
            return Err(MemoryBackendError::Apply(io::Error::last_os_error()));
        }
    }
    Ok(())
}

fn host_page_size() -> u64 {
    // SAFETY: Reads a configuration value.
    u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).expect("a page size")
}

/// Sends `message` as a frame, with `fds` attached.
pub fn send_frame<M: Serialize>(
    stream: &UnixStream,
    message: &M,
    fds: &[RawFd],
) -> Result<(), MemoryBackendError> {
    let body = serde_json::to_vec(message).map_err(MemoryBackendError::Message)?;
    let header = u32::try_from(body.len())
        .map_err(|_| MemoryBackendError::FrameSize(body.len()))?
        .to_le_bytes();
    let mut frame = Vec::with_capacity(header.len() + body.len());
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&body);
    let sent = stream
        .send_with_fds(&[frame.as_slice()], fds)
        .map_err(MemoryBackendError::Socket)?;
    // The descriptors went with the first bytes: the rest go as a stream's do.
    (&*stream)
        .write_all(&frame[sent..])
        .map_err(MemoryBackendError::Io)
}

/// Receives a frame: its message, and the descriptors attached to it.
pub fn recv_frame<M: for<'de> Deserialize<'de>>(
    stream: &UnixStream,
) -> Result<(M, Vec<File>), MemoryBackendError> {
    let mut header = [0u8; 4];
    let mut raw_fds = [-1; MAX_FDS];
    let mut iov = [iovec {
        iov_base: header.as_mut_ptr().cast(),
        iov_len: header.len(),
    }];
    // SAFETY: The iovec is the header's buffer, which nothing else uses meanwhile.
    let (read, count) = unsafe { stream.recv_with_fds(&mut iov, &mut raw_fds) }
        .map_err(MemoryBackendError::Socket)?;
    let fds = raw_fds[..count]
        .iter()
        // SAFETY: The kernel gave each descriptor to this process alone.
        .map(|fd| unsafe { File::from_raw_fd(*fd) })
        .collect();
    if read == 0 {
        return Err(MemoryBackendError::Gone);
    }
    (&*stream)
        .read_exact(&mut header[read..])
        .map_err(MemoryBackendError::Io)?;
    let len = u32::from_le_bytes(header) as usize;
    if len > MAX_FRAME {
        return Err(MemoryBackendError::FrameSize(len));
    }
    let mut body = vec![0u8; len];
    (&*stream)
        .read_exact(&mut body)
        .map_err(MemoryBackendError::Io)?;
    let message = serde_json::from_slice(&body).map_err(MemoryBackendError::Message)?;
    Ok((message, fds))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Messages are as the protocol names them, entries tagged by their kind.
    #[test]
    fn test_messages_json() {
        let map: FromHandler = serde_json::from_str(
            r#"{"type": "map", "id": 7, "region": 1, "entries": [
                {"kind": "file", "fd": 0, "file_offset": 8192, "offset": 0, "len": 4096},
                {"kind": "zeros", "offset": 4096, "len": 4096},
                {"kind": "none", "offset": 8192, "len": 4096}
            ]}"#,
        )
        .unwrap();
        assert_eq!(
            map,
            FromHandler::Map {
                id: 7,
                region: 1,
                entries: vec![
                    Entry::File {
                        fd: 0,
                        file_offset: 8192,
                        offset: 0,
                        len: 4096
                    },
                    Entry::Zeros {
                        offset: 4096,
                        len: 4096
                    },
                    Entry::None {
                        offset: 8192,
                        len: 4096
                    },
                ],
            }
        );
        assert_eq!(
            serde_json::to_string(&ToHandler::Persist).unwrap(),
            r#"{"type":"persist"}"#
        );
        assert_eq!(
            serde_json::to_string(&ToHandler::MapRefused {
                id: 3,
                error: "no".into()
            })
            .unwrap(),
            r#"{"type":"map_refused","id":3,"error":"no"}"#
        );
    }

    /// Lazy ranges join as they are added, split as they are taken out, and cover what lies in one.
    #[test]
    fn test_lazy_ranges() {
        let mut lazy = LazyRanges::default();
        lazy.add(0, 4);
        lazy.add(4, 8);
        lazy.add(12, 16);
        assert_eq!(lazy.0.iter().collect::<Vec<_>>(), [(&0, &8), (&12, &16)]);
        assert!(lazy.covers(2, 6));
        assert!(!lazy.covers(6, 8));
        lazy.remove(2, 14);
        assert_eq!(lazy.0.iter().collect::<Vec<_>>(), [(&0, &2), (&14, &16)]);
        lazy.add(2, 14);
        assert_eq!(lazy.0.iter().collect::<Vec<_>>(), [(&0, &16)]);
        assert!(lazy.covers(0, 16));
    }

    /// A frame's message and descriptors arrive together, the descriptors with the frame they were
    /// sent with.
    #[test]
    fn test_frames_carry_descriptors() {
        let (a, b) = UnixStream::pair().unwrap();
        let file = vmm_sys_util::tempfile::TempFile::new().unwrap();
        send_frame(&a, &FromHandler::Ready, &[file.as_file().as_raw_fd()]).unwrap();
        send_frame(
            &a,
            &FromHandler::Persisted {
                result: serde_json::json!({"version": 3}),
            },
            &[],
        )
        .unwrap();
        let (message, fds) = recv_frame::<FromHandler>(&b).unwrap();
        assert_eq!(message, FromHandler::Ready);
        assert_eq!(fds.len(), 1);
        let (message, fds) = recv_frame::<FromHandler>(&b).unwrap();
        assert_eq!(
            message,
            FromHandler::Persisted {
                result: serde_json::json!({"version": 3})
            }
        );
        assert!(fds.is_empty());
        drop(a);
        assert!(matches!(
            recv_frame::<FromHandler>(&b),
            Err(MemoryBackendError::Gone)
        ));
    }
}
