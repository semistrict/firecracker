//! A single bounded durability worker per managed PMEM device.

use std::io;
use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use vmm_sys_util::eventfd::EventFd;

use crate::managed_memory::Owner;

#[derive(Debug)]
pub(super) struct FlushWorker {
    request: Option<mpsc::SyncSender<()>>,
    result: mpsc::Receiver<i32>,
    thread: Option<JoinHandle<()>>,
    pub event: EventFd,
}

impl FlushWorker {
    pub fn new(owner: Arc<Owner>) -> io::Result<Self> {
        let event = EventFd::new(libc::EFD_NONBLOCK)?;
        let notify = event.try_clone()?;
        let (request, receiver) = mpsc::sync_channel(1);
        let (sender, result) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("sproutfs-pmem-flush".into())
            .spawn(move || {
                if let Err(err) = owner.apply_worker_policy() {
                    eprintln!("Cannot install PMEM-worker policy: {err}");
                    #[allow(clippy::exit)]
                    std::process::exit(1);
                }
                while receiver.recv().is_ok() {
                    let status = if owner.flush(0).is_ok() { 0 } else { -1 };
                    if sender.send(status).is_err() {
                        break;
                    }
                    if notify.write(1).is_err() {
                        // The VMM cannot safely acknowledge or retry a batch
                        // when the completion channel is no longer observable.
                        #[allow(clippy::exit)]
                        std::process::exit(1);
                    }
                }
            })?;
        Ok(Self {
            request: Some(request),
            result,
            thread: Some(thread),
            event,
        })
    }

    #[cfg(test)]
    pub fn controlled() -> (Self, mpsc::Receiver<()>, mpsc::SyncSender<i32>) {
        let (request, receiver) = mpsc::sync_channel(1);
        let (sender, result) = mpsc::sync_channel(1);
        (
            Self {
                request: Some(request),
                result,
                thread: None,
                event: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            },
            receiver,
            sender,
        )
    }

    pub fn submit(&self) -> io::Result<()> {
        self.request
            .as_ref()
            .unwrap()
            .try_send(())
            .map_err(io::Error::other)
    }

    pub fn complete(&self, wait: bool) -> io::Result<Option<i32>> {
        if wait {
            self.result
                .recv_timeout(Duration::from_secs(35))
                .map(Some)
                .map_err(io::Error::other)
        } else {
            match self.result.try_recv() {
                Ok(status) => Ok(Some(status)),
                Err(mpsc::TryRecvError::Empty) => Ok(None),
                Err(err) => Err(io::Error::other(err)),
            }
        }
    }
}

impl Drop for FlushWorker {
    fn drop(&mut self) {
        self.request.take();
        if let Some(thread) = self.thread.take() {
            thread.join().expect("PMEM durability worker panicked");
        }
    }
}
