// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, TryRecvError, channel};
use std::sync::{Arc, Mutex};
use std::thread;

use event_manager::{EventOps, Events, MutEventSubscriber, SubscriberOps};
use vmm::logger::{ProcessTimeReporter, error_unrestricted, info_unrestricted, warn_unrestricted};
use vmm::rpc_interface::{
    ApiRequest, ApiResponse, BuildMicrovmFromRequestsError, PrebootApiController,
    RuntimeApiController, VmmAction,
};
use vmm::seccomp::BpfThreadMap;
use vmm::vmm_config::instance_info::InstanceInfo;
use vmm::{EventManager, FcExitCode, Vmm};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

use super::api_server::{ApiServer, HttpServer, ServerError};

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ApiServerError {
    /// Failed to build MicroVM: {0}.
    BuildMicroVmError(BuildMicrovmFromRequestsError),
    /// MicroVM stopped with an error: {0:?}
    MicroVMStoppedWithError(FcExitCode),
    /// Failed to open the API socket at: {0}. Check that it is not already used.
    FailedToBindSocket(String),
    /// Failed to bind and run the HTTP server: {0}
    FailedToBindAndRunHttpServer(ServerError),
    /// Failed to build MicroVM from Json: {0}
    BuildFromJson(crate::BuildFromJsonError),
    /// Missing vmm seccomp filter
    MissingSeccompFilter,
    /// Failed to install vmm seccomp filter: {0}
    SeccompFilter(vmm::seccomp::InstallationError),
}

/// Event-loop side of the API channel.
///
/// Deliberately holds only what [`MutEventSubscriber::process`] touches. The
/// controller and the response sender live outside it, in [`ApiServerAdapter`], so
/// that dispatching a request does not require holding this lock — a handler that
/// pumps the event loop (see `RuntimeApiController::precopy_snapshot`) would
/// otherwise deadlock against its own subscriber the moment another API request
/// arrived.
#[derive(Debug)]
struct ApiRequestSlot {
    api_event_fd: EventFd,
    from_api: Receiver<ApiRequest>,
    /// At most one request is ever outstanding: the API thread blocks on its
    /// response before sending another.
    request: Option<ApiRequest>,
}

#[derive(Debug)]
struct ApiServerAdapter {
    slot: Arc<Mutex<ApiRequestSlot>>,
    to_api: Sender<ApiResponse>,
    controller: RuntimeApiController,
}

impl ApiServerAdapter {
    /// Runs the vmm to completion, while any arising control events are deferred
    /// to a `RuntimeApiController`.
    fn run_microvm(
        api_event_fd: EventFd,
        from_api: Receiver<ApiRequest>,
        to_api: Sender<ApiResponse>,
        vmm: Arc<Mutex<Vmm>>,
        event_manager: &mut EventManager,
    ) -> Result<(), ApiServerError> {
        let slot = Arc::new(Mutex::new(ApiRequestSlot {
            api_event_fd,
            from_api,
            request: None,
        }));
        event_manager.add_subscriber(slot.clone());

        let mut adapter = Self {
            slot,
            to_api,
            controller: RuntimeApiController::new(vmm.clone()),
        };

        loop {
            event_manager
                .run()
                .expect("EventManager events driver fatal error");
            adapter.handle_request(event_manager);

            match vmm.lock().unwrap().shutdown_exit_code() {
                Some(FcExitCode::Ok) => break,
                Some(exit_code) => return Err(ApiServerError::MicroVMStoppedWithError(exit_code)),
                None => continue,
            }
        }
        Ok(())
    }

    fn _handle_request(&mut self, req_action: VmmAction, event_manager: &mut EventManager) {
        let response = self.controller.handle_request(req_action, event_manager);
        // Send back the result.
        self.to_api
            .send(Box::new(response))
            .map_err(|_| ())
            .expect("one-shot channel closed");
    }

    fn handle_request(&mut self, event_manager: &mut EventManager) {
        let Some(api_request) = self.slot.lock().expect("Poisoned lock").request.take() else {
            return;
        };

        let request_is_pause = *api_request == VmmAction::Pause;
        self._handle_request(*api_request, event_manager);

        // If the latest req is a pause request, temporarily switch to a mode where we
        // do blocking `recv`s on the `from_api` receiver in a loop, until we get
        // unpaused. The device emulation is implicitly paused since we do not
        // relinquish control to the event manager because we're not returning from
        // `process`.
        if request_is_pause {
            // This loop only attempts to process API requests, so things like the
            // metric flush timerfd handling are frozen as well.
            loop {
                let req = {
                    let slot = self.slot.lock().expect("Poisoned lock");
                    slot.from_api.recv().expect("Error receiving API request.")
                };
                let req_is_resume = *req == VmmAction::Resume;
                self._handle_request(*req, event_manager);
                if req_is_resume {
                    break;
                }
            }
        }
    }
}
impl MutEventSubscriber for ApiRequestSlot {
    /// Handle a read event (EPOLLIN).
    fn process(&mut self, event: Events, _: &mut EventOps) {
        let source = event.fd();
        let event_set = event.event_set();

        if source == self.api_event_fd.as_raw_fd() && event_set == EventSet::IN {
            let _ = self.api_event_fd.read();
            match self.from_api.try_recv() {
                Ok(api_request) => {
                    self.request = Some(api_request);
                }
                Err(TryRecvError::Empty) => {
                    warn_unrestricted!("Got a spurious notification from api thread");
                }
                Err(TryRecvError::Disconnected) => {
                    panic!("The channel's sending half was disconnected. Cannot receive data.");
                }
            };
        } else {
            error_unrestricted!("Spurious EventManager event for handler: ApiRequestSlot");
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        if let Err(err) = ops.add(Events::new(&self.api_event_fd, EventSet::IN)) {
            error_unrestricted!("Failed to register activate event: {}", err);
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_with_api(
    seccomp_filters: &mut BpfThreadMap,
    config_json: Option<String>,
    bind_path: PathBuf,
    instance_info: InstanceInfo,
    process_time_reporter: ProcessTimeReporter,
    boot_timer_enabled: bool,
    pci_enabled: bool,
    api_payload_limit: usize,
    mmds_size_limit: usize,
    metadata_json: Option<&str>,
) -> Result<(), ApiServerError> {
    // FD to notify of API events. This is a blocking eventfd by design.
    // It is used in the config/pre-boot loop which is a simple blocking loop
    // which only consumes API events.
    let api_event_fd = EventFd::new(libc::EFD_SEMAPHORE).expect("Cannot create API Eventfd.");
    // FD used to signal API thread to stop/shutdown.
    let api_kill_switch = EventFd::new(libc::EFD_NONBLOCK).expect("Cannot create API kill switch.");

    // Channels for both directions between Vmm and Api threads.
    let (to_vmm, from_api) = channel();
    let (to_api, from_vmm) = channel();

    let to_vmm_event_fd = api_event_fd
        .try_clone()
        .expect("Failed to clone API event FD");
    let api_seccomp_filter = seccomp_filters
        .remove("api")
        .expect("Missing seccomp filter for API thread.");

    let mut server = match HttpServer::new(&bind_path) {
        Ok(s) => s,
        Err(ServerError::IOError(inner)) if inner.kind() == std::io::ErrorKind::AddrInUse => {
            let sock_path = bind_path.display().to_string();
            return Err(ApiServerError::FailedToBindSocket(sock_path));
        }
        Err(err) => {
            return Err(ApiServerError::FailedToBindAndRunHttpServer(err));
        }
    };
    info_unrestricted!("Listening on API socket ({bind_path:?}).");

    let api_kill_switch_clone = api_kill_switch
        .try_clone()
        .expect("Failed to clone API kill switch");

    server
        .add_kill_switch(api_kill_switch_clone)
        .expect("Cannot add HTTP server kill switch");

    // Start the separate API thread.
    let api_thread = thread::Builder::new()
        .name("fc_api".to_owned())
        .spawn(move || {
            ApiServer::new(to_vmm, from_vmm, to_vmm_event_fd).run(
                server,
                process_time_reporter,
                &api_seccomp_filter,
                api_payload_limit,
            );
        })
        .expect("API thread spawn failed.");

    let mut event_manager = EventManager::new().expect("Unable to create EventManager");

    // Create the firecracker metrics object responsible for periodically printing metrics.
    let firecracker_metrics = Arc::new(Mutex::new(super::metrics::PeriodicMetrics::new()));
    event_manager.add_subscriber(firecracker_metrics.clone());

    // Configure, build and start the microVM.
    let build_result = match config_json {
        Some(json) => super::build_microvm_from_json(
            seccomp_filters,
            &mut event_manager,
            json,
            instance_info,
            boot_timer_enabled,
            pci_enabled,
            mmds_size_limit,
            metadata_json,
        )
        .map_err(ApiServerError::BuildFromJson),
        None => PrebootApiController::build_microvm_from_requests(
            seccomp_filters,
            &mut event_manager,
            instance_info,
            &from_api,
            &to_api,
            &api_event_fd,
            boot_timer_enabled,
            pci_enabled,
            mmds_size_limit,
            metadata_json,
        )
        .map_err(ApiServerError::BuildMicroVmError),
    };

    // INVARIANT: seccomp must be applied before entering the event loop.
    // No guest-facing operations may occur between builder return and filter installation.
    let result = build_result.and_then(|vmm| {
        vmm::seccomp::apply_filter(
            seccomp_filters
                .get("vmm")
                .ok_or(ApiServerError::MissingSeccompFilter)?,
        )
        .map_err(ApiServerError::SeccompFilter)?;

        firecracker_metrics
            .lock()
            .expect("Poisoned lock")
            .start(super::metrics::WRITE_METRICS_PERIOD_MS);

        ApiServerAdapter::run_microvm(api_event_fd, from_api, to_api, vmm, &mut event_manager)
    });

    api_kill_switch.write(1).unwrap();
    // This call to thread::join() should block until the API thread has processed the
    // shutdown-internal and returns from its function.
    api_thread.join().expect("Api thread should join");

    result
}
