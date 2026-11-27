// Copyright 2026 cladefs authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;
use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::cladefs::{
    CladefsDeviceCellState, CladefsDeviceConfig, CladefsDeviceUpdateConfig,
};
use vmm::vmm_config::memory_cell::MemoryCellBootConfig;

use super::super::parsed_request::{ParsedRequest, RequestError, checked_id};
use super::{Body, StatusCode};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchCladefsBody {
    #[serde(default)]
    id: Option<String>,
    state: CladefsDeviceCellState,
}

pub(crate) fn parse_put_cladefs(
    body: &Body,
    id_from_path: Option<&str>,
) -> Result<ParsedRequest, RequestError> {
    let id = checked_id(id_from_path.ok_or(RequestError::EmptyID)?)?;
    let device_cfg = serde_json::from_slice::<CladefsDeviceConfig>(body.raw())?;
    if id != device_cfg.id {
        return Err(RequestError::Generic(
            StatusCode::BadRequest,
            "The id from the path does not match the id from the body!".to_string(),
        ));
    }
    Ok(ParsedRequest::new_sync(VmmAction::InsertCladefsDevice(
        device_cfg,
    )))
}

pub(crate) fn parse_patch_cladefs(
    body: &Body,
    id_from_path: Option<&str>,
) -> Result<ParsedRequest, RequestError> {
    let id = checked_id(id_from_path.ok_or(RequestError::EmptyID)?)?;
    let patch = serde_json::from_slice::<PatchCladefsBody>(body.raw())?;
    if let Some(body_id) = patch.id
        && body_id != id
    {
        return Err(RequestError::Generic(
            StatusCode::BadRequest,
            "The id from the path does not match the id from the body!".to_string(),
        ));
    }
    Ok(ParsedRequest::new_sync(VmmAction::UpdateCladefsDevice(
        CladefsDeviceUpdateConfig {
            id: id.to_owned(),
            state: patch.state,
        },
    )))
}

/// `PUT /memory-cell`: the memory cell a freshly booted VM's memory is the window of (board 14415).
pub(crate) fn parse_put_memory_cell(body: &Body) -> Result<ParsedRequest, RequestError> {
    let config = serde_json::from_slice::<MemoryCellBootConfig>(body.raw())?;
    Ok(ParsedRequest::new_sync(VmmAction::SetMemoryCell(config)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_server::parsed_request::tests::vmm_action_from_request;

    const BODY: &str = r#"{
        "id": "extents",
        "tag": "fxfs",
        "path_on_host": "/store",
        "capacity": 1073741824,
        "dax_window_size": 67108864,
        "cladefsd_socket": "/cladefsd.sock"
    }"#;

    #[test]
    fn test_parse_put_cladefs_request() {
        parse_put_cladefs(&Body::new("invalid_payload"), None).unwrap_err();
        parse_put_cladefs(&Body::new(BODY), Some("other")).unwrap_err();
        let expected = CladefsDeviceConfig {
            id: "extents".into(),
            tag: "fxfs".into(),
            path_on_host: "/store".into(),
            capacity: 1 << 30,
            dax_window_size: Some(64 << 20),
            dax_private_max_bytes: None,
            cladefsd_socket: "/cladefsd.sock".into(),
            cache_type: vmm::vmm_config::cladefs::CacheType::Writeback,
        };
        assert_eq!(
            vmm_action_from_request(parse_put_cladefs(&Body::new(BODY), Some("extents")).unwrap()),
            VmmAction::InsertCladefsDevice(expected)
        );
    }

    #[test]
    fn test_parse_put_memory_cell_request() {
        parse_put_memory_cell(&Body::new(r#"{"path_on_host":"0/0"}"#)).unwrap_err();
        parse_put_memory_cell(&Body::new(
            r#"{"path_on_host":"0/0","cladefsd_socket":"/s","version":1}"#,
        ))
        .unwrap_err();
        assert_eq!(
            vmm_action_from_request(
                parse_put_memory_cell(&Body::new(
                    r#"{"path_on_host":"0/0","cladefsd_socket":"/cladefsd.sock"}"#
                ))
                .unwrap()
            ),
            VmmAction::SetMemoryCell(MemoryCellBootConfig {
                path_on_host: "0/0".into(),
                cladefsd_socket: "/cladefsd.sock".into(),
                ephemeral: false,
            })
        );
    }

    #[test]
    fn test_parse_patch_cladefs_request() {
        parse_patch_cladefs(&Body::new(r#"{"state":"Released"}"#), None).unwrap_err();
        parse_patch_cladefs(&Body::new(r#"{"state":"Invalid"}"#), Some("extents")).unwrap_err();
        parse_patch_cladefs(
            &Body::new(r#"{"id":"other","state":"Released"}"#),
            Some("extents"),
        )
        .unwrap_err();
        parse_patch_cladefs(
            &Body::new(r#"{"id":"","state":"Released"}"#),
            Some("extents"),
        )
        .unwrap_err();
        parse_patch_cladefs(
            &Body::new(r#"{"state":"Released","unknown":true}"#),
            Some("extents"),
        )
        .unwrap_err();

        assert_eq!(
            vmm_action_from_request(
                parse_patch_cladefs(&Body::new(r#"{"state":"Released"}"#), Some("extents"))
                    .unwrap()
            ),
            VmmAction::UpdateCladefsDevice(CladefsDeviceUpdateConfig {
                id: "extents".into(),
                state: CladefsDeviceCellState::Released,
            })
        );
        assert_eq!(
            vmm_action_from_request(
                parse_patch_cladefs(
                    &Body::new(r#"{"id":"extents","state":"Open"}"#),
                    Some("extents")
                )
                .unwrap()
            ),
            VmmAction::UpdateCladefsDevice(CladefsDeviceUpdateConfig {
                id: "extents".into(),
                state: CladefsDeviceCellState::Open,
            })
        );
    }
}
