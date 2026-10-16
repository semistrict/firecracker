// Copyright 2026 fxdax authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::extent::ExtentDeviceConfig;

use super::super::parsed_request::{ParsedRequest, RequestError, checked_id};
use super::{Body, StatusCode};

pub(crate) fn parse_put_extent(
    body: &Body,
    id_from_path: Option<&str>,
) -> Result<ParsedRequest, RequestError> {
    let id = checked_id(id_from_path.ok_or(RequestError::EmptyID)?)?;
    let device_cfg = serde_json::from_slice::<ExtentDeviceConfig>(body.raw())?;
    if id != device_cfg.id {
        return Err(RequestError::Generic(
            StatusCode::BadRequest,
            "The id from the path does not match the id from the body!".to_string(),
        ));
    }
    Ok(ParsedRequest::new_sync(VmmAction::InsertExtentDevice(
        device_cfg,
    )))
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
        "extentd_socket": "/extentd.sock"
    }"#;

    #[test]
    fn test_parse_put_extent_request() {
        parse_put_extent(&Body::new("invalid_payload"), None).unwrap_err();
        parse_put_extent(&Body::new(BODY), Some("other")).unwrap_err();
        let expected = ExtentDeviceConfig {
            id: "extents".into(),
            tag: "fxfs".into(),
            path_on_host: "/store".into(),
            capacity: 1 << 30,
            dax_window_size: Some(64 << 20),
            extentd_socket: "/extentd.sock".into(),
        };
        assert_eq!(
            vmm_action_from_request(parse_put_extent(&Body::new(BODY), Some("extents")).unwrap()),
            VmmAction::InsertExtentDevice(expected)
        );
    }
}
