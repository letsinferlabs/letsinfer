// SPDX-License-Identifier: AGPL-3.0-only

use std::ffi::OsString;
use std::path::Path;

use li_core_application::{CoreGatewayProcessArguments, CoreGatewayProcessError};

// Accepts only the exact absolute configuration invocation emitted by CoreProcessLayout.
#[test]
fn process_arguments_match_the_resident_contract() {
    let arguments = CoreGatewayProcessArguments::parse([
        OsString::from("--configuration"),
        OsString::from("/var/lib/letsinfer/configuration/li_gateway.json"),
    ])
    .unwrap();
    assert_eq!(
        arguments.configuration(),
        Path::new("/var/lib/letsinfer/configuration/li_gateway.json")
    );
}

// Rejects missing, reordered, relative, and additional arguments without fallback parsing.
#[test]
fn malformed_process_arguments_fail_closed() {
    let cases = [
        vec![],
        vec![OsString::from("--configuration")],
        vec![
            OsString::from("--configuration"),
            OsString::from("li_gateway.json"),
        ],
        vec![
            OsString::from("--config"),
            OsString::from("/tmp/li_gateway.json"),
        ],
        vec![
            OsString::from("--configuration"),
            OsString::from("/tmp/li_gateway.json"),
            OsString::from("extra"),
        ],
    ];
    for arguments in cases {
        assert_eq!(
            CoreGatewayProcessArguments::parse(arguments),
            Err(CoreGatewayProcessError::InvalidArguments)
        );
    }
}
