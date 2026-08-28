// SPDX-License-Identifier: AGPL-3.0-only

pub const INSTALLATION_PROBE_SCHEMA_NAME: &str = "letsinfer.installer.installation-probe";
pub const INSTALLATION_PROBE_SCHEMA_VERSION: u64 = 1;

pub const PLATFORM_PROBE_COMPLETE_EVENT: &str = "letsinfer.event=platform_probe_complete";
pub const DEPENDENCIES_READY_EVENT: &str = "letsinfer.event=dependencies_ready";
pub const DEPENDENCIES_INSTALLED_EVENT: &str = "letsinfer.event=dependencies_installed";
pub const DEPENDENCIES_VERIFIED_EVENT: &str = "letsinfer.event=dependencies_verified";
