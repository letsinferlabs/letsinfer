// SPDX-License-Identifier: AGPL-3.0-only

use li_core_interface::{
    ApiKeyId, ArtifactRevision, ArtifactUri, BootId, ByteCount, ControllerId, CredentialId,
    DeviceId, DisplayName, EndpointAddress, EndpointScheme, EntityTimestamps,
    HardwareObservationId, InstallationId, LogicalModelName, MachineId, ModelServiceId,
    NetworkInterfaceName, NetworkPort, NodeAddress, NodeId, OperationId, PairingInviteId,
    PlacementGroupId, PlacementId, PortRange, ResourceLeaseId, RuntimeCandidateId,
    RuntimeInstallationId, RuntimeSource, RuntimeVersion, Sha256Digest, TargetId, TaskId,
    TechnicalName, UnixMilliseconds,
};

const VALID_ID: &str = "0123456789abcdef0123456789abcdef";
const VALID_INSTALLATION_ID: &str =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

// Accepts the same canonical representation through every distinct identity type.
#[test]
fn identity_types_accept_canonical_values() {
    assert_eq!(NodeId::parse(VALID_ID).expect("node").as_str(), VALID_ID);
    assert_eq!(
        MachineId::parse(VALID_ID).expect("machine").as_str(),
        VALID_ID
    );
    assert_eq!(
        InstallationId::parse(VALID_INSTALLATION_ID)
            .expect("installation")
            .as_str(),
        VALID_INSTALLATION_ID
    );
    assert_eq!(
        HardwareObservationId::parse(VALID_ID)
            .expect("observation")
            .as_str(),
        VALID_ID
    );
    assert_eq!(
        RuntimeInstallationId::parse(VALID_ID)
            .expect("runtime installation")
            .as_str(),
        VALID_ID
    );
    assert_eq!(
        ModelServiceId::parse(VALID_ID)
            .expect("model service")
            .as_str(),
        VALID_ID
    );
    assert_eq!(
        PlacementGroupId::parse(VALID_ID)
            .expect("placement group")
            .as_str(),
        VALID_ID
    );
    assert_eq!(
        PlacementId::parse(VALID_ID).expect("placement").as_str(),
        VALID_ID
    );
    assert_eq!(
        ResourceLeaseId::parse(VALID_ID)
            .expect("resource lease")
            .as_str(),
        VALID_ID
    );
    assert_eq!(
        OperationId::parse(VALID_ID).expect("operation").as_str(),
        VALID_ID
    );
    assert_eq!(
        CredentialId::parse(VALID_ID).expect("credential").as_str(),
        VALID_ID
    );
    assert_eq!(
        ControllerId::parse(VALID_ID).expect("controller").as_str(),
        VALID_ID
    );
    assert_eq!(
        ApiKeyId::parse(VALID_ID).expect("API key").as_str(),
        VALID_ID
    );
    assert_eq!(
        PairingInviteId::parse(VALID_ID)
            .expect("pairing invitation")
            .as_str(),
        VALID_ID
    );
}

// Rejects non-canonical identity text before it enters any entity snapshot.
#[test]
fn identity_types_reject_ambiguous_values() {
    for value in [
        "",
        "0123456789abcdef0123456789abcde",
        "0123456789abcdef0123456789abcdef0",
        "0123456789ABCDEF0123456789ABCDEF",
        "g123456789abcdef0123456789abcdef",
    ] {
        assert!(NodeId::parse(value).is_err(), "accepted {value:?}");
        assert!(PlacementId::parse(value).is_err(), "accepted {value:?}");
        assert!(CredentialId::parse(value).is_err(), "accepted {value:?}");
        assert!(ControllerId::parse(value).is_err(), "accepted {value:?}");
    }
    assert!(InstallationId::parse(VALID_ID).is_err());
    assert!(InstallationId::parse(&"A".repeat(64)).is_err());
}

// Keeps technical identities canonical while retaining user-facing display names.
#[test]
fn names_preserve_their_distinct_contracts() {
    assert_eq!(
        LogicalModelName::parse("qwen3.8-27b")
            .expect("logical model")
            .as_str(),
        "qwen3.8-27b"
    );
    assert_eq!(
        DisplayName::parse("Living Room Spark")
            .expect("display name")
            .as_str(),
        "Living Room Spark"
    );
    assert!(TechnicalName::parse("Living Room").is_err());
    assert!(DisplayName::parse(" Living Room").is_err());
    assert!(DisplayName::parse("Living\nRoom").is_err());
}

// Validates exact runtime identities without resolving or downloading them.
#[test]
fn runtime_values_require_immutable_canonical_identity() {
    let candidate =
        RuntimeCandidateId::parse("sglang--radixark--qwen3.8--dgx-spark").expect("candidate");
    assert_eq!(candidate.as_str(), "sglang--radixark--qwen3.8--dgx-spark");
    assert!(RuntimeCandidateId::parse("sglang--qwen--dgx-spark").is_err());
    assert!(RuntimeCandidateId::parse("SGLang--owner--model--target").is_err());

    assert_eq!(
        RuntimeVersion::parse("1.2.3-rc.4")
            .expect("version")
            .as_str(),
        "1.2.3-rc.4"
    );
    assert!(RuntimeVersion::parse("1.2").is_err());
    assert!(RuntimeVersion::parse("1.2.3-").is_err());

    let digest = "a".repeat(64);
    assert!(
        RuntimeSource::parse(&format!("ghcr.io/letsinferlabs/runtime@sha256:{digest}")).is_ok()
    );
    assert!(RuntimeSource::parse(&format!("letsinfer-object:sha256:{digest}")).is_ok());
    assert!(RuntimeSource::parse("ghcr.io/letsinferlabs/runtime:latest").is_err());
    assert!(TargetId::parse("dgx-spark").is_ok());
}

// Validates artifact and digest values at the upstream identity boundary.
#[test]
fn artifact_values_require_exact_revisions_and_digests() {
    assert_eq!(
        ArtifactUri::parse("hf://RadixArk/Qwen3.8")
            .expect("artifact URI")
            .as_str(),
        "hf://RadixArk/Qwen3.8"
    );
    assert!(ArtifactUri::parse("https://huggingface.co/owner/model").is_err());
    assert!(ArtifactUri::parse("hf://owner/model/path").is_err());
    assert!(ArtifactRevision::parse(&"a".repeat(40)).is_ok());
    assert!(ArtifactRevision::parse("main").is_err());
    assert!(Sha256Digest::parse(&"b".repeat(64)).is_ok());
    assert!(Sha256Digest::parse(&"B".repeat(64)).is_err());
}

// Preserves opaque task, device, boot, address, and interface identities.
#[test]
fn platform_values_reject_noncanonical_inputs() {
    assert_eq!(TaskId::parse("task-0").expect("task").as_str(), "task-0");
    assert_eq!(TaskId::parse("task-19").expect("task").as_str(), "task-19");
    assert!(TaskId::parse("task-01").is_err());
    assert!(TaskId::parse("rank-0").is_err());
    assert!(DeviceId::parse("GPU-fixture").is_ok());
    assert!(DeviceId::parse(" GPU-fixture").is_err());
    assert!(BootId::parse("boot-fixture-1").is_ok());
    assert!(NodeAddress::parse("homeai.local").is_ok());
    assert!(NodeAddress::parse("home ai.local").is_err());
    assert!(NetworkInterfaceName::parse("enp1s0f0np0").is_ok());
    assert!(NetworkInterfaceName::parse("bad/interface").is_err());
}

// Enforces positive capacities, coherent timestamps, and bounded network ranges.
#[test]
fn numeric_values_enforce_their_shape() {
    assert_eq!(ByteCount::new(128).expect("bytes").value(), 128);
    let error = ByteCount::new(0).expect_err("zero bytes");
    assert_eq!(error.subject(), "byte count");
    assert_eq!(error.reason(), "value must be greater than zero");
    let ports = PortRange::new(9_000, 4).expect("port range");
    assert_eq!(ports.base(), 9_000);
    assert_eq!(ports.last(), 9_003);
    assert!(PortRange::new(80, 1).is_err());
    assert!(PortRange::new(65_535, 2).is_err());
    assert!(NetworkPort::new(1_024).is_ok());
    assert!(NetworkPort::new(443).is_err());

    let timestamps = EntityTimestamps::new(UnixMilliseconds::new(100), UnixMilliseconds::new(101))
        .expect("timestamps");
    assert_eq!(timestamps.updated_at().value(), 101);
    assert!(EntityTimestamps::new(UnixMilliseconds::new(101), UnixMilliseconds::new(100)).is_err());
}

// Keeps endpoint addresses structured instead of accepting an ambiguous URL string.
#[test]
fn endpoint_address_is_structured() {
    let address = EndpointAddress::new(
        EndpointScheme::Https,
        NodeAddress::parse("127.0.0.1").expect("host"),
        8_000,
    )
    .expect("endpoint");
    assert_eq!(address.scheme(), EndpointScheme::Https);
    assert_eq!(address.host().as_str(), "127.0.0.1");
    assert_eq!(address.port(), 8_000);
    assert!(EndpointAddress::new(
        EndpointScheme::Http,
        NodeAddress::parse("localhost").expect("host"),
        0,
    )
    .is_err());
}
