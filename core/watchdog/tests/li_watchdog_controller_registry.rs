// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{Arc, Barrier};
use std::thread;

use li_watchdog_manager::{
    watchdog_crc32, WatchdogControllerAllowlist, WatchdogControllerBinding,
    WatchdogControllerMutationKind, WatchdogControllerRegistry, WatchdogControllerRegistryStore,
    WatchdogProtectedEngine,
};

// Preserves the exact bounded C version-one allowlist grammar and authorization pairing.
#[test]
fn controller_allowlist_preserves_existing_c_semantics() {
    let source = allowlist_source(&[('a', '1'), ('b', '2')]);
    let allowlist = WatchdogControllerAllowlist::parse(source.as_bytes()).unwrap();
    assert_eq!(allowlist.installation_id(), "f".repeat(64));
    assert_eq!(allowlist.controller_count(), 2);
    assert!(allowlist.authorizes(&"a".repeat(32), &"1".repeat(64)));
    assert!(!allowlist.authorizes(&"a".repeat(32), &"2".repeat(64)));
    assert_eq!(
        allowlist.controller_id_for_fingerprint(&"2".repeat(64)),
        Some("b".repeat(32).as_str())
    );

    let with_blank_lines = source.replace("installation_id", "\ninstallation_id");
    assert!(WatchdogControllerAllowlist::parse(with_blank_lines.as_bytes()).is_ok());
}

// Rejects malformed, duplicate, reordered, unbounded, and incomplete allowlists.
#[test]
fn controller_allowlist_rejects_every_failure_class() {
    let valid = allowlist_source(&[('a', '1'), ('b', '2')]);
    let malformed = [
        String::new(),
        valid.trim_end().to_string(),
        valid.replace("version=1\n", ""),
        valid.replace("installation_id=", "unknown="),
        valid.replace("version=1\n", "installation_id=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\nversion=1\n"),
        valid.replace("version=1\n", "version=1\nversion=1\n"),
        valid.replace(&"f".repeat(64), &"F".repeat(64)),
        allowlist_source(&[('a', '1'), ('a', '2')]),
        allowlist_source(&[('a', '1'), ('b', '1')]),
        "version=1\ninstallation_id=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n".to_string(),
    ];
    for source in malformed {
        assert!(WatchdogControllerAllowlist::parse(source.as_bytes()).is_err());
    }
    let mut nul = valid.into_bytes();
    nul[3] = 0;
    assert!(WatchdogControllerAllowlist::parse(&nul).is_err());
    assert!(WatchdogControllerAllowlist::parse(&vec![b'a'; 12_289]).is_err());
}

// Enforces authorization, optimistic revisions, replay, stale, conflict, retirement, and bounds.
#[test]
fn controller_registry_enforces_the_complete_session_lifecycle() {
    let allowlist =
        WatchdogControllerAllowlist::parse(allowlist_source(&[('a', '1'), ('b', '2')]).as_bytes())
            .unwrap();
    let registry = WatchdogControllerRegistry::new(allowlist, 1).unwrap();
    let first = binding('a', '1', 1, 'a', 101);
    let created = registry.apply(first.clone(), 1).unwrap();
    assert_eq!(created.kind(), WatchdogControllerMutationKind::Created);
    assert_eq!(created.revision(), 2);

    let replayed = registry.apply(first.clone(), 2).unwrap();
    assert_eq!(replayed.kind(), WatchdogControllerMutationKind::Replayed);
    assert_eq!(replayed.revision(), 2);
    assert!(registry.apply(first.clone(), 1).is_err());
    assert!(registry.apply(binding('a', '1', 1, 'b', 102), 2).is_err());
    assert!(registry.apply(binding('b', '2', 1, 'c', 103), 2).is_err());
    assert!(registry.apply(binding('b', '1', 1, 'c', 103), 2).is_err());

    let second = binding('a', '1', 2, 'b', 102);
    let advanced = registry.apply(second, 2).unwrap();
    assert_eq!(advanced.kind(), WatchdogControllerMutationKind::Advanced);
    assert_eq!(advanced.revision(), 3);
    assert!(registry.apply(first, 3).is_err());

    let retired = registry.retire(&"a".repeat(32), 2, 3).unwrap();
    assert_eq!(retired.kind(), WatchdogControllerMutationKind::Retired);
    assert_eq!(retired.revision(), 4);
    assert_eq!(
        registry.retire(&"a".repeat(32), 2, 4).unwrap().kind(),
        WatchdogControllerMutationKind::Replayed
    );
    assert!(registry.apply(binding('a', '1', 2, 'b', 102), 4).is_err());
    let resumed = registry.apply(binding('a', '1', 3, 'c', 103), 4).unwrap();
    assert_eq!(resumed.kind(), WatchdogControllerMutationKind::Advanced);
    assert_eq!(registry.active_bindings().unwrap().len(), 1);
}

// Keeps configured active capacity independent from the currently installed allowlist size.
#[test]
fn controller_registry_accepts_growth_capacity_above_initial_authority_count() {
    let allowlist =
        WatchdogControllerAllowlist::parse(allowlist_source(&[('a', '1')]).as_bytes()).unwrap();
    let registry = WatchdogControllerRegistry::new(allowlist, 8).expect("growth capacity");
    assert_eq!(registry.revision().expect("revision"), 1);
}

// Rejects two authorized controllers claiming the same process or protection generation.
#[test]
fn controller_registry_rejects_cross_controller_target_conflicts() {
    let allowlist =
        WatchdogControllerAllowlist::parse(allowlist_source(&[('a', '1'), ('b', '2')]).as_bytes())
            .unwrap();
    let registry = WatchdogControllerRegistry::new(allowlist, 2).unwrap();
    registry.apply(binding('a', '1', 1, 'a', 101), 1).unwrap();
    assert!(registry.apply(binding('b', '2', 1, 'a', 202), 2).is_err());
    assert!(registry.apply(binding('b', '2', 1, 'b', 101), 2).is_err());
    assert_eq!(registry.active_bindings().unwrap().len(), 1);
}

// Reconstructs deterministic active and retired state and rejects corrupted snapshots.
#[test]
fn controller_registry_snapshot_is_deterministic_and_fail_closed() {
    let source = allowlist_source(&[('a', '1'), ('b', '2')]);
    let allowlist = WatchdogControllerAllowlist::parse(source.as_bytes()).unwrap();
    let registry = WatchdogControllerRegistry::new(allowlist.clone(), 2).unwrap();
    registry.apply(binding('b', '2', 4, 'b', 202), 1).unwrap();
    registry.apply(binding('a', '1', 3, 'a', 101), 2).unwrap();
    registry.retire(&"b".repeat(32), 4, 3).unwrap();

    let snapshot = registry.snapshot().unwrap();
    let restored =
        WatchdogControllerRegistry::from_snapshot(allowlist.clone(), 2, &snapshot).unwrap();
    assert_eq!(restored.revision().unwrap(), 4);
    assert_eq!(
        restored.active_bindings().unwrap(),
        registry.active_bindings().unwrap()
    );
    assert_eq!(restored.snapshot().unwrap(), snapshot);
    assert!(restored.apply(binding('b', '2', 4, 'c', 303), 4).is_err());

    let mut corrupted = snapshot.clone();
    corrupted[20] ^= 1;
    assert!(WatchdogControllerRegistry::from_snapshot(allowlist.clone(), 2, &corrupted).is_err());
    assert!(WatchdogControllerRegistry::from_snapshot(
        allowlist.clone(),
        2,
        &snapshot[..snapshot.len() - 1]
    )
    .is_err());
    assert!(WatchdogControllerRegistry::from_snapshot(
        allowlist.clone(),
        2,
        &vec![b'a'; 1_048_577]
    )
    .is_err());

    let other = WatchdogControllerAllowlist::parse(
        source.replace(&"f".repeat(64), &"e".repeat(64)).as_bytes(),
    )
    .unwrap();
    assert!(WatchdogControllerRegistry::from_snapshot(other, 2, &snapshot).is_err());

    let text = String::from_utf8(snapshot).unwrap();
    let body = text.split("checksum=").next().unwrap();
    let unknown = body.replace("revision=4\n", "revision=4\nunknown=value\n");
    let unknown = snapshot_with_checksum(&unknown);
    assert!(WatchdogControllerRegistry::from_snapshot(allowlist.clone(), 2, &unknown).is_err());

    let low_revision = snapshot_with_checksum(&body.replace("revision=4\n", "revision=1\n"));
    assert!(
        WatchdogControllerRegistry::from_snapshot(allowlist.clone(), 2, &low_revision).is_err()
    );
    let mut lines = body.lines().collect::<Vec<_>>();
    lines.swap(4, 5);
    let reordered = snapshot_with_checksum(&format!("{}\n", lines.join("\n")));
    assert!(WatchdogControllerRegistry::from_snapshot(allowlist, 2, &reordered).is_err());
}

// Allows exactly one writer to commit when concurrent callers share one expected revision.
#[test]
fn controller_registry_serializes_concurrent_revision_writers() {
    let allowlist =
        WatchdogControllerAllowlist::parse(allowlist_source(&[('a', '1'), ('b', '2')]).as_bytes())
            .unwrap();
    let registry = Arc::new(WatchdogControllerRegistry::new(allowlist, 2).unwrap());
    let barrier = Arc::new(Barrier::new(3));
    let handles = [('a', '1', 101), ('b', '2', 202)]
        .into_iter()
        .map(|(controller, fingerprint, process_id)| {
            let registry = Arc::clone(&registry);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                registry.apply(
                    binding(controller, fingerprint, 1, controller, process_id),
                    1,
                )
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
    assert_eq!(registry.revision().unwrap(), 2);
    assert_eq!(registry.active_bindings().unwrap().len(), 1);
}

// Retains the exact last-good registry on invalid reload and revokes removed trust atomically.
#[test]
fn controller_registry_store_reloads_without_partial_visibility() {
    let allowlist =
        WatchdogControllerAllowlist::parse(allowlist_source(&[('a', '1'), ('b', '2')]).as_bytes())
            .unwrap();
    let registry = Arc::new(WatchdogControllerRegistry::new(allowlist, 1).unwrap());
    let active = binding('b', '2', 1, 'b', 202);
    registry.apply(active.clone(), 1).unwrap();
    let store = WatchdogControllerRegistryStore::new(registry.clone());
    let (generation, current) = store.current().unwrap();

    let foreign = WatchdogControllerAllowlist::parse(
        allowlist_source(&[('a', '1')])
            .replace(&"f".repeat(64), &"e".repeat(64))
            .as_bytes(),
    )
    .unwrap();
    assert!(store.reload(foreign).is_err());
    let (retained_generation, retained) = store.current().unwrap();
    assert_eq!(retained_generation, generation);
    assert!(Arc::ptr_eq(&retained, &current));
    assert!(retained.is_active(&active).unwrap());

    let replacement =
        WatchdogControllerAllowlist::parse(allowlist_source(&[('a', '1')]).as_bytes()).unwrap();
    assert_eq!(store.reload(replacement).unwrap(), generation + 1);
    let (_, reloaded) = store.current().unwrap();
    assert!(!Arc::ptr_eq(&reloaded, &current));
    assert!(!store.is_current(generation, &current).unwrap());
    assert!(reloaded.active_bindings().unwrap().is_empty());
}

// Creates one exact controller binding for a deterministic fixture identity.
fn binding(
    controller: char,
    fingerprint: char,
    session_generation: u64,
    target_generation: char,
    process_id: u32,
) -> WatchdogControllerBinding {
    WatchdogControllerBinding::new(
        &controller.to_string().repeat(32),
        &fingerprint.to_string().repeat(64),
        session_generation,
        protected_target(target_generation, process_id),
    )
    .unwrap()
}

// Creates one exact active version-one protected-process descriptor.
fn protected_target(generation: char, process_id: u32) -> WatchdogProtectedEngine {
    let value = format!(
        "version=1\ngeneration={}\nphase=armed\ncontainer_name=container-{generation}\ncontainer_id={}\npid={process_id}\nstart_ticks={}\nboot_id=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\ncgroup=/sys/fs/cgroup/letsinfer/{process_id}\n",
        generation.to_string().repeat(32),
        generation.to_string().repeat(64),
        u64::from(process_id) * 10,
    );
    WatchdogProtectedEngine::parse(&value).unwrap()
}

// Creates one canonical version-one allowlist with stable installation identity.
fn allowlist_source(controllers: &[(char, char)]) -> String {
    let mut source = format!("version=1\ninstallation_id={}\n", "f".repeat(64));
    for (controller, fingerprint) in controllers {
        source.push_str(&format!(
            "controller={},{}\n",
            controller.to_string().repeat(32),
            fingerprint.to_string().repeat(64)
        ));
    }
    source
}

// Adds the canonical checksum line to one complete snapshot body.
fn snapshot_with_checksum(body: &str) -> Vec<u8> {
    format!("{body}checksum={:08x}\n", watchdog_crc32(body.as_bytes())).into_bytes()
}
