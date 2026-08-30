// SPDX-License-Identifier: AGPL-3.0-only

use li_benchmark_worker::{materialize_native_benchmark, BenchmarkWorkerError};
use serde_json::{json, Value};

// Returns one complete active schema-8 contract fixture.
fn contract() -> Value {
    let request = json!({
        "output_tokens": 128,
        "min_completion_tokens": 1,
        "require_natural_stop": false,
        "temperature": 0,
        "seed": 42042
    });
    json!({
        "schema_version": 8,
        "suite": "letsinfer-code-prose-v1",
        "generator": {"id": "letsinfer-code-prose", "version": 8},
        "domains": ["code"],
        "execution": {
            "isolation": "fresh-context",
            "prefix_state": "shared",
            "samples_per_cell": 1,
            "stream_prefix": "shared-body"
        },
        "tokenizer": {
            "capability": "engine-rendered-chat-count-v1",
            "model_sha256": "1".repeat(64),
            "engine_payload_sha256": "2".repeat(64),
            "render_contract": "openai-chat-user-v1"
        },
        "request": request,
        "short": {
            "domains": ["code", "prose"],
            "prompt_tokens": 256,
            "concurrencies": [1, 2, 4],
            "request": {
                "output_tokens": 32,
                "min_completion_tokens": 1,
                "require_natural_stop": false,
                "temperature": 0,
                "seed": 42042
            }
        },
        "ttft_cache": {
            "prompt_tokens": 64000,
            "prompt_domain": "code",
            "repetitions": 2,
            "request": {
                "output_tokens": 1,
                "min_completion_tokens": 1,
                "require_natural_stop": false,
                "temperature": 0,
                "seed": 42042
            }
        },
        "sample_interval_seconds": 1,
        "cases": [{"id": "32k", "prompt_tokens": 32768, "concurrencies": [1, 2]}]
    })
}

// Encodes one contract in the same compact newline-terminated form retained by RuntimeManager.
fn bytes(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).expect("contract JSON");
    bytes.push(b'\n');
    bytes
}

// Returns a deterministic positive exact-token mock without inspecting model semantics.
fn byte_counter(value: &str) -> Result<u64, BenchmarkWorkerError> {
    u64::try_from(value.len()).map_err(|_| BenchmarkWorkerError::invalid("fixture too large"))
}

// Matches the Python schema-8 oracle for short, shared-prefix, and TTFT prompt bytes.
#[test]
fn native_materializer_matches_schema_8_oracle_fixtures() {
    let selection = [
        "short-code-c1",
        "short-prose-c1",
        "ttftcold-code-c1",
        "ttftwarm-code-c1",
        "32k-code-c2",
    ]
    .map(str::to_string);
    let materialized =
        materialize_native_benchmark(&bytes(&contract()), &selection, &mut byte_counter)
            .expect("materialization");
    assert_eq!(
        materialized
            .cells()
            .iter()
            .map(|cell| cell.name())
            .collect::<Vec<_>>(),
        [
            "short-code-c1",
            "short-prose-c1",
            "32k-code-c2",
            "ttftcold-code-c1",
            "ttftwarm-code-c1",
        ]
    );
    let short_code = &materialized.cells()[0].fixtures()[0];
    assert_eq!(
        short_code.sha256(),
        "0c96c9e83b7fe0c3eb09f0b8d0c35972c1331c40f4e4145e8b7dfbcdf6fddd81"
    );
    assert_eq!(short_code.content().len(), 192);
    let short_prose = &materialized.cells()[1].fixtures()[0];
    assert_eq!(
        short_prose.sha256(),
        "73dd5a37ba04e55186ebc7affdda4319aa2a66e71f2625b9d93a6755927bb11a"
    );
    assert_eq!(short_prose.content().len(), 240);
    let streams = materialized.cells()[2].fixtures();
    assert_eq!(
        streams[0].sha256(),
        "c0398fdd7e2373765a4402b9461b6c9a2aa16ee1c507a0ff8c4294b27f03950b"
    );
    assert_eq!(
        streams[1].sha256(),
        "7e897c3ea841b1df114e6f020380f6926330fb4e97bfef4e7d2098011bfeb310"
    );
    let cold = &materialized.cells()[3].fixtures()[0];
    let warm = &materialized.cells()[4].fixtures()[0];
    assert_eq!(
        cold.sha256(),
        "75362555dc3212a7164e4d0982d02788ecba551cf6a2abe3b058e0835d2dda1e"
    );
    assert_eq!(cold.content(), warm.content());
    assert!(materialized
        .prompt_set_sha256()
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
}

// Keeps exact token-count observations attached to each distinct canonical prompt.
#[test]
fn native_materializer_uses_injected_engine_token_count_for_every_fixture() {
    let mut observed = Vec::new();
    let mut counter = |value: &str| {
        observed.push(value.len());
        Ok(10_000 + observed.len() as u64)
    };
    let selection = ["32k-code-c2".to_string()];
    let materialized = materialize_native_benchmark(&bytes(&contract()), &selection, &mut counter)
        .expect("materialization");
    assert_eq!(observed.len(), 2);
    assert_eq!(
        materialized.cells()[0]
            .fixtures()
            .iter()
            .map(|fixture| fixture.prompt_tokens())
            .collect::<Vec<_>>(),
        [10_001, 10_002]
    );
}

// Rejects unknown, duplicate, and empty exact cell selections before token counting.
#[test]
fn native_materializer_rejects_cell_selection_drift() {
    for selection in [
        vec!["missing-code-c1".to_string()],
        vec!["32k-code-c1".to_string(), "32k-code-c1".to_string()],
    ] {
        let mut calls = 0;
        let mut counter = |_value: &str| {
            calls += 1;
            Ok(1)
        };
        assert!(
            materialize_native_benchmark(&bytes(&contract()), &selection, &mut counter).is_err()
        );
        assert_eq!(calls, 0);
    }
}

// Rejects every meaningful schema-8 drift class independently in native Rust.
#[test]
fn native_materializer_rejects_contract_mutation_matrix() {
    let mutations: [fn(&mut Value); 12] = [
        |value| value["schema_version"] = json!(7),
        |value| value["suite"] = json!("other"),
        |value| value["generator"]["version"] = json!(7),
        |value| value["domains"] = json!(["prose", "code"]),
        |value| value["execution"]["stream_prefix"] = json!("private"),
        |value| value["tokenizer"]["model_sha256"] = json!("bad"),
        |value| value["request"]["output_tokens"] = json!(0),
        |value| value["short"]["concurrencies"] = json!([1]),
        |value| value["ttft_cache"]["prompt_tokens"] = json!(1),
        |value| value["sample_interval_seconds"] = json!(0),
        |value| value["cases"][0]["concurrencies"] = json!([2, 1]),
        |value| value["unknown"] = json!(true),
    ];
    for mutate in mutations {
        let mut value = contract();
        mutate(&mut value);
        let mut calls = 0;
        let mut counter = |_value: &str| {
            calls += 1;
            Ok(1)
        };
        assert!(materialize_native_benchmark(&bytes(&value), &[], &mut counter).is_err());
        assert_eq!(calls, 0);
    }
}
