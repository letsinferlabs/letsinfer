// SPDX-License-Identifier: AGPL-3.0-only

use regex::Regex;
use serde_json::{Map, Value};
use std::collections::BTreeSet;

// Validates the structural keywords used by the installation-probe JSON Schema.
pub struct JsonSchemaValidator<'a> {
    root: &'a Value,
}

impl<'a> JsonSchemaValidator<'a> {
    // Creates a validator bound to one exact schema document.
    pub fn new(root: &'a Value) -> Self {
        Self { root }
    }

    // Returns every structural validation error for one candidate document.
    pub fn validate(&self, value: &Value) -> Vec<String> {
        let mut errors = Vec::new();
        self.validate_schema(self.root, value, "$", &mut errors);
        errors
    }

    // Applies one schema node recursively without mutating the candidate value.
    fn validate_schema(&self, schema: &Value, value: &Value, path: &str, errors: &mut Vec<String>) {
        let Some(schema_object) = schema.as_object() else {
            errors.push(format!("{}: schema node is not an object", path));
            return;
        };

        if let Some(reference) = schema_object.get("$ref").and_then(Value::as_str) {
            match self.resolve_reference(reference) {
                Ok(resolved) => self.validate_schema(resolved, value, path, errors),
                Err(error) => errors.push(format!("{}: {}", path, error)),
            }
        }

        if let Some(branches) = schema_object.get("oneOf").and_then(Value::as_array) {
            let matches = branches
                .iter()
                .filter(|branch| {
                    let mut branch_errors = Vec::new();
                    self.validate_schema(branch, value, path, &mut branch_errors);
                    branch_errors.is_empty()
                })
                .count();
            if matches != 1 {
                errors.push(format!(
                    "{}: expected exactly one oneOf branch, matched {}",
                    path, matches
                ));
            }
        }

        if let Some(expected) = schema_object.get("const") {
            if value != expected {
                errors.push(format!("{}: value does not equal const", path));
            }
        }
        if let Some(options) = schema_object.get("enum").and_then(Value::as_array) {
            if !options.contains(value) {
                errors.push(format!("{}: value is not in enum", path));
            }
        }
        if let Some(declared_type) = schema_object.get("type") {
            if !valid_type(value, declared_type) {
                errors.push(format!("{}: invalid type", path));
                return;
            }
        }

        if let Some(object) = value.as_object() {
            self.validate_object(schema_object, object, path, errors);
        }
        if let Some(array) = value.as_array() {
            self.validate_array(schema_object, array, path, errors);
        }
        if let Some(string) = value.as_str() {
            self.validate_string(schema_object, string, path, errors);
        }
        if value.is_number() {
            self.validate_number(schema_object, value, path, errors);
        }
    }

    // Applies object properties, required fields, and closed-shape enforcement.
    fn validate_object(
        &self,
        schema: &Map<String, Value>,
        value: &Map<String, Value>,
        path: &str,
        errors: &mut Vec<String>,
    ) {
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for name in required.iter().filter_map(Value::as_str) {
                if !value.contains_key(name) {
                    errors.push(format!("{}: missing required property {}", path, name));
                }
            }
        }

        let properties = schema.get("properties").and_then(Value::as_object);
        for (name, child) in value {
            if let Some(child_schema) = properties.and_then(|items| items.get(name)) {
                self.validate_schema(child_schema, child, &format!("{}.{}", path, name), errors);
            } else if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
                errors.push(format!("{}: unknown property {}", path, name));
            }
        }
    }

    // Applies item validation and bounded array length.
    fn validate_array(
        &self,
        schema: &Map<String, Value>,
        value: &[Value],
        path: &str,
        errors: &mut Vec<String>,
    ) {
        if let Some(maximum) = schema.get("maxItems").and_then(Value::as_u64) {
            if value.len() as u64 > maximum {
                errors.push(format!("{}: too many items", path));
            }
        }
        let Some(item_schema) = schema.get("items") else {
            return;
        };
        for (index, child) in value.iter().enumerate() {
            self.validate_schema(item_schema, child, &format!("{}[{}]", path, index), errors);
        }
    }

    // Applies string length and regular-expression constraints.
    fn validate_string(
        &self,
        schema: &Map<String, Value>,
        value: &str,
        path: &str,
        errors: &mut Vec<String>,
    ) {
        if let Some(minimum) = schema.get("minLength").and_then(Value::as_u64) {
            if (value.chars().count() as u64) < minimum {
                errors.push(format!("{}: string is too short", path));
            }
        }
        let Some(pattern) = schema.get("pattern").and_then(Value::as_str) else {
            return;
        };
        match Regex::new(pattern) {
            Ok(expression) if !expression.is_match(value) => {
                errors.push(format!("{}: string does not match pattern", path));
            }
            Err(error) => errors.push(format!("{}: schema pattern is invalid: {}", path, error)),
            _ => {}
        }
    }

    // Applies numeric minimum constraints.
    fn validate_number(
        &self,
        schema: &Map<String, Value>,
        value: &Value,
        path: &str,
        errors: &mut Vec<String>,
    ) {
        let Some(minimum) = schema.get("minimum").and_then(Value::as_f64) else {
            return;
        };
        if value.as_f64().is_some_and(|number| number < minimum) {
            errors.push(format!("{}: number is below minimum", path));
        }
    }

    // Resolves one local JSON Pointer reference against the exact schema root.
    fn resolve_reference(&self, reference: &str) -> Result<&Value, String> {
        let pointer = reference
            .strip_prefix('#')
            .filter(|value| value.starts_with('/'))
            .ok_or_else(|| "only local schema references are supported".to_string())?;
        self.root
            .pointer(pointer)
            .ok_or_else(|| format!("schema reference is unavailable: {}", reference))
    }
}

// Validates cross-field safety rules that JSON Schema cannot express clearly.
pub struct InstallationProbeSemanticValidator;

impl InstallationProbeSemanticValidator {
    // Returns every semantic validation error for one structurally valid document.
    pub fn validate(document: &Value) -> Vec<String> {
        let mut errors = Vec::new();
        validate_platform(document, &mut errors);
        validate_service_manager(document, &mut errors);
        validate_status(document, &mut errors);
        validate_hardware(document, &mut errors);
        errors
    }
}

// Returns whether one value satisfies any declared JSON Schema type.
fn valid_type(value: &Value, declared: &Value) -> bool {
    let types: Vec<&str> = match declared {
        Value::String(value) => vec![value.as_str()],
        Value::Array(values) => values.iter().filter_map(Value::as_str).collect(),
        _ => return false,
    };
    types.into_iter().any(|declared_type| match declared_type {
        "array" => value.is_array(),
        "boolean" => value.is_boolean(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "null" => value.is_null(),
        "number" => value.is_number(),
        "object" => value.is_object(),
        "string" => value.is_string(),
        _ => false,
    })
}

// Requires the platform identifier to equal its operating-system and architecture pair.
fn validate_platform(document: &Value, errors: &mut Vec<String>) {
    let Some(platform) = document.get("platform").and_then(Value::as_object) else {
        return;
    };
    let Some(operating_system) = platform.get("os").and_then(Value::as_str) else {
        return;
    };
    let Some(architecture) = platform.get("architecture").and_then(Value::as_str) else {
        return;
    };
    let expected = format!("{}-{}", operating_system, architecture);
    if platform.get("identifier").and_then(Value::as_str) != Some(expected.as_str()) {
        errors.push(format!("$.platform.identifier: expected {}", expected));
    }
}

// Requires service-manager identity and readiness to agree with the platform.
fn validate_service_manager(document: &Value, errors: &mut Vec<String>) {
    let Some(service_manager) = document.get("service_manager").and_then(Value::as_object) else {
        return;
    };
    let platform = document.pointer("/platform/os").and_then(Value::as_str);
    let provider = service_manager.get("provider").and_then(Value::as_str);
    let scope = service_manager.get("scope").and_then(Value::as_str);
    let persistence = service_manager
        .get("persistence")
        .and_then(Value::as_object);
    let mechanism = persistence
        .and_then(|value| value.get("mechanism"))
        .and_then(Value::as_str);
    let valid_identity = match platform {
        Some("linux") => {
            provider == Some("systemd")
                && scope == Some("user")
                && mechanism == Some("systemd-linger")
        }
        Some("macos") => {
            provider == Some("launchd") && scope == Some("gui") && mechanism == Some("launch-agent")
        }
        _ => false,
    };
    if !valid_identity {
        errors.push("$.service_manager: identity does not match platform".to_string());
    }

    let document_errors = document
        .get("errors")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let user_domain_available = service_manager
        .get("user_domain_available")
        .and_then(Value::as_bool);
    let persistence_available = persistence
        .and_then(|value| value.get("available"))
        .and_then(Value::as_bool);
    let user_domain_error = format!(
        "service manager user domain is unavailable: {}",
        provider.unwrap_or("")
    );
    let persistence_error = format!(
        "service persistence is unavailable: {}",
        mechanism.unwrap_or("")
    );
    validate_readiness_error(
        user_domain_available,
        &user_domain_error,
        &document_errors,
        "$.service_manager.user_domain_available",
        errors,
    );
    validate_readiness_error(
        persistence_available,
        &persistence_error,
        &document_errors,
        "$.service_manager.persistence.available",
        errors,
    );
}

// Requires one readiness boolean and its stable error to agree.
fn validate_readiness_error(
    available: Option<bool>,
    expected_error: &str,
    document_errors: &[Value],
    path: &str,
    errors: &mut Vec<String>,
) {
    let carries_error = document_errors
        .iter()
        .any(|value| value.as_str() == Some(expected_error));
    match (available, carries_error) {
        (Some(false), false) => errors.push(format!("{}: unavailable state has no error", path)),
        (Some(true), true) => errors.push(format!("{}: available state has an error", path)),
        _ => {}
    }
}

// Requires readiness, dependencies, and errors to describe one consistent state.
fn validate_status(document: &Value, errors: &mut Vec<String>) {
    let status = document.get("status").and_then(Value::as_str);
    let document_errors = document
        .get("errors")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if status == Some("ready") {
        if !document_errors.is_empty() {
            errors.push("$.errors: ready document has errors".to_string());
        }
        if document.get("hardware").is_none_or(Value::is_null) {
            errors.push("$.hardware: ready document has no hardware".to_string());
        }
    } else if status == Some("missing_dependencies") {
        if document_errors.is_empty() {
            errors.push("$.status: missing dependencies have no errors".to_string());
        }
    } else if status == Some("service_manager_unavailable") {
        let user_domain_available = document
            .pointer("/service_manager/user_domain_available")
            .and_then(Value::as_bool);
        let persistence_available = document
            .pointer("/service_manager/persistence/available")
            .and_then(Value::as_bool);
        if document_errors.is_empty() {
            errors.push("$.status: unavailable service manager has no errors".to_string());
        }
        if user_domain_available == Some(true) && persistence_available == Some(true) {
            errors.push("$.status: service manager is available".to_string());
        }
    }
}

// Requires provider, accelerator, compute, and memory facts to agree.
fn validate_hardware(document: &Value, errors: &mut Vec<String>) {
    let Some(hardware) = document.get("hardware").and_then(Value::as_object) else {
        return;
    };
    let platform_operating_system = document.pointer("/platform/os").and_then(Value::as_str);
    let provider = hardware
        .get("provider")
        .and_then(Value::as_object)
        .and_then(|value| value.get("id"))
        .and_then(Value::as_str);
    if provider != platform_operating_system {
        errors.push("$.hardware.provider.id: does not match platform".to_string());
    }

    let Some(accelerators) = hardware.get("accelerators").and_then(Value::as_array) else {
        return;
    };
    let indices: Vec<u64> = accelerators
        .iter()
        .filter_map(|accelerator| accelerator.get("index").and_then(Value::as_u64))
        .collect();
    if indices.iter().collect::<BTreeSet<_>>().len() != indices.len() {
        errors.push("$.hardware.accelerators: duplicate indices".to_string());
    }
    let uuids: Vec<&str> = accelerators
        .iter()
        .filter_map(|accelerator| accelerator.get("uuid").and_then(Value::as_str))
        .collect();
    if uuids.iter().collect::<BTreeSet<_>>().len() != uuids.len() {
        errors.push("$.hardware.accelerators: duplicate UUIDs".to_string());
    }

    for (index, accelerator) in accelerators.iter().enumerate() {
        validate_compute(accelerator, index, errors);
        validate_memory(accelerator, index, errors);
    }
}

// Requires NVIDIA SM and Apple family identities to match their capability systems.
fn validate_compute(accelerator: &Value, index: usize, errors: &mut Vec<String>) {
    let path = format!("$.hardware.accelerators[{}].compute", index);
    let vendor = accelerator.get("vendor").and_then(Value::as_str);
    let Some(compute) = accelerator.get("compute").and_then(Value::as_object) else {
        return;
    };
    match vendor {
        Some("nvidia") => {
            let capability = compute.get("capability").and_then(Value::as_str);
            let expected_architecture = capability.and_then(|value| {
                let expression = Regex::new(r"^([0-9]+)\.([0-9]+)$").ok()?;
                let captures = expression.captures(value)?;
                Some(format!("sm_{}{}", &captures[1], &captures[2]))
            });
            if compute.get("api").and_then(Value::as_str) != Some("cuda") {
                errors.push(format!("{}.api: NVIDIA requires CUDA", path));
            }
            if compute.get("architecture").and_then(Value::as_str)
                != expected_architecture.as_deref()
            {
                errors.push(format!(
                    "{}.architecture: does not match compute capability",
                    path
                ));
            }
            if !compute.get("family").is_none_or(Value::is_null) {
                errors.push(format!(
                    "{}.family: NVIDIA must not claim an Apple family",
                    path
                ));
            }
        }
        Some("apple") => {
            if compute.get("api").and_then(Value::as_str) != Some("metal") {
                errors.push(format!("{}.api: Apple requires Metal", path));
            }
            if !compute.get("architecture").is_none_or(Value::is_null) {
                errors.push(format!("{}.architecture: Apple has no SM identity", path));
            }
            let valid_family = compute
                .get("family")
                .and_then(Value::as_str)
                .is_some_and(|value| {
                    Regex::new(r"^apple[1-9][0-9]*$")
                        .is_ok_and(|expression| expression.is_match(value))
                });
            if !valid_family {
                errors.push(format!("{}.family: Apple family is missing", path));
            }
        }
        _ => {}
    }
}

// Requires physical memory classification to agree with raw accelerator observations.
fn validate_memory(accelerator: &Value, index: usize, errors: &mut Vec<String>) {
    let path = format!("$.hardware.accelerators[{}].memory", index);
    let vendor = accelerator.get("vendor").and_then(Value::as_str);
    let Some(memory) = accelerator.get("memory").and_then(Value::as_object) else {
        return;
    };
    match memory.get("topology").and_then(Value::as_str) {
        Some("unified") if vendor == Some("nvidia") => {
            if memory.get("addressing_mode").and_then(Value::as_str) != Some("ATS") {
                errors.push(format!("{}: NVIDIA unified memory requires ATS", path));
            }
            if !memory.get("framebuffer_bytes").is_none_or(Value::is_null) {
                errors.push(format!(
                    "{}: unified memory cannot expose framebuffer bytes",
                    path
                ));
            }
        }
        Some("discrete") => {
            let valid_framebuffer = memory
                .get("framebuffer_bytes")
                .and_then(Value::as_u64)
                .is_some_and(|value| value > 0);
            if !valid_framebuffer {
                errors.push(format!(
                    "{}: discrete memory requires positive framebuffer bytes",
                    path
                ));
            }
        }
        _ => {}
    }
}

// Returns structural and semantic errors for one installation probe.
pub fn validate_installation_probe(schema: &Value, document: &Value) -> Vec<String> {
    let mut errors = JsonSchemaValidator::new(schema).validate(document);
    if errors.is_empty() {
        errors.extend(InstallationProbeSemanticValidator::validate(document));
    }
    errors
}
