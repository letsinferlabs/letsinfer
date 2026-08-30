// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::{INSTALLATION_PROBE_SCHEMA_NAME, INSTALLATION_PROBE_SCHEMA_VERSION};

// Represents the bounded JSON values emitted by the dependency-free probe.
enum JsonValue {
    Null,
    Bool(bool),
    Number(u64),
    String(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

impl JsonValue {
    // Renders one JSON value with stable key ordering and indentation.
    fn render(&self, depth: usize) -> String {
        match self {
            JsonValue::Null => "null".to_string(),
            JsonValue::Bool(value) => value.to_string(),
            JsonValue::Number(value) => value.to_string(),
            JsonValue::String(value) => format!("\"{}\"", json_escape(value)),
            JsonValue::Array(values) => {
                if values.is_empty() {
                    return "[]".to_string();
                }
                let indentation = "  ".repeat(depth + 1);
                let closing = "  ".repeat(depth);
                let rows = values
                    .iter()
                    .map(|value| format!("{}{}", indentation, value.render(depth + 1)))
                    .collect::<Vec<_>>()
                    .join(",\n");
                format!("[\n{}\n{}]", rows, closing)
            }
            JsonValue::Object(values) => {
                if values.is_empty() {
                    return "{}".to_string();
                }
                let indentation = "  ".repeat(depth + 1);
                let closing = "  ".repeat(depth);
                let rows = values
                    .iter()
                    .map(|(name, value)| {
                        format!(
                            "{}\"{}\": {}",
                            indentation,
                            json_escape(name),
                            value.render(depth + 1)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(",\n");
                format!("{{\n{}\n{}}}", rows, closing)
            }
        }
    }
}

// Stores the explicit dependency arguments supplied by the composition root.
struct ProbeArguments {
    values: BTreeMap<String, String>,
    dependencies: BTreeMap<String, String>,
    installable_dependencies: BTreeSet<String>,
}

impl ProbeArguments {
    // Parses exact name/value pairs and rejects unknown or duplicate arguments.
    fn parse(arguments: &[String]) -> Result<Self, String> {
        let allowed = BTreeSet::from([
            "boot-id-file",
            "cpuinfo-file",
            "date-command",
            "dependency",
            "docker-command",
            "getconf-command",
            "installable-dependency",
            "lscpu-command",
            "meminfo-file",
            "missing-dependencies",
            "mode",
            "nvidia-ctk-command",
            "nvidia-smi-command",
            "os-release-file",
            "platform",
            "schema-file",
            "service-manager-provider",
            "service-manager-scope",
            "service-manager-user-domain-available",
            "service-persistence-available",
            "service-persistence-mechanism",
            "status",
            "uname-command",
        ]);
        let repeated = BTreeSet::from(["dependency", "installable-dependency"]);
        let mut values = BTreeMap::new();
        let mut dependencies = BTreeMap::new();
        let mut installable_dependencies = BTreeSet::new();
        let mut index = 0;
        while index < arguments.len() {
            let raw_name = &arguments[index];
            let name = raw_name
                .strip_prefix("--")
                .ok_or_else(|| format!("argument name is invalid: {}", raw_name))?;
            if !allowed.contains(name) {
                return Err(format!("unknown argument: {}", raw_name));
            }
            if !repeated.contains(name) && values.contains_key(name) {
                return Err(format!("duplicate argument: {}", raw_name));
            }
            index += 1;
            if index >= arguments.len() {
                return Err(format!("argument requires a value: {}", raw_name));
            }
            let value = &arguments[index];
            if name == "dependency" {
                let (dependency_name, dependency_path) = value
                    .split_once('=')
                    .ok_or_else(|| "dependency argument is invalid".to_string())?;
                if dependency_name.is_empty() {
                    return Err("dependency name is empty".to_string());
                }
                if dependencies
                    .insert(dependency_name.to_string(), dependency_path.to_string())
                    .is_some()
                {
                    return Err(format!("duplicate dependency: {}", dependency_name));
                }
            } else if name == "installable-dependency" {
                if value.is_empty() {
                    return Err("installable dependency name is empty".to_string());
                }
                if !installable_dependencies.insert(value.clone()) {
                    return Err(format!("duplicate installable dependency: {}", value));
                }
            } else {
                values.insert(name.to_string(), value.clone());
            }
            index += 1;
        }
        for name in &installable_dependencies {
            if !dependencies.contains_key(name) {
                return Err(format!("installable dependency is unavailable: {}", name));
            }
        }
        Ok(Self {
            values,
            dependencies,
            installable_dependencies,
        })
    }

    // Returns one required argument value without inventing a fallback.
    fn required(&self, name: &str) -> Result<&str, String> {
        self.values
            .get(name)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("required argument is missing: --{}", name))
    }

    // Returns one explicitly supplied optional argument value.
    fn optional(&self, name: &str) -> Option<&str> {
        self.values
            .get(name)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    }
}

// Parses one required boolean argument without accepting alternate spellings.
fn required_boolean_argument(arguments: &ProbeArguments, name: &str) -> Result<bool, String> {
    match arguments.required(name)? {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("boolean argument is invalid: --{}", name)),
    }
}

// Escapes one string according to the JSON string contract.
fn json_escape(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => {
                output.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => output.push(character),
        }
    }
    output
}

// Builds one stably ordered JSON object from explicit fields.
fn object(fields: Vec<(&str, JsonValue)>) -> JsonValue {
    JsonValue::Object(
        fields
            .into_iter()
            .map(|(name, value)| (name.to_string(), value))
            .collect(),
    )
}

// Converts one optional string into its explicit JSON representation.
fn nullable_string(value: Option<&str>) -> JsonValue {
    match value {
        Some(value) if !value.is_empty() => JsonValue::String(value.to_string()),
        _ => JsonValue::Null,
    }
}

// Reads one injected bounded text file.
fn read_text_file(path: &str) -> Result<String, String> {
    let metadata =
        fs::metadata(path).map_err(|error| format!("cannot inspect {}: {}", path, error))?;
    if !metadata.is_file() {
        return Err(format!("input path is not a regular file: {}", path));
    }
    let value =
        fs::read_to_string(path).map_err(|error| format!("cannot read {}: {}", path, error))?;
    if value.is_empty() || value.len() > 1024 * 1024 {
        return Err(format!("input file content is not bounded: {}", path));
    }
    Ok(value)
}

// Runs one injected native command without a shell and returns bounded output.
fn run_command(command: &str, arguments: &[&str]) -> Result<String, String> {
    if !Path::new(command).is_absolute() {
        return Err(format!("command path must be absolute: {}", command));
    }
    let output = Command::new(command)
        .args(arguments)
        .output()
        .map_err(|error| format!("command could not run: {}: {}", command, error))?;
    if !output.status.success() {
        return Err(format!(
            "command failed: {}: {}",
            command,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    if output.stdout.len() > 4 * 1024 * 1024 || output.stderr.len() > 4 * 1024 * 1024 {
        return Err(format!("command output is too large: {}", command));
    }
    let primary = if output.stdout.is_empty() {
        output.stderr
    } else {
        output.stdout
    };
    String::from_utf8(primary)
        .map(|value| value.trim().to_string())
        .map_err(|_| format!("command output is not UTF-8: {}", command))
}

// Loads the installation-probe identity from the injected schema document.
fn schema_identity(path: &str) -> Result<JsonValue, String> {
    let schema = read_text_file(path)?;
    if !schema.contains(&format!(
        "\"const\": \"{}\"",
        INSTALLATION_PROBE_SCHEMA_NAME
    )) || !schema.contains(&format!("\"const\": {}", INSTALLATION_PROBE_SCHEMA_VERSION))
    {
        return Err("installation-probe schema identity is invalid".to_string());
    }
    Ok(object(vec![
        (
            "name",
            JsonValue::String(INSTALLATION_PROBE_SCHEMA_NAME.to_string()),
        ),
        (
            "version",
            JsonValue::Number(INSTALLATION_PROBE_SCHEMA_VERSION),
        ),
    ]))
}

// Returns the first stable line produced by one optional version command.
fn first_version_line(command: &str, arguments: &[&str]) -> String {
    if command.is_empty() {
        return String::new();
    }
    run_command(command, arguments)
        .ok()
        .and_then(|value| value.lines().next().map(str::to_string))
        .unwrap_or_default()
}

// Returns one dependency version through its injected executable contract.
fn dependency_version(name: &str, path: &str, dependencies: &BTreeMap<String, String>) -> String {
    match name {
        "apt_get" | "brew" | "curl" | "dnf" | "docker" | "gh" | "install" | "loginctl"
        | "openssl" | "pacman" | "sg" | "stat" | "sudo" | "systemctl" | "systemd_run" | "tar"
        | "zypper" => {
            let arguments: &[&str] = match name {
                "docker" => &["--version"],
                "openssl" => &["version"],
                "sudo" => &["-V"],
                _ => &["--version"],
            };
            first_version_line(path, arguments)
        }
        "ssh" => first_version_line(path, &["-V"]),
        "ssh_keygen" => first_version_line(
            dependencies.get("ssh").map(String::as_str).unwrap_or(""),
            &["-V"],
        ),
        "nvidia_ctk" => first_version_line(path, &["--version"]),
        "nvidia_smi" => first_version_line(
            path,
            &[
                "--query-gpu=driver_version",
                "--format=csv,noheader,nounits",
            ],
        ),
        "avahi_browse" | "avahi_publish_service" => first_version_line(path, &["--version"]),
        _ => String::new(),
    }
}

// Builds structured version/path records for every injected CLI dependency.
fn dependency_observations(arguments: &ProbeArguments) -> JsonValue {
    JsonValue::Object(
        arguments
            .dependencies
            .iter()
            .map(|(name, path)| {
                (
                    name.clone(),
                    object(vec![
                        (
                            "version",
                            JsonValue::String(dependency_version(
                                name,
                                path,
                                &arguments.dependencies,
                            )),
                        ),
                        ("path", JsonValue::String(path.clone())),
                        (
                            "installable",
                            JsonValue::Bool(arguments.installable_dependencies.contains(name)),
                        ),
                    ]),
                )
            })
            .collect(),
    )
}

// Builds the exact Linux user-service readiness observation.
fn service_manager_observation(arguments: &ProbeArguments) -> Result<JsonValue, String> {
    let provider = arguments.required("service-manager-provider")?;
    let scope = arguments.required("service-manager-scope")?;
    let mechanism = arguments.required("service-persistence-mechanism")?;
    if provider != "systemd" || scope != "user" || mechanism != "systemd-linger" {
        return Err("Linux service-manager identity is invalid".to_string());
    }
    Ok(object(vec![
        ("provider", JsonValue::String(provider.to_string())),
        ("scope", JsonValue::String(scope.to_string())),
        (
            "user_domain_available",
            JsonValue::Bool(required_boolean_argument(
                arguments,
                "service-manager-user-domain-available",
            )?),
        ),
        (
            "persistence",
            object(vec![
                ("mechanism", JsonValue::String(mechanism.to_string())),
                (
                    "available",
                    JsonValue::Bool(required_boolean_argument(
                        arguments,
                        "service-persistence-available",
                    )?),
                ),
            ]),
        ),
    ]))
}

// Returns stable errors for dependency and service-manager readiness gaps.
fn installation_errors(arguments: &ProbeArguments) -> Result<JsonValue, String> {
    let mut values = arguments
        .optional("missing-dependencies")
        .unwrap_or("")
        .split(',')
        .filter(|value| !value.is_empty())
        .map(|value| JsonValue::String(format!("missing dependency: {}", value)))
        .collect::<Vec<_>>();
    if !required_boolean_argument(arguments, "service-manager-user-domain-available")? {
        values.push(JsonValue::String(format!(
            "service manager user domain is unavailable: {}",
            arguments.required("service-manager-provider")?
        )));
    }
    if !required_boolean_argument(arguments, "service-persistence-available")? {
        values.push(JsonValue::String(format!(
            "service persistence is unavailable: {}",
            arguments.required("service-persistence-mechanism")?
        )));
    }
    Ok(JsonValue::Array(values))
}

// Returns one exact value from an injected operating-system release document.
fn operating_system_release_value(document: &str, wanted_key: &str) -> Result<String, String> {
    for line in document.lines() {
        let Some((key, raw_value)) = line.split_once('=') else {
            continue;
        };
        if key != wanted_key {
            continue;
        }
        let value = raw_value.trim();
        let unquoted = if value.len() >= 2
            && ((value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\'')))
        {
            &value[1..value.len() - 1]
        } else {
            value
        };
        if unquoted.is_empty() {
            return Err(format!(
                "operating-system release value is empty: {}",
                wanted_key
            ));
        }
        return Ok(unquoted.to_string());
    }
    Err(format!(
        "operating-system release value is missing: {}",
        wanted_key
    ))
}

// Returns total host memory from an injected Linux meminfo document.
fn linux_memory_bytes(document: &str) -> Result<u64, String> {
    for line in document.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() == 3 && fields[0] == "MemTotal:" && fields[2] == "kB" {
            let kibibytes = fields[1]
                .parse::<u64>()
                .map_err(|_| "Linux memory total is invalid".to_string())?;
            return kibibytes
                .checked_mul(1024)
                .filter(|value| *value > 0)
                .ok_or_else(|| "Linux memory total is invalid".to_string());
        }
    }
    Err("Linux memory total is missing".to_string())
}

// Returns the first CPU model from an injected Linux cpuinfo document.
fn cpu_model_from_cpuinfo(document: &str) -> Result<String, String> {
    for line in document.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if ["model name", "Hardware"].contains(&key.trim()) && !value.trim().is_empty() {
            return Ok(value.trim().to_string());
        }
    }
    Err("Linux CPU model is missing".to_string())
}

// Returns the CPU model through the injected lscpu adapter or cpuinfo fallback.
fn linux_cpu_model(arguments: &ProbeArguments, cpuinfo: &str) -> Result<String, String> {
    if let Some(command) = arguments.optional("lscpu-command") {
        let output = run_command(command, &[])?;
        for line in output.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            if key.trim() == "Model name" && !value.trim().is_empty() {
                return Ok(value.trim().to_string());
            }
        }
    }
    cpu_model_from_cpuinfo(cpuinfo)
}

// Converts one NVIDIA unavailable sentinel into an explicit optional value.
fn nvidia_optional(value: &str) -> Option<&str> {
    let normalized = value.trim();
    if ["", "N/A", "[N/A]", "Not Supported"].contains(&normalized) {
        None
    } else {
        Some(normalized)
    }
}

// Returns the maximum CUDA version advertised in an nvidia-smi summary.
fn nvidia_cuda_version(summary: &str) -> Option<String> {
    let marker = "CUDA Version:";
    let start = summary.find(marker)? + marker.len();
    summary[start..]
        .trim_start()
        .split(|character: char| character.is_whitespace() || character == '|')
        .next()
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

// Converts an NVIDIA compute capability into its canonical SM architecture.
fn nvidia_sm_architecture(capability: Option<&str>) -> Result<Option<String>, String> {
    let Some(capability) = capability else {
        return Ok(None);
    };
    let Some((major, minor)) = capability.split_once('.') else {
        return Err("NVIDIA compute capability is invalid".to_string());
    };
    if major.chars().all(|value| value.is_ascii_digit())
        && minor.chars().all(|value| value.is_ascii_digit())
    {
        Ok(Some(format!("sm_{}{}", major, minor)))
    } else {
        Err("NVIDIA compute capability is invalid".to_string())
    }
}

// Parses one NVIDIA accelerator observation into the canonical JSON shape.
fn nvidia_accelerators(arguments: &ProbeArguments) -> Result<(JsonValue, Option<String>), String> {
    let Some(command) = arguments.optional("nvidia-smi-command") else {
        return Ok((JsonValue::Array(Vec::new()), None));
    };
    let fields = "index,uuid,name,pci.bus_id,driver_version,memory.total,compute_cap,mig.mode.current,addressing_mode";
    let query = format!("--query-gpu={}", fields);
    let output = match run_command(command, &[&query, "--format=csv,noheader,nounits"]) {
        Ok(output) => output,
        Err(_) => return Ok((JsonValue::Array(Vec::new()), None)),
    };
    let cuda_version = run_command(command, &[])
        .ok()
        .and_then(|summary| nvidia_cuda_version(&summary));
    let mut accelerators = Vec::new();
    for line in output.lines() {
        let values: Vec<&str> = line.split(',').map(str::trim).collect();
        if values.len() != 9 {
            return Err("NVIDIA accelerator row has an invalid shape".to_string());
        }
        let index = values[0]
            .parse::<u64>()
            .map_err(|_| "NVIDIA accelerator index is invalid".to_string())?;
        let framebuffer = nvidia_optional(values[5]);
        let addressing = nvidia_optional(values[8]);
        let (memory_topology, framebuffer_bytes) = match framebuffer {
            Some(value) => {
                let bytes = value
                    .parse::<u64>()
                    .map_err(|_| "NVIDIA framebuffer memory is invalid".to_string())?
                    .checked_mul(1024 * 1024)
                    .ok_or_else(|| "NVIDIA framebuffer memory is invalid".to_string())?;
                ("discrete", JsonValue::Number(bytes))
            }
            None if addressing == Some("ATS") => ("unified", JsonValue::Null),
            None => ("unknown", JsonValue::Null),
        };
        let compute_capability = nvidia_optional(values[6]);
        let sm_architecture = nvidia_sm_architecture(compute_capability)?;
        accelerators.push(object(vec![
            ("index", JsonValue::Number(index)),
            ("vendor", JsonValue::String("nvidia".to_string())),
            ("vendor_name", JsonValue::String("NVIDIA".to_string())),
            ("name", JsonValue::String(values[2].to_string())),
            ("uuid", nullable_string(nvidia_optional(values[1]))),
            ("pci_address", nullable_string(nvidia_optional(values[3]))),
            (
                "driver",
                object(vec![
                    ("version", nullable_string(nvidia_optional(values[4]))),
                    ("source", JsonValue::String("nvidia-smi".to_string())),
                ]),
            ),
            (
                "compute",
                object(vec![
                    ("api", JsonValue::String("cuda".to_string())),
                    ("version", nullable_string(cuda_version.as_deref())),
                    ("capability", nullable_string(compute_capability)),
                    ("architecture", nullable_string(sm_architecture.as_deref())),
                    ("family", JsonValue::Null),
                ]),
            ),
            (
                "memory",
                object(vec![
                    ("topology", JsonValue::String(memory_topology.to_string())),
                    ("framebuffer_bytes", framebuffer_bytes),
                    ("addressing_mode", nullable_string(addressing)),
                ]),
            ),
            (
                "partitioning",
                object(vec![(
                    "mig_mode",
                    nullable_string(nvidia_optional(values[7])),
                )]),
            ),
            ("gpu_core_count", JsonValue::Null),
            ("bus", JsonValue::Null),
        ]));
    }
    Ok((JsonValue::Array(accelerators), cuda_version))
}

// Returns the Docker client version through its injected optional adapter.
fn docker_version(arguments: &ProbeArguments) -> Result<Option<String>, String> {
    match arguments.optional("docker-command") {
        Some(command) => {
            run_command(command, &["version", "--format", "{{.Client.Version}}"]).map(Some)
        }
        None => Ok(None),
    }
}

// Returns the NVIDIA container-toolkit version through its injected adapter.
fn nvidia_toolkit_version(arguments: &ProbeArguments) -> Result<Option<String>, String> {
    match arguments.optional("nvidia-ctk-command") {
        Some(command) => run_command(command, &["--version"])
            .map(|value| value.lines().next().map(str::to_string)),
        None => Ok(None),
    }
}

// Constructs the complete single-document Linux installation probe.
fn installation_probe(arguments: &ProbeArguments) -> Result<JsonValue, String> {
    let platform = arguments.required("platform")?;
    if !["linux-arm64", "linux-x86_64"].contains(&platform) {
        return Err(format!("Linux platform identity is invalid: {}", platform));
    }
    let architecture = platform
        .split('-')
        .next_back()
        .ok_or_else(|| "Linux architecture is unavailable".to_string())?;
    let os_release = read_text_file(arguments.required("os-release-file")?)?;
    let meminfo = read_text_file(arguments.required("meminfo-file")?)?;
    let cpuinfo = read_text_file(arguments.required("cpuinfo-file")?)?;
    let boot_id = read_text_file(arguments.required("boot-id-file")?)?
        .trim()
        .to_string();
    let logical_cpu_count = run_command(
        arguments.required("getconf-command")?,
        &["_NPROCESSORS_ONLN"],
    )?
    .parse::<u64>()
    .map_err(|_| "Linux logical CPU count is invalid".to_string())?;
    let timestamp = run_command(arguments.required("date-command")?, &["+%s"])?
        .parse::<u64>()
        .map_err(|_| "observation timestamp is invalid".to_string())?;
    let (accelerators, cuda_version) = nvidia_accelerators(arguments)?;
    let dependencies = dependency_observations(arguments);
    let hardware = object(vec![
        (
            "provider",
            object(vec![
                ("id", JsonValue::String("linux".to_string())),
                (
                    "mode",
                    JsonValue::String(arguments.required("mode")?.to_string()),
                ),
            ]),
        ),
        (
            "observation",
            object(vec![
                ("observed_at_unix", JsonValue::Number(timestamp)),
                ("boot_id", JsonValue::String(boot_id)),
            ]),
        ),
        (
            "operating_system",
            object(vec![
                (
                    "distribution",
                    JsonValue::String(operating_system_release_value(&os_release, "ID")?),
                ),
                (
                    "version",
                    JsonValue::String(operating_system_release_value(&os_release, "VERSION_ID")?),
                ),
                ("build", JsonValue::Null),
                (
                    "kernel_version",
                    JsonValue::String(run_command(arguments.required("uname-command")?, &["-r"])?),
                ),
            ]),
        ),
        (
            "host",
            object(vec![
                ("hardware_model", JsonValue::Null),
                (
                    "cpu_model",
                    JsonValue::String(linux_cpu_model(arguments, &cpuinfo)?),
                ),
                ("logical_cpu_count", JsonValue::Number(logical_cpu_count)),
                (
                    "memory_bytes",
                    JsonValue::Number(linux_memory_bytes(&meminfo)?),
                ),
                (
                    "memory_source",
                    JsonValue::String("proc-meminfo".to_string()),
                ),
            ]),
        ),
        ("accelerators", accelerators),
        (
            "software",
            object(vec![
                (
                    "docker_version",
                    nullable_string(docker_version(arguments)?.as_deref()),
                ),
                (
                    "nvidia_container_toolkit_version",
                    nullable_string(nvidia_toolkit_version(arguments)?.as_deref()),
                ),
                (
                    "nvidia_cuda_max_version",
                    nullable_string(cuda_version.as_deref()),
                ),
            ]),
        ),
        (
            "topology",
            object(vec![("mutable_links_observed", JsonValue::Bool(false))]),
        ),
    ]);
    Ok(object(vec![
        (
            "schema",
            schema_identity(arguments.required("schema-file")?)?,
        ),
        (
            "status",
            JsonValue::String(arguments.required("status")?.to_string()),
        ),
        (
            "platform",
            object(vec![
                ("os", JsonValue::String("linux".to_string())),
                ("architecture", JsonValue::String(architecture.to_string())),
                ("identifier", JsonValue::String(platform.to_string())),
            ]),
        ),
        ("service_manager", service_manager_observation(arguments)?),
        ("dependencies", dependencies),
        ("hardware", hardware),
        ("errors", installation_errors(arguments)?),
    ]))
}

// Collects one Linux observation from the composition root's explicit arguments.
pub fn observe(arguments: &[String]) -> Result<String, String> {
    let arguments = ProbeArguments::parse(arguments)?;
    Ok(installation_probe(&arguments)?.render(0))
}
