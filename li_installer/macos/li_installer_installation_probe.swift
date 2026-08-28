// SPDX-License-Identifier: AGPL-3.0-only

import Foundation
import Metal


// Represents one bounded failure at the native provider boundary.
struct ProbeError: Error, CustomStringConvertible {
    let description: String
}


// Stores the explicit dependency arguments supplied by the composition root.
struct ProbeArguments {
    private let values: [String: String]
    let dependencies: [String: String]
    let installableDependencies: Set<String>

    // Parses exact name/value pairs and rejects unknown or duplicate arguments.
    init(_ arguments: ArraySlice<String>) throws {
        let allowed = Set([
            "date-command",
            "dependency",
            "installable-dependency",
            "metal-observation-file",
            "metal-observation-source",
            "missing-dependencies",
            "mode",
            "platform",
            "schema-file",
            "service-manager-provider",
            "service-manager-scope",
            "service-manager-user-domain-available",
            "service-persistence-available",
            "service-persistence-mechanism",
            "status",
            "sw-vers-command",
            "sysctl-command",
            "system-profiler-command",
            "uname-command",
        ])
        let repeated = Set(["dependency", "installable-dependency"])
        var parsed: [String: String] = [:]
        var parsedDependencies: [String: String] = [:]
        var parsedInstallableDependencies = Set<String>()
        var index = arguments.startIndex
        while index < arguments.endIndex {
            let rawName = arguments[index]
            guard rawName.hasPrefix("--") else {
                throw ProbeError(description: "argument name is invalid: \(rawName)")
            }
            let name = String(rawName.dropFirst(2))
            guard allowed.contains(name) else {
                throw ProbeError(description: "unknown argument: \(rawName)")
            }
            guard repeated.contains(name) || parsed[name] == nil else {
                throw ProbeError(description: "duplicate argument: \(rawName)")
            }
            index = arguments.index(after: index)
            guard index < arguments.endIndex else {
                throw ProbeError(description: "argument requires a value: \(rawName)")
            }
            let value = arguments[index]
            if name == "dependency" {
                let fields = value.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
                guard fields.count == 2, !fields[0].isEmpty else {
                    throw ProbeError(description: "dependency argument is invalid")
                }
                let dependencyName = String(fields[0])
                guard parsedDependencies[dependencyName] == nil else {
                    throw ProbeError(description: "duplicate dependency: \(dependencyName)")
                }
                parsedDependencies[dependencyName] = String(fields[1])
            } else if name == "installable-dependency" {
                guard !value.isEmpty else {
                    throw ProbeError(description: "installable dependency name is empty")
                }
                guard parsedInstallableDependencies.insert(value).inserted else {
                    throw ProbeError(description: "duplicate installable dependency: \(value)")
                }
            } else {
                parsed[name] = value
            }
            index = arguments.index(after: index)
        }
        for name in parsedInstallableDependencies where parsedDependencies[name] == nil {
            throw ProbeError(description: "installable dependency is unavailable: \(name)")
        }
        values = parsed
        dependencies = parsedDependencies
        installableDependencies = parsedInstallableDependencies
    }

    // Returns one required argument value without inventing a fallback.
    func required(_ name: String) throws -> String {
        guard let value = values[name], !value.isEmpty else {
            throw ProbeError(description: "required argument is missing: --\(name)")
        }
        return value
    }

    // Returns one explicitly supplied optional argument value.
    func optional(_ name: String) -> String? {
        guard let value = values[name], !value.isEmpty else { return nil }
        return value
    }
}


// Parses one required boolean argument without accepting alternate spellings.
func requiredBoolean(_ arguments: ProbeArguments, _ name: String) throws -> Bool {
    switch try arguments.required(name) {
    case "true": return true
    case "false": return false
    default: throw ProbeError(description: "boolean argument is invalid: --\(name)")
    }
}


// Defines the bounded native Metal observation used by live and fixture probes.
struct MetalObservation: Codable {
    let deviceName: String
    let registryID: UInt64
    let appleFamily: String?
    let commonFamily: String?
    let macFamily: String?
    let metalFamily: String?
}


// Returns an executable path only when the injected command is usable.
func executablePath(_ value: String) throws -> String {
    guard value.hasPrefix("/") else {
        throw ProbeError(description: "command path must be absolute: \(value)")
    }
    guard FileManager.default.isExecutableFile(atPath: value) else {
        throw ProbeError(description: "command is not executable: \(value)")
    }
    return value
}


// Runs one injected native command without a shell and returns bounded output.
func runCommand(_ command: String, _ arguments: [String] = []) throws -> String {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: try executablePath(command))
    process.arguments = arguments
    let output = Pipe()
    let error = Pipe()
    process.standardOutput = output
    process.standardError = error
    try process.run()
    process.waitUntilExit()
    let outputData = output.fileHandleForReading.readDataToEndOfFile()
    let errorData = error.fileHandleForReading.readDataToEndOfFile()
    guard process.terminationStatus == 0 else {
        let detail = String(data: errorData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
        throw ProbeError(description: "command failed: \(command): \(detail ?? "unknown error")")
    }
    guard outputData.count <= 4 * 1024 * 1024,
          errorData.count <= 4 * 1024 * 1024 else {
        throw ProbeError(description: "command output is invalid: \(command)")
    }
    let primaryData = outputData.isEmpty ? errorData : outputData
    guard let primaryValue = String(data: primaryData, encoding: .utf8) else {
        throw ProbeError(description: "command output is not UTF-8: \(command)")
    }
    return primaryValue.trimmingCharacters(in: .whitespacesAndNewlines)
}


// Reads one injected bounded JSON document.
func readJSONFile(_ path: String) throws -> [String: Any] {
    let data = try Data(contentsOf: URL(fileURLWithPath: path))
    guard data.count > 0, data.count <= 1024 * 1024,
          let value = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw ProbeError(description: "JSON document is invalid: \(path)")
    }
    return value
}


// Loads the schema identity used to construct the installation probe.
func schemaIdentity(_ path: String) throws -> [String: Any] {
    let schema = try readJSONFile(path)
    guard let definitions = schema["$defs"] as? [String: Any],
          let identity = definitions["schemaIdentity"] as? [String: Any],
          let properties = identity["properties"] as? [String: Any],
          let nameProperty = properties["name"] as? [String: Any],
          let versionProperty = properties["version"] as? [String: Any],
          let name = nameProperty["const"] as? String,
          let version = versionProperty["const"] as? Int,
          name == "letsinfer.installer.installation-probe",
          version == 1 else {
        throw ProbeError(description: "installation-probe schema identity is invalid")
    }
    return ["name": name, "version": version]
}


// Returns the first stable line produced by one optional version command.
func firstVersionLine(_ command: String, _ arguments: [String]) -> String {
    guard !command.isEmpty,
          let output = try? runCommand(command, arguments),
          let firstLine = output.split(separator: "\n").first else {
        return ""
    }
    return String(firstLine)
}


// Returns one dependency version through its injected executable contract.
func dependencyVersion(
    name: String,
    path: String,
    dependencies: [String: String]
) -> String {
    switch name {
    case "brew", "curl", "tar":
        return firstVersionLine(path, ["--version"])
    case "openssl":
        return firstVersionLine(path, ["version"])
    case "python":
        return firstVersionLine(path, ["--version"])
    case "ssh":
        return firstVersionLine(path, ["-V"])
    case "ssh_keygen":
        return firstVersionLine(dependencies["ssh"] ?? "", ["-V"])
    case "sudo":
        return firstVersionLine(path, ["-V"])
    default:
        return ""
    }
}


// Builds structured version/path records for every injected CLI dependency.
func dependencyObservations(_ arguments: ProbeArguments) -> [String: Any] {
    var observations: [String: Any] = [:]
    for (name, path) in arguments.dependencies {
        observations[name] = [
            "version": dependencyVersion(
                name: name,
                path: path,
                dependencies: arguments.dependencies
            ),
            "path": path,
            "installable": arguments.installableDependencies.contains(name)
        ]
    }
    return observations
}


// Builds the exact macOS user-service readiness observation.
func serviceManagerObservation(_ arguments: ProbeArguments) throws -> [String: Any] {
    let provider = try arguments.required("service-manager-provider")
    let scope = try arguments.required("service-manager-scope")
    let mechanism = try arguments.required("service-persistence-mechanism")
    guard provider == "launchd", scope == "gui", mechanism == "launch-agent" else {
        throw ProbeError(description: "macOS service-manager identity is invalid")
    }
    return [
        "provider": provider,
        "scope": scope,
        "user_domain_available": try requiredBoolean(
            arguments,
            "service-manager-user-domain-available"
        ),
        "persistence": [
            "mechanism": mechanism,
            "available": try requiredBoolean(arguments, "service-persistence-available")
        ]
    ]
}


// Returns stable errors for dependency and service-manager readiness gaps.
func installationErrors(_ arguments: ProbeArguments) throws -> [String] {
    var errors = arguments.optional("missing-dependencies")?
        .split(separator: ",")
        .map { "missing dependency: \($0)" } ?? []
    if try !requiredBoolean(arguments, "service-manager-user-domain-available") {
        errors.append(
            "service manager user domain is unavailable: \(try arguments.required("service-manager-provider"))"
        )
    }
    if try !requiredBoolean(arguments, "service-persistence-available") {
        errors.append(
            "service persistence is unavailable: \(try arguments.required("service-persistence-mechanism"))"
        )
    }
    return errors
}


// Converts one optional string into an explicit JSON value.
func jsonValue(_ value: String?) -> Any {
    if let value { return value }
    return NSNull()
}


// Converts one optional integer into an explicit JSON value.
func jsonValue(_ value: Int?) -> Any {
    if let value { return value }
    return NSNull()
}


// Parses one required positive integer without fabricating a default.
func positiveInteger(_ value: String, name: String) throws -> Int {
    guard let parsed = Int(value), parsed > 0 else {
        throw ProbeError(description: "\(name) is not a positive integer")
    }
    return parsed
}


// Parses one required positive 64-bit integer without fabricating a default.
func positiveInteger64(_ value: String, name: String) throws -> Int64 {
    guard let parsed = Int64(value), parsed > 0 else {
        throw ProbeError(description: "\(name) is not a positive integer")
    }
    return parsed
}


// Returns the highest Apple GPU family supported by the selected Metal device.
func highestAppleFamily(for device: MTLDevice) -> String? {
    if #available(macOS 14.0, *), device.supportsFamily(.apple9) { return "apple9" }
    if #available(macOS 13.0, *), device.supportsFamily(.apple8) { return "apple8" }
    if device.supportsFamily(.apple7) { return "apple7" }
    if device.supportsFamily(.apple6) { return "apple6" }
    if device.supportsFamily(.apple5) { return "apple5" }
    if device.supportsFamily(.apple4) { return "apple4" }
    if device.supportsFamily(.apple3) { return "apple3" }
    if device.supportsFamily(.apple2) { return "apple2" }
    if device.supportsFamily(.apple1) { return "apple1" }
    return nil
}


// Returns the highest common GPU family supported by the selected Metal device.
func highestCommonFamily(for device: MTLDevice) -> String? {
    if device.supportsFamily(.common3) { return "common3" }
    if device.supportsFamily(.common2) { return "common2" }
    if device.supportsFamily(.common1) { return "common1" }
    return nil
}


// Returns the highest macOS GPU family supported by the selected Metal device.
func highestMacFamily(for device: MTLDevice) -> String? {
    if device.supportsFamily(.mac2) { return "mac2" }
    return nil
}


// Returns the highest Metal feature family supported by the selected device.
func highestMetalFamily(for device: MTLDevice) -> String? {
    // Keeps macOS 14 release builders source-compatible with the macOS 26 family.
    if #available(macOS 26.0, *),
       let metal4 = MTLGPUFamily(rawValue: 5002),
       device.supportsFamily(metal4) { return "metal4" }
    if #available(macOS 13.0, *), device.supportsFamily(.metal3) { return "metal3" }
    return nil
}


// Collects the default Metal device through the native live adapter.
func liveMetalObservation() throws -> MetalObservation {
    guard let device = MTLCreateSystemDefaultDevice() else {
        throw ProbeError(description: "the default Metal device is unavailable")
    }
    return MetalObservation(
        deviceName: device.name,
        registryID: device.registryID,
        appleFamily: highestAppleFamily(for: device),
        commonFamily: highestCommonFamily(for: device),
        macFamily: highestMacFamily(for: device),
        metalFamily: highestMetalFamily(for: device)
    )
}


// Loads a deterministic Metal observation through the injected fixture adapter.
func fixtureMetalObservation(_ path: String) throws -> MetalObservation {
    let data = try Data(contentsOf: URL(fileURLWithPath: path))
    return try JSONDecoder().decode(MetalObservation.self, from: data)
}


// Selects the explicit native or fixture Metal observation construct.
func metalObservation(_ arguments: ProbeArguments) throws -> MetalObservation {
    switch try arguments.required("metal-observation-source") {
    case "native":
        guard arguments.optional("metal-observation-file") == nil else {
            throw ProbeError(description: "native Metal observation cannot use a fixture file")
        }
        return try liveMetalObservation()
    case "fixture":
        return try fixtureMetalObservation(try arguments.required("metal-observation-file"))
    default:
        throw ProbeError(description: "Metal observation source is invalid")
    }
}


// Returns the normalized GPU vendor represented by system_profiler output.
func normalizedVendor(_ value: String?) -> String {
    guard let value else { return "unknown" }
    if value.hasPrefix("Apple") { return "apple" }
    if value.hasPrefix("AMD") { return "amd" }
    if value.hasPrefix("Intel") { return "intel" }
    return "unknown"
}


// Parses injected system_profiler output into typed accelerator observations.
func acceleratorObservations(_ arguments: ProbeArguments, metal: MetalObservation) throws -> [[String: Any]] {
    let output = try runCommand(
        try arguments.required("system-profiler-command"),
        ["SPDisplaysDataType"]
    )
    var records: [[String: String]] = []
    var current: [String: String]?
    let labels = [
        "Chipset Model": "name",
        "Vendor": "vendor_name",
        "Total Number of Cores": "gpu_core_count",
        "Metal Support": "metal_support",
        "Bus": "bus"
    ]
    for line in output.split(separator: "\n") {
        let fields = line.trimmingCharacters(in: .whitespaces).split(separator: ":", maxSplits: 1).map(String.init)
        guard fields.count == 2, let field = labels[fields[0]] else { continue }
        if fields[0] == "Chipset Model" {
            if let current { records.append(current) }
            current = ["name": fields[1].trimmingCharacters(in: .whitespaces)]
        } else {
            current?[field] = fields[1].trimmingCharacters(in: .whitespaces)
        }
    }
    if let current { records.append(current) }

    let architecture = try arguments.required("platform").hasSuffix("-arm64") ? "arm64" : "x86_64"
    return records.enumerated().map { index, record in
        let isDefaultDevice = record["name"] == metal.deviceName
        let cores = record["gpu_core_count"].flatMap(Int.init)
        return [
            "index": index,
            "vendor": normalizedVendor(record["vendor_name"]),
            "vendor_name": jsonValue(record["vendor_name"]),
            "name": record["name"] ?? "Unknown GPU",
            "uuid": NSNull(),
            "pci_address": NSNull(),
            "driver": ["version": NSNull(), "source": "macos"],
            "compute": [
                "api": "metal",
                "version": jsonValue(
                    isDefaultDevice ? metal.metalFamily : record["metal_support"]
                ),
                "capability": NSNull(),
                "architecture": NSNull(),
                "family": jsonValue(isDefaultDevice ? metal.appleFamily : nil)
            ],
            "memory": [
                "topology": architecture == "arm64" ? "unified" : "unknown",
                "framebuffer_bytes": NSNull(),
                "addressing_mode": NSNull()
            ],
            "partitioning": ["mig_mode": NSNull()],
            "gpu_core_count": jsonValue(cores),
            "bus": jsonValue(record["bus"])
        ]
    }
}


// Returns one exact value through the injected sysctl command.
func sysctlValue(_ arguments: ProbeArguments, _ name: String) throws -> String {
    let value = try runCommand(try arguments.required("sysctl-command"), ["-n", name])
    guard !value.isEmpty else {
        throw ProbeError(description: "sysctl value is empty: \(name)")
    }
    return value
}


// Constructs the complete single-document macOS installation probe.
func installationProbe(_ arguments: ProbeArguments) throws -> [String: Any] {
    let platform = try arguments.required("platform")
    guard platform == "macos-arm64" || platform == "macos-x86_64" else {
        throw ProbeError(description: "macOS platform identity is invalid: \(platform)")
    }
    let metal = try metalObservation(arguments)
    let observedAtUnix = try positiveInteger(
        try runCommand(try arguments.required("date-command"), ["+%s"]),
        name: "observation timestamp"
    )
    let logicalCPUCount = try positiveInteger(
        try sysctlValue(arguments, "hw.logicalcpu"),
        name: "logical CPU count"
    )
    let memoryBytes = try positiveInteger64(
        try sysctlValue(arguments, "hw.memsize"),
        name: "host memory"
    )
    let hardware: [String: Any] = [
        "provider": ["id": "macos", "mode": try arguments.required("mode")],
        "observation": [
            "observed_at_unix": observedAtUnix,
            "boot_id": try sysctlValue(arguments, "kern.bootsessionuuid")
        ],
        "operating_system": [
            "distribution": "macos",
            "version": try runCommand(try arguments.required("sw-vers-command"), ["-productVersion"]),
            "build": try runCommand(try arguments.required("sw-vers-command"), ["-buildVersion"]),
            "kernel_version": try runCommand(try arguments.required("uname-command"), ["-r"])
        ],
        "host": [
            "hardware_model": try sysctlValue(arguments, "hw.model"),
            "cpu_model": try sysctlValue(arguments, "machdep.cpu.brand_string"),
            "logical_cpu_count": logicalCPUCount,
            "memory_bytes": memoryBytes,
            "memory_source": "sysctl"
        ],
        "accelerators": try acceleratorObservations(arguments, metal: metal),
        "software": [
            "docker_version": NSNull(),
            "nvidia_container_toolkit_version": NSNull(),
            "nvidia_cuda_max_version": NSNull()
        ],
        "topology": ["mutable_links_observed": false]
    ]
    return [
        "schema": try schemaIdentity(try arguments.required("schema-file")),
        "status": try arguments.required("status"),
        "platform": [
            "os": "macos",
            "architecture": String(platform.split(separator: "-").last ?? ""),
            "identifier": platform
        ],
        "service_manager": try serviceManagerObservation(arguments),
        "dependencies": dependencyObservations(arguments),
        "hardware": hardware,
        "errors": try installationErrors(arguments)
    ]
}


// Parses dependencies, collects facts, and emits exactly one JSON document.
func main() throws {
    let arguments = try ProbeArguments(CommandLine.arguments.dropFirst())
    let document = try installationProbe(arguments)
    guard JSONSerialization.isValidJSONObject(document) else {
        throw ProbeError(description: "installation-probe document is not valid JSON")
    }
    let data = try JSONSerialization.data(withJSONObject: document, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data([0x0A]))
    FileHandle.standardError.write(Data("letsinfer.event=platform_probe_complete\n".utf8))
}


do {
    try main()
} catch {
    FileHandle.standardError.write(Data("installation probe: \(error)\n".utf8))
    exit(1)
}
