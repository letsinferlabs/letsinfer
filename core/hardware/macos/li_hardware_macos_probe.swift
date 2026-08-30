// SPDX-License-Identifier: AGPL-3.0-only

import Foundation
import Metal

// Describes one stable native Metal observation failure.
enum LIHardwareProbeError: Error {
    case noDevices
    case unsupportedAppleFamily
}

// Returns text safe for the tab-separated provider contract.
func normalizedField(_ value: String) -> String {
    value
        .replacingOccurrences(of: "\t", with: " ")
        .replacingOccurrences(of: "\n", with: " ")
        .trimmingCharacters(in: .whitespacesAndNewlines)
}

// Returns the highest Apple GPU family reported by one Metal device.
func appleFamily(_ device: MTLDevice) throws -> String {
    for index in (1...16).reversed() {
        guard let family = MTLGPUFamily(rawValue: 1000 + index) else {
            continue
        }
        if device.supportsFamily(family) {
            return "apple\(index)"
        }
    }
    throw LIHardwareProbeError.unsupportedAppleFamily
}

// Returns the highest Metal generation available on the active operating system.
func metalVersion() -> String {
    if #available(macOS 26.0, *) {
        return "metal4"
    }
    if #available(macOS 13.0, *) {
        return "metal3"
    }
    return "metal2"
}

// Emits one stable tab-separated row for every physical Metal device.
func run() throws {
    let devices = MTLCopyAllDevices()
    guard !devices.isEmpty else {
        throw LIHardwareProbeError.noDevices
    }
    for device in devices.sorted(by: { $0.registryID < $1.registryID }) {
        let identifier = String(format: "APPLE-%016llx", device.registryID)
        print([
            identifier,
            normalizedField(device.name),
            try appleFamily(device),
            metalVersion(),
        ].joined(separator: "\t"))
    }
}

do {
    try run()
} catch {
    FileHandle.standardError.write(Data("hardware probe failed\n".utf8))
    exit(1)
}
