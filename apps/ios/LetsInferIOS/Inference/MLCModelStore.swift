import CryptoKit
import Foundation

@MainActor
final class MLCModelStore: ObservableObject {
    enum State: Equatable {
        case missing
        case downloading(Double)
        case verifying
        case ready(URL)
        case failed(String)
    }

    static let repository = "mlc-ai/Qwen3-0.6B-q4f16_1-MLC"
    static let revision = "8c14ce481d4c692769976ad52afea453a102df19"
    static let expectedFileCount = 18
    static let expectedSnapshotBytes: Int64 = 351_517_143
    @Published private(set) var state: State = .missing

    private struct TreeEntry: Decodable {
        struct LFS: Decodable { let oid: String; let size: Int64? }
        let type: String
        let path: String
        let size: Int64?
        let lfs: LFS?
    }

    private struct Receipt: Decodable {
        struct File: Decodable {
            let path: String
            let bytes: Int64
            let sha256: String?
        }
        let schema_version: Int
        let repository: String
        let revision: String
        let files: [File]
    }

    init() { refresh() }

    var modelURL: URL? {
        if case .ready(let url) = state { return url }
        return nil
    }

    func refresh() {
        guard let data = try? Data(contentsOf: receiptURL),
              let receipt = try? JSONDecoder().decode(Receipt.self, from: data),
              receipt.schema_version == 1,
              receipt.repository == Self.repository,
              receipt.revision == Self.revision,
              receipt.files.count == Self.expectedFileCount,
              receipt.files.allSatisfy({ $0.bytes >= 0 }),
              receipt.files.reduce(Int64(0), { $0 + $1.bytes })
                == Self.expectedSnapshotBytes
        else {
            state = .missing
            return
        }
        state = .ready(destinationURL)
    }

    func verifiedModelURL() async throws -> URL {
        guard modelURL != nil else {
            throw NodeError.inference("The exact MLC model snapshot is not installed")
        }
        state = .verifying
        let destination = destinationURL
        let receipt = receiptURL
        do {
            try await Task.detached(priority: .utility) {
                try Self.verifySnapshot(destination: destination, receiptURL: receipt)
            }.value
            state = .ready(destination)
            return destination
        } catch {
            state = .failed(error.localizedDescription)
            throw error
        }
    }

    func download() async throws -> URL {
        if let modelURL { return modelURL }
        do {
            state = .downloading(0)
            let entries = try await tree()
            let files = entries.filter { $0.type == "file" }
            guard files.count == Self.expectedFileCount,
                  files.allSatisfy({ $0.size != nil }),
                  files.compactMap(\.size).reduce(0, +) == Self.expectedSnapshotBytes
            else {
                throw NodeError.inference("MLC model snapshot file inventory is invalid")
            }
            let manager = FileManager.default
            let staging = destinationURL.deletingLastPathComponent()
                .appending(path: ".\(Self.revision).incoming-\(UUID().uuidString)")
            try manager.createDirectory(at: staging, withIntermediateDirectories: true)
            do {
                for (index, entry) in files.enumerated() {
                    guard let expectedSize = entry.size, expectedSize >= 0 else {
                        throw NodeError.invalidData("MLC model file size is unavailable")
                    }
                    let relative = try Self.safeRelativePath(entry.path)
                    let target = relative.reduce(staging) { $0.appending(path: $1) }
                    try manager.createDirectory(
                        at: target.deletingLastPathComponent(),
                        withIntermediateDirectories: true
                    )
                    let encoded = relative.map {
                        $0.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? $0
                    }.joined(separator: "/")
                    guard let url = URL(string:
                        "https://huggingface.co/\(Self.repository)/resolve/\(Self.revision)/\(encoded)?download=true"
                    ) else {
                        throw NodeError.invalidData("MLC model download URL is invalid")
                    }
                    let (temporary, response) = try await URLSession.shared.download(from: url)
                    guard let http = response as? HTTPURLResponse,
                          http.statusCode == 200,
                          Int64((try temporary.resourceValues(forKeys: [.fileSizeKey])).fileSize ?? -1)
                            == expectedSize
                    else {
                        throw NodeError.inference("MLC model file size differs")
                    }
                    if let oid = entry.lfs?.oid.removingPrefix("sha256:") {
                        guard try Self.sha256(of: temporary) == oid else {
                            throw NodeError.inference("MLC model file SHA-256 differs")
                        }
                    }
                    try manager.moveItem(at: temporary, to: target)
                    state = .downloading(Double(index + 1) / Double(files.count))
                }
                state = .verifying
                let receipt: [String: Any] = [
                    "schema_version": 1,
                    "repository": Self.repository,
                    "revision": Self.revision,
                    "files": files.map { [
                        "path": $0.path,
                        "bytes": ($0.size ?? -1),
                        "sha256": ($0.lfs?.oid as Any?) ?? NSNull(),
                    ] },
                ]
                try JSONSerialization.data(withJSONObject: receipt, options: [.sortedKeys])
                    .write(to: staging.appending(path: ".letsinfer-snapshot.json"), options: .atomic)
                if manager.fileExists(atPath: destinationURL.path) {
                    try manager.removeItem(at: destinationURL)
                }
                try manager.moveItem(at: staging, to: destinationURL)
                var values = URLResourceValues()
                values.isExcludedFromBackup = true
                var destination = destinationURL
                try destination.setResourceValues(values)
                state = .ready(destinationURL)
                return destinationURL
            } catch {
                try? manager.removeItem(at: staging)
                throw error
            }
        } catch {
            state = .failed(error.localizedDescription)
            throw error
        }
    }

    private func tree() async throws -> [TreeEntry] {
        let repository = Self.repository.addingPercentEncoding(
            withAllowedCharacters: .urlPathAllowed
        ) ?? Self.repository
        guard let url = URL(string:
            "https://huggingface.co/api/models/\(repository)/tree/\(Self.revision)?recursive=true&limit=1000"
        ) else {
            throw NodeError.invalidData("MLC model tree URL is invalid")
        }
        let (data, response) = try await URLSession.shared.data(from: url)
        guard let http = response as? HTTPURLResponse,
              http.statusCode == 200,
              data.count <= 16 * 1024 * 1024
        else {
            throw NodeError.network("MLC model tree request failed")
        }
        return try JSONDecoder().decode([TreeEntry].self, from: data)
    }

    nonisolated private static func safeRelativePath(_ value: String) throws -> [String] {
        let parts = value.split(separator: "/").map(String.init)
        guard !parts.isEmpty,
              parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && !$0.contains("\0") })
        else {
            throw NodeError.invalidData("MLC model snapshot path is unsafe")
        }
        return parts
    }

    nonisolated private static func sha256(of url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var digest = SHA256()
        while true {
            let data = try handle.read(upToCount: 4 * 1024 * 1024) ?? Data()
            if data.isEmpty { break }
            digest.update(data: data)
        }
        return digest.finalize().hexString
    }

    nonisolated private static func verifySnapshot(
        destination: URL,
        receiptURL: URL
    ) throws {
        let data = try Data(contentsOf: receiptURL)
        let receipt = try JSONDecoder().decode(Receipt.self, from: data)
        guard receipt.schema_version == 1,
              receipt.repository == repository,
              receipt.revision == revision,
              receipt.files.count == expectedFileCount,
              receipt.files.reduce(Int64(0), { $0 + $1.bytes })
                == expectedSnapshotBytes
        else {
            throw NodeError.inference("MLC model receipt is invalid")
        }
        var seen = Set<String>()
        var total: Int64 = 0
        for record in receipt.files {
            let relative = try safeRelativePath(record.path)
            guard seen.insert(record.path).inserted,
                  record.bytes >= 0
            else {
                throw NodeError.inference("MLC model receipt contains invalid files")
            }
            total += record.bytes
            guard total <= 1_099_511_627_776 else {
                throw NodeError.inference("MLC model snapshot exceeds its bound")
            }
            let file = relative.reduce(destination) { $0.appending(path: $1) }
            let values = try file.resourceValues(forKeys: [
                .isRegularFileKey,
                .fileSizeKey,
            ])
            guard values.isRegularFile == true,
                  Int64(values.fileSize ?? -1) == record.bytes
            else {
                throw NodeError.inference("MLC model snapshot is incomplete")
            }
            if let rawSHA256 = record.sha256 {
                guard let expected = rawSHA256.removingPrefix("sha256:"),
                      expected.count == 64,
                      try sha256(of: file) == expected
                else {
                    throw NodeError.inference("MLC model snapshot checksum differs")
                }
            }
        }
    }

    private var destinationURL: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appending(path: "Models/mlc-ai--qwen3-0.6b-q4f16_1-mlc/\(Self.revision)")
    }

    private var receiptURL: URL {
        destinationURL.appending(path: ".letsinfer-snapshot.json")
    }
}

private extension String {
    func removingPrefix(_ prefix: String) -> String? {
        hasPrefix(prefix) ? String(dropFirst(prefix.count)) : nil
    }
}
