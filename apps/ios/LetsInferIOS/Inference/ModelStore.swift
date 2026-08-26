import CryptoKit
import Foundation

struct NativeModelManifest: Codable, Equatable, Identifiable {
    let id: String
    let displayName: String
    let filename: String
    let sourceURL: URL
    let revision: String
    let sha256: String
    let sizeBytes: Int64
    let contextTokens: Int

    static let qwen3_0_6B = NativeModelManifest(
        id: "qwen3-0.6b",
        displayName: "Qwen3 0.6B",
        filename: "Qwen3-0.6B-Q8_0.gguf",
        sourceURL: URL(string: "https://huggingface.co/Qwen/Qwen3-0.6B-GGUF/resolve/23749fefcc72300e3a2ad315e1317431b06b590a/Qwen3-0.6B-Q8_0.gguf")!,
        revision: "23749fefcc72300e3a2ad315e1317431b06b590a",
        sha256: "9465e63a22add5354d9bb4b99e90117043c7124007664907259bd16d043bb031",
        sizeBytes: 639_446_688,
        contextTokens: 8_192
    )
}

@MainActor
final class ModelStore: NSObject, ObservableObject, URLSessionDownloadDelegate {
    enum State: Equatable {
        case missing
        case downloading(Double)
        case verifying
        case ready(URL)
        case failed(String)
    }

    @Published private(set) var state: State = .missing
    let manifest: NativeModelManifest
    private var downloadSession: URLSession?
    private var continuation: CheckedContinuation<URL, Error>?

    init(manifest: NativeModelManifest = .qwen3_0_6B) {
        self.manifest = manifest
        super.init()
        refresh()
    }

    var modelURL: URL? {
        if case .ready(let url) = state { return url }
        return nil
    }

    func refresh() {
        let url = destinationURL
        if FileManager.default.fileExists(atPath: url.path),
           let size = try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize,
           Int64(size) == manifest.sizeBytes {
            state = .ready(url)
        } else {
            state = .missing
        }
    }

    func download() async throws -> URL {
        if let modelURL { return modelURL }
        guard continuation == nil else {
            throw NodeError.inference("Model download is already running")
        }
        state = .downloading(0)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForResource = 60 * 60
        let session = URLSession(
            configuration: configuration,
            delegate: self,
            delegateQueue: nil
        )
        downloadSession = session
        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            session.downloadTask(with: manifest.sourceURL).resume()
        }
    }

    func verifiedModelURL() async throws -> URL {
        guard let url = modelURL else {
            throw NodeError.inference("The exact GGUF model is not installed")
        }
        state = .verifying
        do {
            let expectedBytes = manifest.sizeBytes
            let expectedSHA256 = manifest.sha256
            let verified = try await Task.detached(priority: .utility) {
                let values = try url.resourceValues(forKeys: [.fileSizeKey])
                let digest = try Self.sha256(of: url)
                return Int64(values.fileSize ?? -1) == expectedBytes
                    && digest == expectedSHA256
            }.value
            guard verified else {
                state = .missing
                throw NodeError.inference("Installed GGUF model bytes differ from the runtime")
            }
            state = .ready(url)
            return url
        } catch {
            state = .failed(error.localizedDescription)
            throw error
        }
    }

    func cancelDownload() {
        downloadSession?.invalidateAndCancel()
        finish(.failure(NodeError.inference("Model download cancelled")))
    }

    nonisolated func urlSession(
        _ session: URLSession,
        downloadTask: URLSessionDownloadTask,
        didWriteData bytesWritten: Int64,
        totalBytesWritten: Int64,
        totalBytesExpectedToWrite: Int64
    ) {
        let expected = totalBytesExpectedToWrite > 0
            ? totalBytesExpectedToWrite
            : manifest.sizeBytes
        Task { @MainActor in
            self.state = .downloading(
                min(1, Double(totalBytesWritten) / Double(max(1, expected)))
            )
        }
    }

    nonisolated func urlSession(
        _ session: URLSession,
        downloadTask: URLSessionDownloadTask,
        didFinishDownloadingTo location: URL
    ) {
        Task { @MainActor in
            do {
                self.state = .verifying
                let values = try location.resourceValues(forKeys: [.fileSizeKey])
                guard Int64(values.fileSize ?? -1) == self.manifest.sizeBytes else {
                    throw NodeError.inference("Downloaded model size does not match its manifest")
                }
                let digest = try Self.sha256(of: location)
                guard digest == self.manifest.sha256 else {
                    throw NodeError.inference("Downloaded model checksum does not match its manifest")
                }
                let directory = self.destinationURL.deletingLastPathComponent()
                try FileManager.default.createDirectory(
                    at: directory,
                    withIntermediateDirectories: true
                )
                if FileManager.default.fileExists(atPath: self.destinationURL.path) {
                    try FileManager.default.removeItem(at: self.destinationURL)
                }
                try FileManager.default.moveItem(at: location, to: self.destinationURL)
                var resourceValues = URLResourceValues()
                resourceValues.isExcludedFromBackup = true
                var destination = self.destinationURL
                try destination.setResourceValues(resourceValues)
                self.state = .ready(self.destinationURL)
                self.finish(.success(self.destinationURL))
            } catch {
                self.state = .failed(error.localizedDescription)
                self.finish(.failure(error))
            }
        }
    }

    nonisolated func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didCompleteWithError error: Error?
    ) {
        guard let error else { return }
        Task { @MainActor in
            self.state = .failed(error.localizedDescription)
            self.finish(.failure(error))
        }
    }

    private var destinationURL: URL {
        let root = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        )[0]
        return root
            .appending(path: "Models", directoryHint: .isDirectory)
            .appending(path: manifest.id, directoryHint: .isDirectory)
            .appending(path: manifest.revision, directoryHint: .isDirectory)
            .appending(path: manifest.filename)
    }

    private func finish(_ result: Result<URL, Error>) {
        let continuation = continuation
        self.continuation = nil
        downloadSession?.finishTasksAndInvalidate()
        downloadSession = nil
        continuation?.resume(with: result)
    }

    nonisolated private static func sha256(of url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hasher = SHA256()
        while true {
            let data = try handle.read(upToCount: 4 * 1024 * 1024) ?? Data()
            if data.isEmpty { break }
            hasher.update(data: data)
        }
        return hasher.finalize().hexString
    }
}
