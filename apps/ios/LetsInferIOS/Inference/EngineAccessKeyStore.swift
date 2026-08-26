import Foundation
import Security

final class EngineAccessKeyStore {
    private let service = "ai.letsinfer.ios.engine-access"
    private let account = "default"
    private let groupAccount = "active-group"

    func key() throws -> String {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecSuccess,
           let data = item as? Data,
           let value = String(data: data, encoding: .utf8),
           value.hasPrefix("li_ios_") {
            return value
        }
        guard status == errSecItemNotFound else {
            throw NodeError.crypto("Could not read the Engine access key (\(status))")
        }
        let value = "li_ios_" + (try secureRandom(count: 24)).hexString
        let addStatus = SecItemAdd([
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecValueData: Data(value.utf8),
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ] as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw NodeError.crypto("Could not store the Engine access key (\(addStatus))")
        }
        return value
    }

    func authorizes(_ header: String?) -> Bool {
        guard let header, header.hasPrefix("Bearer ")
        else { return false }
        let candidate = String(header.dropFirst("Bearer ".count))
        let expected = [try? key(), groupKey()].compactMap { $0 }
        return expected.contains {
            constantTimeEqual(Data(candidate.utf8), Data($0.utf8))
        }
    }

    func setGroupKey(_ value: String?) throws {
        SecItemDelete([
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: groupAccount,
        ] as CFDictionary)
        guard let value else { return }
        let status = SecItemAdd([
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: groupAccount,
            kSecValueData: Data(value.utf8),
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ] as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw NodeError.crypto("Could not store the group Engine key (\(status))")
        }
    }

    private func groupKey() -> String? {
        var item: CFTypeRef?
        let status = SecItemCopyMatching([
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: groupAccount,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne,
        ] as CFDictionary, &item)
        guard status == errSecSuccess,
              let data = item as? Data
        else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private func constantTimeEqual(_ left: Data, _ right: Data) -> Bool {
        guard left.count == right.count else { return false }
        return zip(left, right).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
    }
}
