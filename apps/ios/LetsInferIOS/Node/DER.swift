import Foundation
import Security

enum DER {
    static func item(tag: UInt8, _ content: Data) -> Data {
        Data([tag]) + length(content.count) + content
    }

    static func sequence(_ values: Data...) -> Data {
        item(tag: 0x30, values.reduce(into: Data()) { $0.append($1) })
    }

    static func set(_ values: Data...) -> Data {
        item(tag: 0x31, values.reduce(into: Data()) { $0.append($1) })
    }

    static func integer(_ bytes: Data) -> Data {
        var value = bytes.drop { $0 == 0 }
        if value.isEmpty { value = Data([0])[...] }
        var content = Data(value)
        if let first = content.first, first & 0x80 != 0 {
            content.insert(0, at: 0)
        }
        return item(tag: 0x02, content)
    }

    static func integer(_ value: UInt8) -> Data {
        integer(Data([value]))
    }

    static func boolean(_ value: Bool) -> Data {
        item(tag: 0x01, Data([value ? 0xFF : 0x00]))
    }

    static func utf8String(_ value: String) -> Data {
        item(tag: 0x0C, Data(value.utf8))
    }

    static func utcTime(_ date: Date) -> Data {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyMMddHHmmss'Z'"
        return item(tag: 0x17, Data(formatter.string(from: date).utf8))
    }

    static func bitString(_ value: Data, unusedBits: UInt8 = 0) -> Data {
        item(tag: 0x03, Data([unusedBits]) + value)
    }

    static func octetString(_ value: Data) -> Data {
        item(tag: 0x04, value)
    }

    static func context(_ number: UInt8, constructed: Bool, _ value: Data) -> Data {
        item(tag: (constructed ? 0xA0 : 0x80) | number, value)
    }

    static func objectIdentifier(_ value: String) -> Data {
        let parts = value.split(separator: ".").compactMap { UInt64($0) }
        precondition(parts.count >= 2 && parts[0] <= 2)
        var bytes = Data([UInt8(parts[0] * 40 + parts[1])])
        for part in parts.dropFirst(2) {
            var encoded = [UInt8(part & 0x7F)]
            var remaining = part >> 7
            while remaining > 0 {
                encoded.insert(UInt8(remaining & 0x7F) | 0x80, at: 0)
                remaining >>= 7
            }
            bytes.append(contentsOf: encoded)
        }
        return item(tag: 0x06, bytes)
    }

    static func p256SubjectPublicKeyInfo(rawPublicKey: Data) -> Data {
        sequence(
            sequence(
                objectIdentifier("1.2.840.10045.2.1"),
                objectIdentifier("1.2.840.10045.3.1.7")
            ),
            bitString(rawPublicKey)
        )
    }

    private static func length(_ value: Int) -> Data {
        precondition(value >= 0)
        if value < 128 { return Data([UInt8(value)]) }
        var remaining = value
        var bytes: [UInt8] = []
        while remaining > 0 {
            bytes.insert(UInt8(remaining & 0xFF), at: 0)
            remaining >>= 8
        }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }
}

enum X509CertificateBuilder {
    private static let ecdsaWithSHA256 = "1.2.840.10045.4.3.2"

    static func selfSigned(
        privateKey: SecKey,
        publicKey: SecKey,
        memberID: String,
        now: Date = Date()
    ) throws -> Data {
        let rawPublic = try externalRepresentation(publicKey)
        let commonName = "Let's Infer iOS \(memberID)"
        let name = DER.sequence(
            DER.set(
                DER.sequence(
                    DER.objectIdentifier("2.5.4.3"),
                    DER.utf8String(commonName)
                )
            )
        )
        var serial = try secureRandom(count: 16)
        serial[serial.startIndex] &= 0x7F
        if serial.allSatisfy({ $0 == 0 }) { serial[serial.startIndex] = 1 }

        let signatureAlgorithm = DER.sequence(DER.objectIdentifier(ecdsaWithSHA256))
        let basicConstraints = extensionValue(
            oid: "2.5.29.19",
            critical: true,
            value: DER.sequence()
        )
        let keyUsage = extensionValue(
            oid: "2.5.29.15",
            critical: true,
            value: DER.bitString(Data([0x80]), unusedBits: 7)
        )
        let extendedKeyUsage = extensionValue(
            oid: "2.5.29.37",
            critical: false,
            value: DER.sequence(
                DER.objectIdentifier("1.3.6.1.5.5.7.3.1"),
                DER.objectIdentifier("1.3.6.1.5.5.7.3.2")
            )
        )
        let subjectAlternativeName = extensionValue(
            oid: "2.5.29.17",
            critical: false,
            value: DER.sequence(
                DER.context(
                    6,
                    constructed: false,
                    Data("urn:letsinfer:member:\(memberID)".utf8)
                )
            )
        )
        let expiration = Calendar(identifier: .gregorian).date(
            byAdding: .year,
            value: 10,
            to: now
        ) ?? now.addingTimeInterval(10 * 365 * 24 * 60 * 60)
        let tbs = DER.sequence(
            DER.context(0, constructed: true, DER.integer(2)),
            DER.integer(serial),
            signatureAlgorithm,
            name,
            DER.sequence(
                DER.utcTime(now.addingTimeInterval(-300)),
                DER.utcTime(expiration)
            ),
            name,
            DER.p256SubjectPublicKeyInfo(rawPublicKey: rawPublic),
            DER.context(
                3,
                constructed: true,
                DER.sequence(
                    basicConstraints,
                    keyUsage,
                    extendedKeyUsage,
                    subjectAlternativeName
                )
            )
        )
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            tbs as CFData,
            &error
        ) as Data? else {
            if let error { throw error.takeRetainedValue() }
            throw NodeError.crypto("Could not sign TLS certificate")
        }
        return DER.sequence(tbs, signatureAlgorithm, DER.bitString(signature))
    }

    private static func extensionValue(
        oid: String,
        critical: Bool,
        value: Data
    ) -> Data {
        if critical {
            return DER.sequence(
                DER.objectIdentifier(oid),
                DER.boolean(true),
                DER.octetString(value)
            )
        }
        return DER.sequence(DER.objectIdentifier(oid), DER.octetString(value))
    }
}

func externalRepresentation(_ key: SecKey) throws -> Data {
    var error: Unmanaged<CFError>?
    guard let data = SecKeyCopyExternalRepresentation(key, &error) as Data? else {
        if let error { throw error.takeRetainedValue() }
        throw NodeError.crypto("Key is not exportable")
    }
    return data
}

func secureRandom(count: Int) throws -> Data {
    var data = Data(count: count)
    let status = data.withUnsafeMutableBytes { bytes in
        SecRandomCopyBytes(kSecRandomDefault, count, bytes.baseAddress!)
    }
    guard status == errSecSuccess else {
        throw NodeError.crypto("Secure random generation failed (\(status))")
    }
    return data
}
