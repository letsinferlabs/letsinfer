import Foundation

enum CanonicalJSON {
    static func data(_ value: Any) throws -> Data {
        guard JSONSerialization.isValidJSONObject(value) else {
            throw NodeError.invalidData("Value is not valid JSON")
        }
        var data = try JSONSerialization.data(
            withJSONObject: value,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        data.append(0x0A)
        return data
    }

    static func object(from data: Data) throws -> [String: Any] {
        guard data.count <= NodeProtocol.maximumBodyBytes else {
            throw NodeError.invalidData("Response is larger than 16 KiB")
        }
        let value = try JSONSerialization.jsonObject(with: data)
        guard let object = value as? [String: Any] else {
            throw NodeError.invalidData("Response is not a JSON object")
        }
        return object
    }
}
