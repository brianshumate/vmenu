import Foundation

/// Parsed representation of `vault status` output.
public struct VaultStatus: Equatable {
    public var sealType: String = "-"
    public var initialized: String = "-"
    public var sealed: String = "-"
    public var totalShares: String = "-"
    public var threshold: String = "-"
    public var version: String = "-"
    public var buildDate: String = "-"
    public var storageType: String = "-"
    public var clusterName: String = "-"
    public var clusterId: String = "-"
    public var haEnabled: String = "-"

    public init(
        sealType: String = "-",
        initialized: String = "-",
        sealed: String = "-",
        totalShares: String = "-",
        threshold: String = "-",
        version: String = "-",
        buildDate: String = "-",
        storageType: String = "-",
        clusterName: String = "-",
        clusterId: String = "-",
        haEnabled: String = "-"
    ) {
        self.sealType = sealType
        self.initialized = initialized
        self.sealed = sealed
        self.totalShares = totalShares
        self.threshold = threshold
        self.version = version
        self.buildDate = buildDate
        self.storageType = storageType
        self.clusterName = clusterName
        self.clusterId = clusterId
        self.haEnabled = haEnabled
    }

    /// Parse the key-value table produced by `vault status`.
    public static func parse(from output: String) -> VaultStatus {
        var status = VaultStatus()
        let pairs = parseKeyValuePairs(from: output)

        for (key, value) in pairs {
            applyField(key: key, value: value, to: &status)
        }

        return status
    }

    /// Extract key-value pairs from the `vault status` table output.
    private static func parseKeyValuePairs(from output: String) -> [(String, String)] {
        var pairs: [(String, String)] = []
        let lines = output.components(separatedBy: .newlines)

        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)

            if trimmed.isEmpty || trimmed.hasPrefix("Key") || trimmed.hasPrefix("---") {
                continue
            }

            guard let separatorRange = trimmed.range(
                of: "\\s{2,}",
                options: .regularExpression
            ) else {
                continue
            }

            let key = String(trimmed[trimmed.startIndex..<separatorRange.lowerBound])
                .trimmingCharacters(in: .whitespaces)
            let value = String(trimmed[separatorRange.upperBound...])
                .trimmingCharacters(in: .whitespaces)

            if !key.isEmpty, !value.isEmpty {
                pairs.append((key, value))
            }
        }

        return pairs
    }

    /// Apply a single parsed field to the status struct.
    private static func applyField(key: String, value: String, to status: inout VaultStatus) {
        switch key {
        case "Seal Type": status.sealType = value
        case "Initialized": status.initialized = value
        case "Sealed": status.sealed = value
        case "Total Shares": status.totalShares = value
        case "Threshold": status.threshold = value
        case "Version": status.version = value
        case "Build Date": status.buildDate = value
        case "Storage Type": status.storageType = value
        case "Cluster Name": status.clusterName = value
        case "Cluster ID": status.clusterId = value
        case "HA Enabled": status.haEnabled = value
        default: break
        }
    }
}
