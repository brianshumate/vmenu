import Foundation

// MARK: - Vault HTTP API JSON responses

/// JSON response from `GET /v1/sys/seal-status`.
///
/// This endpoint does not require authentication and returns all fields
/// that `vault status` displays.
public struct SealStatusResponse: Codable, Equatable {
  public let type: String
  public let initialized: Bool
  public let sealed: Bool
  /// Key threshold required to unseal (maps to `t` in the JSON).
  public let threshold: Int
  /// Total number of key shares (maps to `n` in the JSON).
  public let totalShares: Int
  public let progress: Int
  public let nonce: String
  public let version: String
  public let buildDate: String
  public let migration: Bool
  public let clusterName: String?
  public let clusterId: String?
  public let recoverySeal: Bool
  public let storageType: String?

  enum CodingKeys: String, CodingKey {
    case type, initialized, sealed, progress, nonce, version
    case threshold = "t"
    case totalShares = "n"
    case buildDate = "build_date"
    case migration
    case clusterName = "cluster_name"
    case clusterId = "cluster_id"
    case recoverySeal = "recovery_seal"
    case storageType = "storage_type"
  }
}

/// JSON response from `GET /v1/sys/leader`.
///
/// Used to obtain the `ha_enabled` field, which is not included in the
/// seal-status response.  This endpoint does not require authentication.
public struct LeaderResponse: Codable, Equatable {
  public let haEnabled: Bool
  public let isSelf: Bool
  public let leaderAddress: String
  public let leaderClusterAddress: String

  enum CodingKeys: String, CodingKey {
    case haEnabled = "ha_enabled"
    case isSelf = "is_self"
    case leaderAddress = "leader_address"
    case leaderClusterAddress = "leader_cluster_address"
  }
}

// MARK: - VaultStatus

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

  /// Construct from the Vault HTTP API JSON responses.
  ///
  /// Combines the seal-status response (which carries most fields) with the
  /// optional leader response (which provides `ha_enabled`).
  public init(from sealStatus: SealStatusResponse, leader: LeaderResponse? = nil) {
    self.sealType = sealStatus.type
    self.initialized = String(sealStatus.initialized)
    self.sealed = String(sealStatus.sealed)
    self.totalShares = String(sealStatus.totalShares)
    self.threshold = String(sealStatus.threshold)
    self.version = sealStatus.version
    self.buildDate = sealStatus.buildDate
    self.storageType = sealStatus.storageType ?? "-"
    self.clusterName = sealStatus.clusterName ?? "-"
    self.clusterId = sealStatus.clusterId ?? "-"
    self.haEnabled = leader.map { String($0.haEnabled) } ?? "-"
  }

  /// Format as a key-value table matching the `vault status` CLI output.
  ///
  /// Used to populate the "Raw Output" disclosure group in the status
  /// window, preserving the familiar layout without spawning a process.
  public func formatAsTable() -> String {
    var rows: [(String, String)] = [
      ("Seal Type", sealType),
      ("Initialized", initialized),
      ("Sealed", sealed),
      ("Total Shares", totalShares),
      ("Threshold", threshold),
      ("Version", version),
      ("Build Date", buildDate),
      ("Storage Type", storageType),
      ("Cluster Name", clusterName),
      ("Cluster ID", clusterId),
      ("HA Enabled", haEnabled),
    ]

    // Omit fields that have no value (mirrors vault CLI behavior for
    // sealed servers where cluster details are absent).
    rows = rows.filter { $0.1 != "-" }

    guard !rows.isEmpty else { return "" }

    let maxKeyLen = rows.map(\.0.count).max() ?? 0
    let padded = max(maxKeyLen + 4, 16)  // minimum padding like vault CLI

    var lines = [
      "Key" + String(repeating: " ", count: padded - 3) + "Value",
      "---" + String(repeating: " ", count: padded - 3) + "-----",
    ]

    for (key, value) in rows {
      let padding = String(repeating: " ", count: padded - key.count)
      lines.append(key + padding + value)
    }

    return lines.joined(separator: "\n")
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
