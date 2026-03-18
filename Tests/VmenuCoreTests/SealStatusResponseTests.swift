import XCTest

@testable import VmenuCore

final class SealStatusResponseTests: XCTestCase {

  // MARK: - JSON decoding

  func testDecodeUnsealedDevServer() throws {
    let json = Data("""
    {
      "type": "shamir",
      "initialized": true,
      "sealed": false,
      "t": 1,
      "n": 1,
      "progress": 0,
      "nonce": "",
      "version": "1.21.4",
      "build_date": "2026-03-04T17:40:05Z",
      "migration": false,
      "cluster_name": "vault-cluster-0063c64e",
      "cluster_id": "4b924ccb-a038-951a-c990-b72f471d1eb0",
      "recovery_seal": false,
      "storage_type": "inmem"
    }
    """.utf8)

    let response = try JSONDecoder().decode(SealStatusResponse.self, from: json)

    XCTAssertEqual(response.type, "shamir")
    XCTAssertTrue(response.initialized)
    XCTAssertFalse(response.sealed)
    XCTAssertEqual(response.threshold, 1)
    XCTAssertEqual(response.totalShares, 1)
    XCTAssertEqual(response.progress, 0)
    XCTAssertEqual(response.nonce, "")
    XCTAssertEqual(response.version, "1.21.4")
    XCTAssertEqual(response.buildDate, "2026-03-04T17:40:05Z")
    XCTAssertFalse(response.migration)
    XCTAssertEqual(response.clusterName, "vault-cluster-0063c64e")
    XCTAssertEqual(response.clusterId, "4b924ccb-a038-951a-c990-b72f471d1eb0")
    XCTAssertFalse(response.recoverySeal)
    XCTAssertEqual(response.storageType, "inmem")
  }

  func testDecodeSealedServer() throws {
    let json = Data("""
    {
      "type": "shamir",
      "initialized": true,
      "sealed": true,
      "t": 3,
      "n": 5,
      "progress": 1,
      "nonce": "abc123",
      "version": "1.15.4",
      "build_date": "2024-01-26T14:53:40Z",
      "migration": false,
      "recovery_seal": false,
      "storage_type": "raft"
    }
    """.utf8)

    let response = try JSONDecoder().decode(SealStatusResponse.self, from: json)

    XCTAssertTrue(response.sealed)
    XCTAssertEqual(response.threshold, 3)
    XCTAssertEqual(response.totalShares, 5)
    XCTAssertEqual(response.progress, 1)
    XCTAssertEqual(response.nonce, "abc123")
    XCTAssertEqual(response.storageType, "raft")
    // Cluster fields absent when sealed
    XCTAssertNil(response.clusterName)
    XCTAssertNil(response.clusterId)
  }

  func testDecodeUninitializedServer() throws {
    let json = Data("""
    {
      "type": "shamir",
      "initialized": false,
      "sealed": true,
      "t": 0,
      "n": 0,
      "progress": 0,
      "nonce": "",
      "version": "1.15.4",
      "build_date": "2024-01-26T14:53:40Z",
      "migration": false,
      "recovery_seal": false
    }
    """.utf8)

    let response = try JSONDecoder().decode(SealStatusResponse.self, from: json)

    XCTAssertFalse(response.initialized)
    XCTAssertTrue(response.sealed)
    XCTAssertEqual(response.threshold, 0)
    XCTAssertEqual(response.totalShares, 0)
    XCTAssertNil(response.storageType)
    XCTAssertNil(response.clusterName)
    XCTAssertNil(response.clusterId)
  }

  func testDecodeAWSKMSSealType() throws {
    let json = Data("""
    {
      "type": "awskms",
      "initialized": true,
      "sealed": false,
      "t": 1,
      "n": 1,
      "progress": 0,
      "nonce": "",
      "version": "1.16.0",
      "build_date": "2024-06-01T00:00:00Z",
      "migration": false,
      "cluster_name": "prod-cluster",
      "cluster_id": "abc-123",
      "recovery_seal": true,
      "storage_type": "consul"
    }
    """.utf8)

    let response = try JSONDecoder().decode(SealStatusResponse.self, from: json)

    XCTAssertEqual(response.type, "awskms")
    XCTAssertTrue(response.recoverySeal)
    XCTAssertEqual(response.storageType, "consul")
  }

  func testEquality() throws {
    let json = Data("""
    {
      "type": "shamir",
      "initialized": true,
      "sealed": false,
      "t": 1,
      "n": 1,
      "progress": 0,
      "nonce": "",
      "version": "1.21.4",
      "build_date": "2026-03-04T17:40:05Z",
      "migration": false,
      "recovery_seal": false,
      "storage_type": "inmem"
    }
    """.utf8)

    let lhs = try JSONDecoder().decode(SealStatusResponse.self, from: json)
    let rhs = try JSONDecoder().decode(SealStatusResponse.self, from: json)

    XCTAssertEqual(lhs, rhs)
  }

  // MARK: - VaultStatus construction from JSON

  func testVaultStatusFromSealStatusOnly() throws {
    let json = Data("""
    {
      "type": "shamir",
      "initialized": true,
      "sealed": false,
      "t": 1,
      "n": 1,
      "progress": 0,
      "nonce": "",
      "version": "1.21.4",
      "build_date": "2026-03-04T17:40:05Z",
      "migration": false,
      "cluster_name": "vault-cluster-0063c64e",
      "cluster_id": "4b924ccb-a038-951a-c990-b72f471d1eb0",
      "recovery_seal": false,
      "storage_type": "inmem"
    }
    """.utf8)

    let sealStatus = try JSONDecoder().decode(SealStatusResponse.self, from: json)
    let status = VaultStatus(from: sealStatus)

    XCTAssertEqual(status.sealType, "shamir")
    XCTAssertEqual(status.initialized, "true")
    XCTAssertEqual(status.sealed, "false")
    XCTAssertEqual(status.totalShares, "1")
    XCTAssertEqual(status.threshold, "1")
    XCTAssertEqual(status.version, "1.21.4")
    XCTAssertEqual(status.buildDate, "2026-03-04T17:40:05Z")
    XCTAssertEqual(status.storageType, "inmem")
    XCTAssertEqual(status.clusterName, "vault-cluster-0063c64e")
    XCTAssertEqual(status.clusterId, "4b924ccb-a038-951a-c990-b72f471d1eb0")
    // No leader response → haEnabled is "-"
    XCTAssertEqual(status.haEnabled, "-")
  }

  func testVaultStatusFromSealStatusAndLeader() throws {
    let sealJson = Data("""
    {
      "type": "shamir",
      "initialized": true,
      "sealed": false,
      "t": 1,
      "n": 1,
      "progress": 0,
      "nonce": "",
      "version": "1.21.4",
      "build_date": "2026-03-04T17:40:05Z",
      "migration": false,
      "cluster_name": "vault-cluster-0063c64e",
      "cluster_id": "4b924ccb-a038-951a-c990-b72f471d1eb0",
      "recovery_seal": false,
      "storage_type": "inmem"
    }
    """.utf8)

    let leaderJson = Data("""
    {
      "ha_enabled": false,
      "is_self": false,
      "leader_address": "",
      "leader_cluster_address": "",
      "performance_standby": false,
      "performance_standby_last_remote_wal": 0
    }
    """.utf8)

    let sealStatus = try JSONDecoder().decode(SealStatusResponse.self, from: sealJson)
    let leader = try JSONDecoder().decode(LeaderResponse.self, from: leaderJson)
    let status = VaultStatus(from: sealStatus, leader: leader)

    XCTAssertEqual(status.haEnabled, "false")
    XCTAssertEqual(status.sealType, "shamir")
    XCTAssertEqual(status.sealed, "false")
  }

  func testVaultStatusFromSealedServerNoCluster() throws {
    let json = Data("""
    {
      "type": "shamir",
      "initialized": true,
      "sealed": true,
      "t": 3,
      "n": 5,
      "progress": 0,
      "nonce": "",
      "version": "1.15.4",
      "build_date": "2024-01-26T14:53:40Z",
      "migration": false,
      "recovery_seal": false,
      "storage_type": "raft"
    }
    """.utf8)

    let sealStatus = try JSONDecoder().decode(SealStatusResponse.self, from: json)
    let status = VaultStatus(from: sealStatus)

    XCTAssertEqual(status.sealed, "true")
    XCTAssertEqual(status.totalShares, "5")
    XCTAssertEqual(status.threshold, "3")
    XCTAssertEqual(status.storageType, "raft")
    XCTAssertEqual(status.clusterName, "-")
    XCTAssertEqual(status.clusterId, "-")
  }

  func testVaultStatusHAEnabled() throws {
    let sealJson = Data("""
    {
      "type": "shamir",
      "initialized": true,
      "sealed": false,
      "t": 1,
      "n": 1,
      "progress": 0,
      "nonce": "",
      "version": "1.21.4",
      "build_date": "2026-03-04T17:40:05Z",
      "migration": false,
      "recovery_seal": false,
      "storage_type": "raft"
    }
    """.utf8)

    let leaderJson = Data("""
    {
      "ha_enabled": true,
      "is_self": true,
      "leader_address": "https://127.0.0.1:8200",
      "leader_cluster_address": "https://127.0.0.1:8201",
      "performance_standby": false,
      "performance_standby_last_remote_wal": 0
    }
    """.utf8)

    let sealStatus = try JSONDecoder().decode(SealStatusResponse.self, from: sealJson)
    let leader = try JSONDecoder().decode(LeaderResponse.self, from: leaderJson)
    let status = VaultStatus(from: sealStatus, leader: leader)

    XCTAssertEqual(status.haEnabled, "true")
  }
}
