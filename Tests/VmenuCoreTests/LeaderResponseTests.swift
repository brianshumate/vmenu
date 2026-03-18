import XCTest

@testable import VmenuCore

final class LeaderResponseTests: XCTestCase {

  func testDecodeHADisabled() throws {
    let json = Data("""
    {
      "ha_enabled": false,
      "is_self": false,
      "leader_address": "",
      "leader_cluster_address": "",
      "performance_standby": false,
      "performance_standby_last_remote_wal": 0
    }
    """.utf8)

    let response = try JSONDecoder().decode(LeaderResponse.self, from: json)

    XCTAssertFalse(response.haEnabled)
    XCTAssertFalse(response.isSelf)
    XCTAssertEqual(response.leaderAddress, "")
    XCTAssertEqual(response.leaderClusterAddress, "")
  }

  func testDecodeHAEnabled() throws {
    let json = Data("""
    {
      "ha_enabled": true,
      "is_self": true,
      "leader_address": "https://127.0.0.1:8200",
      "leader_cluster_address": "https://127.0.0.1:8201",
      "performance_standby": false,
      "performance_standby_last_remote_wal": 0
    }
    """.utf8)

    let response = try JSONDecoder().decode(LeaderResponse.self, from: json)

    XCTAssertTrue(response.haEnabled)
    XCTAssertTrue(response.isSelf)
    XCTAssertEqual(response.leaderAddress, "https://127.0.0.1:8200")
    XCTAssertEqual(response.leaderClusterAddress, "https://127.0.0.1:8201")
  }

  func testEquality() throws {
    let json = Data("""
    {
      "ha_enabled": false,
      "is_self": false,
      "leader_address": "",
      "leader_cluster_address": ""
    }
    """.utf8)

    let lhs = try JSONDecoder().decode(LeaderResponse.self, from: json)
    let rhs = try JSONDecoder().decode(LeaderResponse.self, from: json)

    XCTAssertEqual(lhs, rhs)
  }

  func testInequality() throws {
    let json1 = Data("""
    {
      "ha_enabled": false,
      "is_self": false,
      "leader_address": "",
      "leader_cluster_address": ""
    }
    """.utf8)

    let json2 = Data("""
    {
      "ha_enabled": true,
      "is_self": true,
      "leader_address": "https://10.0.0.1:8200",
      "leader_cluster_address": "https://10.0.0.1:8201"
    }
    """.utf8)

    let lhs = try JSONDecoder().decode(LeaderResponse.self, from: json1)
    let rhs = try JSONDecoder().decode(LeaderResponse.self, from: json2)

    XCTAssertNotEqual(lhs, rhs)
  }
}
