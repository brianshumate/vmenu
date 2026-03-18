import XCTest

@testable import VmenuCore

final class FormatAsTableTests: XCTestCase {

  func testUnsealedDevServerTable() {
    let status = VaultStatus(
      sealType: "shamir",
      initialized: "true",
      sealed: "false",
      totalShares: "1",
      threshold: "1",
      version: "1.21.4",
      buildDate: "2026-03-04T17:40:05Z",
      storageType: "inmem",
      clusterName: "vault-cluster-0063c64e",
      clusterId: "4b924ccb-a038-951a-c990-b72f471d1eb0",
      haEnabled: "false"
    )

    let table = status.formatAsTable()
    let lines = table.components(separatedBy: "\n")

    // Header + separator + 11 data rows
    XCTAssertEqual(lines.count, 13)
    XCTAssertTrue(lines[0].hasPrefix("Key"))
    XCTAssertTrue(lines[0].contains("Value"))
    XCTAssertTrue(lines[1].hasPrefix("---"))
    XCTAssertTrue(lines[1].contains("-----"))

    // Verify key fields are present
    XCTAssertTrue(table.contains("Seal Type"))
    XCTAssertTrue(table.contains("shamir"))
    XCTAssertTrue(table.contains("Initialized"))
    XCTAssertTrue(table.contains("true"))
    XCTAssertTrue(table.contains("Version"))
    XCTAssertTrue(table.contains("1.21.4"))
    XCTAssertTrue(table.contains("Storage Type"))
    XCTAssertTrue(table.contains("inmem"))
    XCTAssertTrue(table.contains("Cluster Name"))
    XCTAssertTrue(table.contains("vault-cluster-0063c64e"))
    XCTAssertTrue(table.contains("HA Enabled"))
  }

  func testSealedServerOmitsClusterFields() {
    let status = VaultStatus(
      sealType: "shamir",
      initialized: "true",
      sealed: "true",
      totalShares: "5",
      threshold: "3",
      version: "1.15.4",
      buildDate: "2024-01-26T14:53:40Z",
      storageType: "raft",
      haEnabled: "true"
    )

    let table = status.formatAsTable()

    // Cluster Name and Cluster ID default to "-" and should be omitted
    XCTAssertFalse(table.contains("Cluster Name"))
    XCTAssertFalse(table.contains("Cluster ID"))

    // Other fields should be present
    XCTAssertTrue(table.contains("Sealed"))
    XCTAssertTrue(table.contains("true"))
    XCTAssertTrue(table.contains("Total Shares"))
    XCTAssertTrue(table.contains("5"))
  }

  func testAllDefaultsProducesEmptyString() {
    let status = VaultStatus()
    XCTAssertEqual(status.formatAsTable(), "")
  }

  func testSingleFieldTable() {
    let status = VaultStatus(version: "1.18.0")
    let table = status.formatAsTable()
    let lines = table.components(separatedBy: "\n")

    // Header + separator + 1 data row
    XCTAssertEqual(lines.count, 3)
    XCTAssertTrue(table.contains("Version"))
    XCTAssertTrue(table.contains("1.18.0"))
  }

  func testTableAlignmentConsistency() {
    let status = VaultStatus(
      sealType: "shamir",
      initialized: "true",
      sealed: "false",
      totalShares: "1",
      threshold: "1",
      version: "1.21.4",
      buildDate: "2026-03-04T17:40:05Z",
      storageType: "inmem",
      clusterName: "vault-cluster-abc",
      clusterId: "123-456",
      haEnabled: "false"
    )

    let table = status.formatAsTable()
    let lines = table.components(separatedBy: "\n")

    // Skip header (first 2 lines). All data lines should have the
    // "Value" column starting at the same character position.
    let dataLines = Array(lines.dropFirst(2))
    XCTAssertFalse(dataLines.isEmpty)

    // The header "Value" position tells us where values should start
    guard let headerValueRange = lines[0].range(of: "Value") else {
      XCTFail("Header line should contain 'Value'")
      return
    }
    let expectedOffset = lines[0].distance(
      from: lines[0].startIndex, to: headerValueRange.lowerBound
    )

    for line in dataLines {
      // Each line should have content at the expected offset
      XCTAssertGreaterThanOrEqual(
        line.count, expectedOffset,
        "Line too short: \(line)"
      )
    }
  }

  func testRoundTripThroughParse() {
    // Construct a VaultStatus, format it, and parse it back
    let original = VaultStatus(
      sealType: "shamir",
      initialized: "true",
      sealed: "false",
      totalShares: "1",
      threshold: "1",
      version: "1.21.4",
      buildDate: "2026-03-04T17:40:05Z",
      storageType: "inmem",
      clusterName: "vault-cluster-abc",
      clusterId: "123-456-789",
      haEnabled: "false"
    )

    let table = original.formatAsTable()
    let parsed = VaultStatus.parse(from: table)

    XCTAssertEqual(parsed.sealType, original.sealType)
    XCTAssertEqual(parsed.initialized, original.initialized)
    XCTAssertEqual(parsed.sealed, original.sealed)
    XCTAssertEqual(parsed.totalShares, original.totalShares)
    XCTAssertEqual(parsed.threshold, original.threshold)
    XCTAssertEqual(parsed.version, original.version)
    XCTAssertEqual(parsed.buildDate, original.buildDate)
    XCTAssertEqual(parsed.storageType, original.storageType)
    XCTAssertEqual(parsed.clusterName, original.clusterName)
    XCTAssertEqual(parsed.clusterId, original.clusterId)
    XCTAssertEqual(parsed.haEnabled, original.haEnabled)
  }

  func testNoHAEnabledOmitsField() {
    let status = VaultStatus(
      sealType: "shamir",
      version: "1.21.4"
    )

    let table = status.formatAsTable()

    // haEnabled defaults to "-" and should be omitted
    XCTAssertFalse(table.contains("HA Enabled"))
    XCTAssertTrue(table.contains("Seal Type"))
    XCTAssertTrue(table.contains("Version"))
  }
}
