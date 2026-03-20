import XCTest

@testable import VmenuCore

final class VaultStatusTests: XCTestCase {

  func testParseUnsealedDevServer() {
    let output = """
    Key             Value
    ---             -----
    Seal Type       shamir
    Initialized     true
    Sealed          false
    Total Shares    1
    Threshold       1
    Version         1.15.4
    Build Date      2024-01-26T14:53:40Z
    Storage Type    inmem
    Cluster Name    vault-cluster-abc123
    Cluster ID      d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f9a
    HA Enabled      false
    """

    let status = VaultStatus.parse(from: output)

    XCTAssertEqual(status.sealType, "shamir")
    XCTAssertEqual(status.initialized, "true")
    XCTAssertEqual(status.sealed, "false")
    XCTAssertEqual(status.totalShares, "1")
    XCTAssertEqual(status.threshold, "1")
    XCTAssertEqual(status.version, "1.15.4")
    XCTAssertEqual(status.buildDate, "2024-01-26T14:53:40Z")
    XCTAssertEqual(status.storageType, "inmem")
    XCTAssertEqual(status.clusterName, "vault-cluster-abc123")
    XCTAssertEqual(status.clusterId, "d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f9a")
    XCTAssertEqual(status.haEnabled, "false")
  }

  func testParseSealedServer() {
    let output = """
    Key                Value
    ---                -----
    Seal Type          shamir
    Initialized        true
    Sealed             true
    Total Shares       5
    Threshold          3
    Version            1.15.4
    Build Date         2024-01-26T14:53:40Z
    Storage Type       raft
    HA Enabled         true
    """

    let status = VaultStatus.parse(from: output)

    XCTAssertEqual(status.sealType, "shamir")
    XCTAssertEqual(status.initialized, "true")
    XCTAssertEqual(status.sealed, "true")
    XCTAssertEqual(status.totalShares, "5")
    XCTAssertEqual(status.threshold, "3")
    XCTAssertEqual(status.storageType, "raft")
    XCTAssertEqual(status.haEnabled, "true")
    // Cluster fields not present in sealed output
    XCTAssertEqual(status.clusterName, "-")
    XCTAssertEqual(status.clusterId, "-")
  }

  func testParseUninitializedServer() {
    let output = """
    Key                Value
    ---                -----
    Seal Type          shamir
    Initialized        false
    Sealed             true
    Total Shares       0
    Threshold          0
    HA Enabled         false
    """

    let status = VaultStatus.parse(from: output)

    XCTAssertEqual(status.initialized, "false")
    XCTAssertEqual(status.sealed, "true")
    XCTAssertEqual(status.totalShares, "0")
    XCTAssertEqual(status.threshold, "0")
    // Fields not present retain defaults
    XCTAssertEqual(status.version, "-")
    XCTAssertEqual(status.buildDate, "-")
    XCTAssertEqual(status.storageType, "-")
  }

  func testParseEmptyString() {
    let status = VaultStatus.parse(from: "")

    XCTAssertEqual(status.sealType, "-")
    XCTAssertEqual(status.initialized, "-")
    XCTAssertEqual(status.sealed, "-")
    XCTAssertEqual(status.totalShares, "-")
    XCTAssertEqual(status.threshold, "-")
    XCTAssertEqual(status.version, "-")
    XCTAssertEqual(status.buildDate, "-")
    XCTAssertEqual(status.storageType, "-")
    XCTAssertEqual(status.clusterName, "-")
    XCTAssertEqual(status.clusterId, "-")
    XCTAssertEqual(status.haEnabled, "-")
  }

  func testParseGarbageInput() {
    let output = """
    this is not vault output
    just some random text
    no key-value pairs here
    """

    let status = VaultStatus.parse(from: output)

    XCTAssertEqual(status, VaultStatus())
  }

  func testParseOnlyHeaderNoData() {
    let output = """
    Key             Value
    ---             -----
    """

    let status = VaultStatus.parse(from: output)

    XCTAssertEqual(status, VaultStatus())
  }

  func testParseSingleField() {
    let output = """
    Key             Value
    ---             -----
    Version         1.19.0
    """

    let status = VaultStatus.parse(from: output)

    XCTAssertEqual(status.version, "1.19.0")
    XCTAssertEqual(status.sealType, "-")
    XCTAssertEqual(status.sealed, "-")
  }

  func testParseIgnoresUnknownFields() {
    let output = """
    Key                Value
    ---                -----
    Seal Type          shamir
    Custom Field       some-value
    Version            1.15.4
    Another Unknown    ignored
    """

    let status = VaultStatus.parse(from: output)

    XCTAssertEqual(status.sealType, "shamir")
    XCTAssertEqual(status.version, "1.15.4")
  }

  func testParseLinesWithoutSeparatorAreSkipped() {
    let output = """
    Key             Value
    ---             -----
    Seal Type       shamir
    SingleWordNoSeparator
    Version         1.15.4
    """

    let status = VaultStatus.parse(from: output)

    XCTAssertEqual(status.sealType, "shamir")
    XCTAssertEqual(status.version, "1.15.4")
  }

  func testParseExtraWhitespace() {
    let output = """
    Key                    Value
    ---                    -----
    Seal Type              shamir
    Version                1.15.4
    Storage Type           inmem
    """

    let status = VaultStatus.parse(from: output)

    XCTAssertEqual(status.sealType, "shamir")
    XCTAssertEqual(status.version, "1.15.4")
    XCTAssertEqual(status.storageType, "inmem")
  }

  func testParseOutputWithLeadingBlankLines() {
    let output = """


    Key             Value
    ---             -----
    Sealed          false
    """

    let status = VaultStatus.parse(from: output)

    XCTAssertEqual(status.sealed, "false")
  }

  func testParseOutputWithTrailingBlankLines() {
    let output = """
    Key             Value
    ---             -----
    Sealed          false


    """

    let status = VaultStatus.parse(from: output)

    XCTAssertEqual(status.sealed, "false")
  }

  func testParseClusterIdWithUUID() {
    let output = """
    Key             Value
    ---             -----
    Cluster ID      550e8400-e29b-41d4-a716-446655440000
    """

    let status = VaultStatus.parse(from: output)

    XCTAssertEqual(status.clusterId, "550e8400-e29b-41d4-a716-446655440000")
  }

  func testParseOutputWithTabsInsteadOfSpaces() {
    let output = "Seal Type\t\tshamir"
    let status = VaultStatus.parse(from: output)
    XCTAssertEqual(status.sealType, "shamir")
  }

  func testDefaultValuesEquality() {
    let lhs = VaultStatus()
    let rhs = VaultStatus()
    XCTAssertEqual(lhs, rhs)
  }

  func testInequalityOnDifferentValues() {
    let lhs = VaultStatus(sealed: "true")
    let rhs = VaultStatus(sealed: "false")
    XCTAssertNotEqual(lhs, rhs)
  }

  func testMemberwiseInit() {
    let status = VaultStatus(
      sealType: "awskms",
      initialized: "true",
      sealed: "false",
      totalShares: "1",
      threshold: "1",
      version: "1.16.0",
      buildDate: "2024-06-01T00:00:00Z",
      storageType: "consul",
      clusterName: "prod-cluster",
      clusterId: "abc-123",
      haEnabled: "true"
    )

    XCTAssertEqual(status.sealType, "awskms")
    XCTAssertEqual(status.storageType, "consul")
    XCTAssertEqual(status.clusterName, "prod-cluster")
    XCTAssertEqual(status.haEnabled, "true")
  }
}
