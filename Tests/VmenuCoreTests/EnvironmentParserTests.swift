import XCTest

@testable import VmenuCore

final class EnvironmentParserTests: XCTestCase {

  func testParseTypicalStartupLog() {
    let log = """
    ==> Vault server configuration:

          Api Address: https://127.0.0.1:8200
              Cgo: disabled
        Cluster Address: https://127.0.0.1:8201
       Environment Variables: VAULT_DEV_ROOT_TOKEN_ID
         Listener 1: tcp (addr: "127.0.0.1:8200",
         cluster: "127.0.0.1:8201", tls: "enabled")
          Log Level:
            Mlock: supported: false, enabled: false
        Recovery Mode: false
           Storage: inmem
           Version: Vault v1.15.4

    WARNING! dev mode is enabled! In this mode, Vault runs entirely in memory
    and starts unsealed with a single unseal key. The root token is already
    authenticated to the CLI, so you can immediately begin using Vault.

    You may need to set the following environment variables:

      export VAULT_ADDR='https://127.0.0.1:8200'
      export VAULT_CACERT='/var/folders/ab/cd/T/vault-tls12345/vault-ca.pem'

    The unseal key and root token are displayed below in case you want to
    seal/unseal the Vault or re-authenticate.

    Unseal Key: abc123def456
    Root Token: root
    """

    let env = parseEnvironmentVariables(from: log)

    XCTAssertEqual(env.vaultAddr, "https://127.0.0.1:8200")
    XCTAssertEqual(env.vaultCACert, "/var/folders/ab/cd/T/vault-tls12345/vault-ca.pem")
    XCTAssertEqual(env.vaultToken, "root")
    XCTAssertEqual(env.unsealKey, "abc123def456")
  }

  func testParseDoubleQuotedValues() {
    let log = """
      export VAULT_ADDR="https://127.0.0.1:8200"
      export VAULT_CACERT="/tmp/vault-ca.pem"
    Root Token: s.abcdef123456
    """

    let env = parseEnvironmentVariables(from: log)

    XCTAssertEqual(env.vaultAddr, "https://127.0.0.1:8200")
    XCTAssertEqual(env.vaultCACert, "/tmp/vault-ca.pem")
    XCTAssertEqual(env.vaultToken, "s.abcdef123456")
  }

  func testParseSingleQuotedValues() {
    let log = """
      export VAULT_ADDR='https://127.0.0.1:8200'
      export VAULT_CACERT='/tmp/vault-ca.pem'
    Root Token: root
    """

    let env = parseEnvironmentVariables(from: log)

    XCTAssertEqual(env.vaultAddr, "https://127.0.0.1:8200")
    XCTAssertEqual(env.vaultCACert, "/tmp/vault-ca.pem")
    XCTAssertEqual(env.vaultToken, "root")
  }

  func testParseUnquotedValues() {
    let log = """
      export VAULT_ADDR=https://127.0.0.1:8200
      export VAULT_CACERT=/tmp/vault-ca.pem
    Root Token: root
    """

    let env = parseEnvironmentVariables(from: log)

    XCTAssertEqual(env.vaultAddr, "https://127.0.0.1:8200")
    XCTAssertEqual(env.vaultCACert, "/tmp/vault-ca.pem")
    XCTAssertEqual(env.vaultToken, "root")
  }

  func testPicksMostRecentValuesFromMultipleRuns() {
    let log = """
      export VAULT_ADDR='https://127.0.0.1:8200'
      export VAULT_CACERT='/tmp/old-cert.pem'
    Unseal Key: oldkey123
    Root Token: old-token

    Vault restarted...

      export VAULT_ADDR='https://127.0.0.1:8201'
      export VAULT_CACERT='/tmp/new-cert.pem'
    Unseal Key: newkey456
    Root Token: new-token
    """

    let env = parseEnvironmentVariables(from: log)

    // Should pick the latest (last) values since it iterates in reverse
    XCTAssertEqual(env.vaultAddr, "https://127.0.0.1:8201")
    XCTAssertEqual(env.vaultCACert, "/tmp/new-cert.pem")
    XCTAssertEqual(env.vaultToken, "new-token")
    XCTAssertEqual(env.unsealKey, "newkey456")
  }

  func testParseOnlyAddr() {
    let log = """
      export VAULT_ADDR='https://127.0.0.1:8200'
    """

    let env = parseEnvironmentVariables(from: log)

    XCTAssertEqual(env.vaultAddr, "https://127.0.0.1:8200")
    XCTAssertEqual(env.vaultCACert, "")
    XCTAssertEqual(env.vaultToken, "")
  }

  func testParseOnlyCACert() {
    let log = """
      export VAULT_CACERT='/tmp/vault-ca.pem'
    """

    let env = parseEnvironmentVariables(from: log)

    XCTAssertEqual(env.vaultAddr, "")
    XCTAssertEqual(env.vaultCACert, "/tmp/vault-ca.pem")
    XCTAssertEqual(env.vaultToken, "")
  }

  func testParseOnlyToken() {
    let log = """
    Root Token: hvs.some-long-token
    """

    let env = parseEnvironmentVariables(from: log)

    XCTAssertEqual(env.vaultAddr, "")
    XCTAssertEqual(env.vaultCACert, "")
    XCTAssertEqual(env.vaultToken, "hvs.some-long-token")
    XCTAssertEqual(env.unsealKey, "")
  }

  func testParseOnlyUnsealKey() {
    let log = """
    Unseal Key: GDz8cL2gACZJAByboalN3e0BFpqAmwNCJ3Tve5Evac0=
    """

    let env = parseEnvironmentVariables(from: log)

    XCTAssertEqual(env.vaultAddr, "")
    XCTAssertEqual(env.vaultCACert, "")
    XCTAssertEqual(env.vaultToken, "")
    XCTAssertEqual(env.unsealKey, "GDz8cL2gACZJAByboalN3e0BFpqAmwNCJ3Tve5Evac0=")
  }

  func testEmptyString() {
    let env = parseEnvironmentVariables(from: "")

    XCTAssertEqual(env.vaultAddr, "")
    XCTAssertEqual(env.vaultCACert, "")
    XCTAssertEqual(env.vaultToken, "")
    XCTAssertEqual(env.unsealKey, "")
  }

  func testNoExportLines() {
    let log = """
    Vault server started
    Listening on 127.0.0.1:8200
    Ready.
    """

    let env = parseEnvironmentVariables(from: log)

    XCTAssertEqual(env.vaultAddr, "")
    XCTAssertEqual(env.vaultCACert, "")
    XCTAssertEqual(env.vaultToken, "")
    XCTAssertEqual(env.unsealKey, "")
  }

  func testExportWithEmptyValue() {
    let log = """
      export VAULT_ADDR=
      export VAULT_CACERT=
    """

    let env = parseEnvironmentVariables(from: log)

    XCTAssertEqual(env.vaultAddr, "")
    XCTAssertEqual(env.vaultCACert, "")
    XCTAssertEqual(env.vaultToken, "")
    XCTAssertEqual(env.unsealKey, "")
  }

  func testExportOnDifferentPort() {
    let log = """
      export VAULT_ADDR='https://10.0.1.50:8250'
      export VAULT_CACERT='/etc/vault/tls/ca.pem'
    """

    let env = parseEnvironmentVariables(from: log)

    XCTAssertEqual(env.vaultAddr, "https://10.0.1.50:8250")
    XCTAssertEqual(env.vaultCACert, "/etc/vault/tls/ca.pem")
  }

  func testHttpAddressWithoutTLS() {
    let log = """
      export VAULT_ADDR='http://127.0.0.1:8200'
    """

    let env = parseEnvironmentVariables(from: log)

    XCTAssertEqual(env.vaultAddr, "http://127.0.0.1:8200")
  }

  func testVaultEnvironmentDefaults() {
    let env = VaultEnvironment()
    XCTAssertEqual(env.vaultAddr, "")
    XCTAssertEqual(env.vaultCACert, "")
    XCTAssertEqual(env.vaultToken, "")
    XCTAssertEqual(env.unsealKey, "")
  }

  func testVaultEnvironmentEquality() {
    let lhs = VaultEnvironment(
      vaultAddr: "https://localhost:8200",
      vaultCACert: "/tmp/ca.pem",
      vaultToken: "root",
      unsealKey: "abc123"
    )
    let rhs = VaultEnvironment(
      vaultAddr: "https://localhost:8200",
      vaultCACert: "/tmp/ca.pem",
      vaultToken: "root",
      unsealKey: "abc123"
    )
    XCTAssertEqual(lhs, rhs)
  }

  func testVaultEnvironmentInequality() {
    let lhs = VaultEnvironment(vaultAddr: "https://localhost:8200")
    let rhs = VaultEnvironment(vaultAddr: "https://localhost:8201")
    XCTAssertNotEqual(lhs, rhs)
  }

  func testVaultEnvironmentTokenInequality() {
    let lhs = VaultEnvironment(vaultToken: "root")
    let rhs = VaultEnvironment(vaultToken: "other-token")
    XCTAssertNotEqual(lhs, rhs)
  }

  func testVaultEnvironmentUnsealKeyInequality() {
    let lhs = VaultEnvironment(unsealKey: "key1")
    let rhs = VaultEnvironment(unsealKey: "key2")
    XCTAssertNotEqual(lhs, rhs)
  }
}
