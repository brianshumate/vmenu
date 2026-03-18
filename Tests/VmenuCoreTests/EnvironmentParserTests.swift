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
  }

  func testParseDoubleQuotedValues() {
    let log = """
      export VAULT_ADDR="https://127.0.0.1:8200"
      export VAULT_CACERT="/tmp/vault-ca.pem"
    """

    let env = parseEnvironmentVariables(from: log)

    XCTAssertEqual(env.vaultAddr, "https://127.0.0.1:8200")
    XCTAssertEqual(env.vaultCACert, "/tmp/vault-ca.pem")
  }

  func testParseSingleQuotedValues() {
    let log = """
      export VAULT_ADDR='https://127.0.0.1:8200'
      export VAULT_CACERT='/tmp/vault-ca.pem'
    """

    let env = parseEnvironmentVariables(from: log)

    XCTAssertEqual(env.vaultAddr, "https://127.0.0.1:8200")
    XCTAssertEqual(env.vaultCACert, "/tmp/vault-ca.pem")
  }

  func testParseUnquotedValues() {
    let log = """
      export VAULT_ADDR=https://127.0.0.1:8200
      export VAULT_CACERT=/tmp/vault-ca.pem
    """

    let env = parseEnvironmentVariables(from: log)

    XCTAssertEqual(env.vaultAddr, "https://127.0.0.1:8200")
    XCTAssertEqual(env.vaultCACert, "/tmp/vault-ca.pem")
  }

  func testPicksMostRecentValuesFromMultipleRuns() {
    let log = """
      export VAULT_ADDR='https://127.0.0.1:8200'
      export VAULT_CACERT='/tmp/old-cert.pem'

    Vault restarted...

      export VAULT_ADDR='https://127.0.0.1:8201'
      export VAULT_CACERT='/tmp/new-cert.pem'
    """

    let env = parseEnvironmentVariables(from: log)

    // Should pick the latest (last) values since it iterates in reverse
    XCTAssertEqual(env.vaultAddr, "https://127.0.0.1:8201")
    XCTAssertEqual(env.vaultCACert, "/tmp/new-cert.pem")
  }

  func testParseOnlyAddr() {
    let log = """
      export VAULT_ADDR='https://127.0.0.1:8200'
    """

    let env = parseEnvironmentVariables(from: log)

    XCTAssertEqual(env.vaultAddr, "https://127.0.0.1:8200")
    XCTAssertEqual(env.vaultCACert, "")
  }

  func testParseOnlyCACert() {
    let log = """
      export VAULT_CACERT='/tmp/vault-ca.pem'
    """

    let env = parseEnvironmentVariables(from: log)

    XCTAssertEqual(env.vaultAddr, "")
    XCTAssertEqual(env.vaultCACert, "/tmp/vault-ca.pem")
  }

  func testEmptyString() {
    let env = parseEnvironmentVariables(from: "")

    XCTAssertEqual(env.vaultAddr, "")
    XCTAssertEqual(env.vaultCACert, "")
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
  }

  func testExportWithEmptyValue() {
    let log = """
      export VAULT_ADDR=
      export VAULT_CACERT=
    """

    let env = parseEnvironmentVariables(from: log)

    XCTAssertEqual(env.vaultAddr, "")
    XCTAssertEqual(env.vaultCACert, "")
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
  }

  func testVaultEnvironmentEquality() {
    let lhs = VaultEnvironment(vaultAddr: "https://localhost:8200", vaultCACert: "/tmp/ca.pem")
    let rhs = VaultEnvironment(vaultAddr: "https://localhost:8200", vaultCACert: "/tmp/ca.pem")
    XCTAssertEqual(lhs, rhs)
  }

  func testVaultEnvironmentInequality() {
    let lhs = VaultEnvironment(vaultAddr: "https://localhost:8200")
    let rhs = VaultEnvironment(vaultAddr: "https://localhost:8201")
    XCTAssertNotEqual(lhs, rhs)
  }
}
