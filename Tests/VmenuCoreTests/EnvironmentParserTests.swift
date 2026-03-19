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

  // MARK: - isLoopbackVaultAddr tests

  func testLoopback127001() {
    XCTAssertTrue(isLoopbackVaultAddr("https://127.0.0.1:8200"))
  }

  func testLoopbackLocalhost() {
    XCTAssertTrue(isLoopbackVaultAddr("https://localhost:8200"))
  }

  func testLoopbackIPv6() {
    XCTAssertTrue(isLoopbackVaultAddr("https://[::1]:8200"))
  }

  func testLoopbackHTTP() {
    XCTAssertTrue(isLoopbackVaultAddr("http://127.0.0.1:8200"))
  }

  func testLoopbackLocalhostNoPort() {
    XCTAssertTrue(isLoopbackVaultAddr("https://localhost"))
  }

  func testNonLoopbackRemoteHost() {
    XCTAssertFalse(isLoopbackVaultAddr("https://evil.example.com:8200"))
  }

  func testNonLoopbackPrivateIP() {
    XCTAssertFalse(isLoopbackVaultAddr("https://10.0.1.50:8200"))
  }

  func testNonLoopbackPublicIP() {
    XCTAssertFalse(isLoopbackVaultAddr("https://203.0.113.1:8200"))
  }

  func testNonLoopbackEmptyString() {
    XCTAssertFalse(isLoopbackVaultAddr(""))
  }

  func testNonLoopbackGarbageString() {
    XCTAssertFalse(isLoopbackVaultAddr("not-a-url"))
  }

  func testNonLoopbackFTPScheme() {
    XCTAssertFalse(isLoopbackVaultAddr("ftp://127.0.0.1:8200"))
  }

  func testNonLoopbackNoScheme() {
    XCTAssertFalse(isLoopbackVaultAddr("127.0.0.1:8200"))
  }

  func testLoopbackLocalhostUppercase() {
    XCTAssertTrue(isLoopbackVaultAddr("HTTPS://LOCALHOST:8200"))
  }

  func testNonLoopback192168() {
    XCTAssertFalse(isLoopbackVaultAddr("https://192.168.1.1:8200"))
  }

  // MARK: - isValidVaultToken tests

  func testValidTokenDevRoot() {
    XCTAssertTrue(isValidVaultToken("root"))
  }

  func testValidTokenLegacyFormat() {
    XCTAssertTrue(isValidVaultToken("s.abcdef123456"))
  }

  func testValidTokenModernFormat() {
    XCTAssertTrue(isValidVaultToken("hvs.CAESIJmAshSNMsfGUxPeH5PBc"))
  }

  func testValidTokenBatchFormat() {
    XCTAssertTrue(isValidVaultToken("hvb.AAAAAQKnM2E4YjFjYy0zOGZl"))
  }

  func testValidTokenWithHyphens() {
    XCTAssertTrue(isValidVaultToken("s.some-long-token-value"))
  }

  func testInvalidTokenEmpty() {
    XCTAssertFalse(isValidVaultToken(""))
  }

  func testInvalidTokenWithControlChars() {
    XCTAssertFalse(isValidVaultToken("root\u{00}injected"))
  }

  func testInvalidTokenWithNewline() {
    XCTAssertFalse(isValidVaultToken("root\ninjected"))
  }

  func testInvalidTokenWithTab() {
    XCTAssertFalse(isValidVaultToken("root\tinjected"))
  }

  func testInvalidTokenWithSpace() {
    XCTAssertFalse(isValidVaultToken("root injected"))
  }

  func testInvalidTokenWithNonASCII() {
    XCTAssertFalse(isValidVaultToken("root\u{FF}injected"))
  }

  func testInvalidTokenTooLong() {
    let longToken = String(repeating: "a", count: 513)
    XCTAssertFalse(isValidVaultToken(longToken))
  }

  func testValidTokenAtMaxLength() {
    let maxToken = String(repeating: "a", count: 512)
    XCTAssertTrue(isValidVaultToken(maxToken))
  }

  func testTokenWithShellMetacharsAccepted() {
    // Shell metacharacters are printable ASCII. Since tokens are only
    // displayed in SwiftUI Text views and copied to NSPasteboard (never
    // passed to a shell), they don't pose a risk and are accepted.
    XCTAssertTrue(isValidVaultToken("root$(whoami)"))
  }

  // MARK: - isValidVaultUnsealKey tests

  func testValidUnsealKeyBase64() {
    XCTAssertTrue(isValidVaultUnsealKey("GDz8cL2gACZJAByboalN3e0BFpqAmwNCJ3Tve5Evac0="))
  }

  func testValidUnsealKeyBase64WithPlus() {
    XCTAssertTrue(isValidVaultUnsealKey("abc+def/ghi="))
  }

  func testValidUnsealKeyAlphanumericOnly() {
    XCTAssertTrue(isValidVaultUnsealKey("abc123def456"))
  }

  func testInvalidUnsealKeyEmpty() {
    XCTAssertFalse(isValidVaultUnsealKey(""))
  }

  func testInvalidUnsealKeyWithControlChars() {
    XCTAssertFalse(isValidVaultUnsealKey("abc\u{00}def"))
  }

  func testInvalidUnsealKeyWithNewline() {
    XCTAssertFalse(isValidVaultUnsealKey("abc\ndef"))
  }

  func testInvalidUnsealKeyWithSpace() {
    XCTAssertFalse(isValidVaultUnsealKey("abc def"))
  }

  func testInvalidUnsealKeyWithDot() {
    // Base64 does not include dots
    XCTAssertFalse(isValidVaultUnsealKey("abc.def"))
  }

  func testInvalidUnsealKeyWithShellMetachars() {
    XCTAssertFalse(isValidVaultUnsealKey("abc$(whoami)"))
  }

  func testInvalidUnsealKeyTooLong() {
    let longKey = String(repeating: "A", count: 513)
    XCTAssertFalse(isValidVaultUnsealKey(longKey))
  }

  func testValidUnsealKeyAtMaxLength() {
    let maxKey = String(repeating: "A", count: 512)
    XCTAssertTrue(isValidVaultUnsealKey(maxKey))
  }

  func testInvalidUnsealKeyWithNonASCII() {
    XCTAssertFalse(isValidVaultUnsealKey("abc\u{FF}def"))
  }

  func testTokenWithBacktickAccepted() {
    // Backticks are printable ASCII. Tokens are never evaluated by a
    // shell, so this is safe and accepted.
    XCTAssertTrue(isValidVaultToken("`whoami`"))
  }

  func testInvalidUnsealKeyWithHyphen() {
    // Hyphens are not in the base64 alphabet
    XCTAssertFalse(isValidVaultUnsealKey("abc-def"))
  }
}
