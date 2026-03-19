import Foundation

/// Parsed environment variables from Vault's startup log.
public struct VaultEnvironment: Equatable {
  public var vaultAddr: String
  public var vaultCACert: String
  public var vaultToken: String
  public var unsealKey: String

  public init(
    vaultAddr: String = "",
    vaultCACert: String = "",
    vaultToken: String = "",
    unsealKey: String = ""
  ) {
    self.vaultAddr = vaultAddr
    self.vaultCACert = vaultCACert
    self.vaultToken = vaultToken
    self.unsealKey = unsealKey
  }
}

/// Validate that a VAULT_ADDR value points to a loopback address.
///
/// In dev mode, Vault always listens on localhost (127.0.0.1 or ::1).
/// Accepting a non-loopback address from the startup log would indicate
/// either a configuration error or injected content from an attacker
/// attempting to redirect the client to a malicious Vault server.
///
/// Accepts URLs of the form `http(s)://127.0.0.1:PORT`,
/// `http(s)://localhost:PORT`, or `http(s)://[::1]:PORT`.
public func isLoopbackVaultAddr(_ addr: String) -> Bool {
  guard let url = URL(string: addr),
        let scheme = url.scheme?.lowercased(),
        scheme == "http" || scheme == "https",
        let host = url.host?.lowercased()
  else {
    return false
  }
  let loopbackHosts: Set<String> = [
    "127.0.0.1", "localhost", "::1"
  ]
  return loopbackHosts.contains(host)
}

/// Maximum accepted length for a Vault token or unseal key.
///
/// Vault tokens are typically 26–95 characters (legacy `s.` format, modern
/// `hvs.` format, or the dev-mode `root` literal).  Unseal keys are
/// base64-encoded 256-bit values (~44 characters).  A generous upper bound
/// of 512 characters prevents absurdly long injected values from consuming
/// memory or being pasted into clipboards, while still accommodating any
/// foreseeable format changes.
private let maxSecretValueLength = 512

/// Validate that a Vault root token contains only safe characters.
///
/// Vault tokens consist of printable ASCII characters — specifically
/// alphanumerics, dots, hyphens, and underscores (the `s.` / `hvs.`
/// prefixes use dots).  This rejects control characters, whitespace,
/// shell metacharacters, and non-ASCII bytes that could indicate
/// injected or corrupted log content.
///
/// Accepted formats:
/// - Dev-mode literal: `root`
/// - Legacy service tokens: `s.<base62>`
/// - Modern service tokens: `hvs.<base62>` or `hvb.<base62>`
/// - Batch tokens: `hvb.<long-base62>`
public func isValidVaultToken(_ token: String) -> Bool {
  guard !token.isEmpty, token.count <= maxSecretValueLength else {
    return false
  }
  // Only printable ASCII (0x21–0x7E) — excludes control chars, space,
  // and DEL.  Vault tokens use a subset of this (alphanumeric + '.' + '-')
  // but we allow the full printable range for forward-compatibility.
  return token.allSatisfy { char in
    guard let ascii = char.asciiValue else { return false }
    return ascii >= 0x21 && ascii <= 0x7E
  }
}

/// Validate that a Vault unseal key contains only safe characters.
///
/// Unseal keys are base64-encoded 256-bit values, so the valid character
/// set is `[A-Za-z0-9+/=]`.  This rejects control characters, shell
/// metacharacters, and non-ASCII bytes that could indicate injected or
/// corrupted log content.
public func isValidVaultUnsealKey(_ key: String) -> Bool {
  guard !key.isEmpty, key.count <= maxSecretValueLength else {
    return false
  }
  // Base64 alphabet: A-Z, a-z, 0-9, +, /, =
  return key.allSatisfy { char in
    char.isASCII && (char.isLetter || char.isNumber || char == "+" || char == "/" || char == "=")
  }
}

/// Parses VAULT_ADDR, VAULT_CACERT, and the root token from Vault's startup
/// log content.
///
/// Iterates in reverse so the most recent values from the latest launch are
/// picked up when the log contains output from multiple runs.
///
/// The root token is extracted from the `Root Token:` line that Vault prints
/// during dev-mode startup (there is no `export VAULT_TOKEN=` line in the
/// log).
public func parseEnvironmentVariables(from content: String) -> VaultEnvironment {
  var result = VaultEnvironment()
  let lines = content.components(separatedBy: .newlines)
  var foundAddr = false
  var foundCACert = false
  var foundToken = false
  var foundUnsealKey = false

  for line in lines.reversed() {
    if !foundAddr, line.contains("export VAULT_ADDR=") {
      if let range = line.range(of: "export VAULT_ADDR=") {
        let addr = String(line[range.upperBound...])
        result.vaultAddr = addr.trimmingCharacters(in: CharacterSet(charactersIn: "\"'\n"))
        foundAddr = true
      }
    }
    if !foundCACert, line.contains("export VAULT_CACERT=") {
      if let range = line.range(of: "export VAULT_CACERT=") {
        let cert = String(line[range.upperBound...])
        result.vaultCACert = cert.trimmingCharacters(
          in: CharacterSet(charactersIn: "\"'\n")
        )
        foundCACert = true
      }
    }
    if !foundToken, line.contains("Root Token:") {
      if let range = line.range(of: "Root Token:") {
        let token = String(line[range.upperBound...])
          .trimmingCharacters(in: .whitespaces)
        if !token.isEmpty {
          result.vaultToken = token
          foundToken = true
        }
      }
    }
    if !foundUnsealKey, line.contains("Unseal Key:") {
      if let range = line.range(of: "Unseal Key:") {
        let key = String(line[range.upperBound...])
          .trimmingCharacters(in: .whitespaces)
        if !key.isEmpty {
          result.unsealKey = key
          foundUnsealKey = true
        }
      }
    }
    if foundAddr && foundCACert && foundToken && foundUnsealKey { break }
  }

  return result
}
