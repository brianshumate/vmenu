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

private let loopbackHosts: Set<String> = ["127.0.0.1", "localhost", "::1"]

/// Validate and normalize a VAULT_ADDR string.
///
/// Returns a clean `scheme://host` or `scheme://host:port` string
/// reconstructed from the parsed URL components — scheme, host, and port
/// only. Path, query, and fragment from the original string are discarded,
/// so URLs built by appending API paths later can never be polluted by
/// extra components that slipped through validation.
///
/// Returns `nil` if the addr is not a loopback http/https URL.
public func normalizedLoopbackVaultAddr(_ addr: String) -> String? {
  guard let url = URL(string: addr),
        let scheme = url.scheme?.lowercased(),
        scheme == "http" || scheme == "https",
        let host = url.host?.lowercased(),
        loopbackHosts.contains(host)
  else {
    return nil
  }
  // Initialize from the already-parsed URL so URLComponents inherits
  // the correct internal representation (including IPv6 brackets), then
  // strip everything except scheme, host, and port.
  // Do not reassign `host` — URLComponents initialized from a URL with
  // "[::1]" carries the bracket form internally; setting host = "::1"
  // (the bare value URL.host returns) drops the brackets and breaks
  // the IPv6 URL string.
  guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
    return nil
  }
  components.scheme = scheme   // normalize case (e.g. HTTPS → https)
  components.path = ""
  components.query = nil
  components.fragment = nil
  components.user = nil
  components.password = nil
  return components.string
}

/// Returns true when `addr` is a loopback http/https URL.
///
/// Delegates to ``normalizedLoopbackVaultAddr(_:)`` so validation logic
/// lives in one place.
public func isLoopbackVaultAddr(_ addr: String) -> Bool {
  normalizedLoopbackVaultAddr(addr) != nil
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
///
/// Matching rules:
/// - Each pattern is anchored at the start of the line (after stripping
///   leading whitespace) so that commented examples or prose that contains
///   the keyword as a substring are ignored.
/// - Values are trimmed with `.whitespacesAndNewlines` unioned with quote
///   characters so that CRLF line endings, surrounding shell quotes, and
///   stray whitespace are all stripped in one pass.
public func parseEnvironmentVariables(from content: String) -> VaultEnvironment {
  var result = VaultEnvironment()
  let lines = content.components(separatedBy: .newlines)
  var foundAddr = false
  var foundCACert = false
  var foundToken = false
  var foundUnsealKey = false

  let quotesAndWhitespace = CharacterSet(charactersIn: "\"'").union(.whitespacesAndNewlines)

  for line in lines.reversed() {
    let stripped = line.trimmingCharacters(in: .whitespaces)

    if !foundAddr, stripped.hasPrefix("export VAULT_ADDR=") {
      let value = String(stripped.dropFirst("export VAULT_ADDR=".count))
        .trimmingCharacters(in: quotesAndWhitespace)
      if !value.isEmpty {
        result.vaultAddr = value
        foundAddr = true
      }
    }
    if !foundCACert, stripped.hasPrefix("export VAULT_CACERT=") {
      let value = String(stripped.dropFirst("export VAULT_CACERT=".count))
        .trimmingCharacters(in: quotesAndWhitespace)
      if !value.isEmpty {
        result.vaultCACert = value
        foundCACert = true
      }
    }
    if !foundToken, stripped.hasPrefix("Root Token:") {
      let token = String(stripped.dropFirst("Root Token:".count))
        .trimmingCharacters(in: .whitespacesAndNewlines)
      if !token.isEmpty {
        result.vaultToken = token
        foundToken = true
      }
    }
    if !foundUnsealKey, stripped.hasPrefix("Unseal Key:") {
      let key = String(stripped.dropFirst("Unseal Key:".count))
        .trimmingCharacters(in: .whitespacesAndNewlines)
      if !key.isEmpty {
        result.unsealKey = key
        foundUnsealKey = true
      }
    }
    if foundAddr && foundCACert && foundToken && foundUnsealKey { break }
  }

  return result
}
