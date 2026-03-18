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
