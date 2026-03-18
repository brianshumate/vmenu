import Foundation

/// Parsed environment variables from Vault's startup log.
public struct VaultEnvironment: Equatable {
    public var vaultAddr: String
    public var vaultCACert: String

    public init(vaultAddr: String = "", vaultCACert: String = "") {
        self.vaultAddr = vaultAddr
        self.vaultCACert = vaultCACert
    }
}

/// Parses VAULT_ADDR and VAULT_CACERT from Vault's startup log content.
///
/// Iterates in reverse so the most recent values from the latest launch are
/// picked up when the log contains output from multiple runs.
public func parseEnvironmentVariables(from content: String) -> VaultEnvironment {
    var result = VaultEnvironment()
    let lines = content.components(separatedBy: .newlines)
    var foundAddr = false
    var foundCACert = false

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
        if foundAddr && foundCACert { break }
    }

    return result
}
