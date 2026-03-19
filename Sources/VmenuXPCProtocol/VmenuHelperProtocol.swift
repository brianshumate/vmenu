import Foundation

/// Mach service name for the XPC helper agent.
///
/// This must match the bundle identifier of the helper agent and the
/// label in its launchd plist (embedded inside the main app bundle at
/// `Contents/Library/LaunchAgents/`).
public let vmenuHelperMachServiceName = "com.brianshumate.vmenu.helper"

/// XPC protocol that the sandboxed main app uses to delegate privileged
/// operations to the unsandboxed helper agent.
///
/// Every method that performs an operation the App Sandbox forbids lives
/// here: process spawning (`launchctl`), file system access outside the
/// sandbox container (plist, logs, CA certs), and `vault` binary
/// discovery.
///
/// All methods use the reply-block pattern required by `NSXPCConnection`.
@objc public protocol VmenuHelperProtocol {

  // MARK: - Vault binary discovery

  /// Locate the `vault` binary on the system.
  /// Replies with the absolute path, or `nil` if not found.
  func findVaultPath(withReply reply: @escaping (String?) -> Void)

  // MARK: - LaunchAgent lifecycle

  /// Create or update the LaunchAgent plist and return success.
  func createOrUpdatePlist(withReply reply: @escaping (Bool) -> Void)

  /// Bootstrap (load) the Vault LaunchAgent into the current user's
  /// GUI domain.
  func bootstrapService(withReply reply: @escaping (Bool) -> Void)

  /// Bootout (unload) the Vault LaunchAgent.
  func bootoutService(withReply reply: @escaping (Bool) -> Void)

  /// Kick-start the Vault LaunchAgent (ensure it is running).
  func kickstartService(withReply reply: @escaping (Bool) -> Void)

  /// Check whether the Vault LaunchAgent service is currently loaded.
  func checkServiceStatus(withReply reply: @escaping (Bool) -> Void)

  // MARK: - Log file operations

  /// Read the Vault startup log and return its contents (or `nil`).
  func readStartupLog(withReply reply: @escaping (String?) -> Void)

  /// Atomically recreate (truncate) the startup log for a fresh Vault
  /// launch.  Returns `true` on success.
  func recreateStartupLog(withReply reply: @escaping (Bool) -> Void)

  // MARK: - CA certificate operations

  /// Read the raw bytes of a CA certificate file so the sandboxed main
  /// app can use them for TLS trust evaluation.  The helper validates
  /// the path before reading.  Replies with the data, or `nil` on failure.
  func readCACertData(atPath path: String, withReply reply: @escaping (Data?) -> Void)

  /// Remove the CA certificate file at the given path.  The helper
  /// validates the path before removal.
  func removeCACertFile(atPath path: String, withReply reply: @escaping (Bool) -> Void)
}
