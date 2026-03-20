import Foundation
import OSLog
import Security
import VmenuCore
import VmenuXPCProtocol

/// Unified logger for the XPC helper agent.
///
/// Uses `os_log` via the `Logger` API so messages go through the unified
/// logging system with proper privacy annotations instead of `print()`.
private let logger = Logger(subsystem: "com.brianshumate.vmenu.helper", category: "helper")

// MARK: - Helper Delegate

/// XPC listener delegate that creates connection handlers for each
/// incoming connection from the main app.
///
/// Validates that the connecting process is signed by the same team
/// before accepting the connection.  This prevents arbitrary local
/// processes from invoking privileged helper operations (launchctl,
/// file I/O, token/key access) simply by knowing the Mach service name.
final class HelperDelegate: NSObject, NSXPCListenerDelegate {

  /// Code-signing requirement that the connecting process must satisfy.
  ///
  /// The requirement enforces:
  /// 1. The process is signed with a valid Apple code signature.
  /// 2. The signing identifier matches the main app bundle ID.
  /// 3. For distribution builds, the signing certificate's Team ID
  ///    matches (prevents a different developer from signing a binary
  ///    with the same bundle identifier).
  ///
  /// To pin to a specific team for distribution builds, replace the
  /// empty string below with your 10-character Apple Team ID (e.g.
  /// "A1B2C3D4E5").  The Xcode project can inject this via a
  /// `VMENU_TEAM_ID` build setting and `GCC_PREPROCESSOR_DEFINITIONS`.
  private static let teamID = ""

  private static let signingRequirement: String = {
    let base = "identifier \"com.brianshumate.vmenu\" and anchor apple generic"
    if !teamID.isEmpty {
      return base + " and certificate leaf[subject.OU] = \"\(teamID)\""
    }
    return base
  }()

  func listener(
    _ listener: NSXPCListener,
    shouldAcceptNewConnection newConnection: NSXPCConnection
  ) -> Bool {
    // Validate the connecting process is our main app by checking its
    // code-signing identity.  Reject connections that do not satisfy
    // the requirement — this prevents local privilege escalation
    // through the helper's Mach service.
    if !validateConnection(newConnection) {
      logger.error("Rejecting XPC connection — code-signing requirement not met (pid \(newConnection.processIdentifier))")
      newConnection.invalidate()
      return false
    }

    let interface = NSXPCInterface(with: VmenuHelperProtocol.self)
    newConnection.exportedInterface = interface
    newConnection.exportedObject = HelperHandler()
    newConnection.resume()
    return true
  }

  /// Check the connecting process against the code-signing requirement.
  ///
  /// Uses `SecCodeCopyGuestWithAttributes` to obtain the code object for
  /// the connecting PID, then evaluates it against the compiled
  /// requirement string.
  private func validateConnection(_ connection: NSXPCConnection) -> Bool {
    let pid = connection.processIdentifier

    // Obtain the SecCode for the connecting process.
    var codeRef: SecCode?
    let attrs = [kSecGuestAttributePid: pid] as CFDictionary
    guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &codeRef) == errSecSuccess,
          let code = codeRef
    else {
      return false
    }

    // Compile the requirement string.
    var requirementRef: SecRequirement?
    guard SecRequirementCreateWithString(
      Self.signingRequirement as CFString,
      [],
      &requirementRef
    ) == errSecSuccess,
          let requirement = requirementRef
    else {
      return false
    }

    // Evaluate the code against the requirement.
    return SecCodeCheckValidity(code, [], requirement) == errSecSuccess
  }
}

// MARK: - Helper Handler

/// Implements the XPC protocol by performing the actual privileged
/// operations: launchctl commands, file I/O outside the sandbox, and
/// vault binary discovery.
final class HelperHandler: NSObject, VmenuHelperProtocol {

  // MARK: - Constants

  private let plistLabel = "com.hashicorp.vault"

  private var plistURL: URL {
    FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent("Library/LaunchAgents/com.hashicorp.vault.plist")
  }

  private var logDir: URL {
    FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent("Library/Logs/vmenu")
  }

  private var startupLogURL: URL {
    logDir.appendingPathComponent("vault.startup.log")
  }

  private var operationsLogURL: URL {
    logDir.appendingPathComponent("vault.operations.log")
  }

  private var domainTarget: String {
    "gui/\(getuid())"
  }

  private var serviceTarget: String {
    "\(domainTarget)/\(plistLabel)"
  }

  private static let macOSMajorVersion: Int = {
    ProcessInfo.processInfo.operatingSystemVersion.majorVersion
  }()

  private static let usesModernLaunchctl: Bool = {
    macOSMajorVersion >= 13
  }()

  // MARK: - Vault binary discovery

  func findVaultPath(withReply reply: @escaping (String?) -> Void) {
    reply(locateVaultBinary())
  }

  private func locateVaultBinary() -> String? {
    let fileManager = FileManager.default
    let home = fileManager.homeDirectoryForCurrentUser.path

    let candidates = [
      "\(home)/bin/vault",
      "/opt/homebrew/bin/vault",
      "/usr/local/bin/vault",
      "/opt/homebrew/sbin/vault",
      "/usr/local/sbin/vault",
      "\(home)/.local/bin/vault",
      "/opt/local/bin/vault"
    ]

    for path in candidates where fileManager.isExecutableFile(atPath: path) {
      return path
    }

    // Fallback: use /usr/bin/which with an explicit broad PATH.
    return loginShellWhich("vault")
  }

  private func loginShellWhich(_ binary: String) -> String? {
    let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_"))
    guard !binary.isEmpty,
          binary.unicodeScalars.allSatisfy({ allowed.contains($0) })
    else {
      return nil
    }

    let home = FileManager.default.homeDirectoryForCurrentUser.path
    let searchPATH = [
      "\(home)/bin",
      "\(home)/.local/bin",
      "/opt/homebrew/bin",
      "/opt/homebrew/sbin",
      "/usr/local/bin",
      "/usr/local/sbin",
      "/opt/local/bin",
      "/usr/bin",
      "/usr/sbin",
      "/bin",
      "/sbin"
    ].joined(separator: ":")

    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/usr/bin/which")
    task.arguments = [binary]
    task.environment = ["PATH": searchPATH]

    let pipe = Pipe()
    task.standardOutput = pipe
    task.standardError = FileHandle.nullDevice

    do {
      try task.run()
      task.waitUntilExit()
      if task.terminationStatus == 0 {
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let path = String(data: data, encoding: .utf8)?
          .trimmingCharacters(in: .whitespacesAndNewlines)
        if let path, !path.isEmpty, path.hasPrefix("/"),
           FileManager.default.isExecutableFile(atPath: path) {
          return path
        }
      }
    } catch {
      // Ignore – caller will get nil.
    }
    return nil
  }

  // MARK: - LaunchAgent lifecycle

  func createOrUpdatePlist(withReply reply: @escaping (Bool) -> Void) {
    reply(performCreateOrUpdatePlist())
  }

  func bootstrapService(withReply reply: @escaping (Bool) -> Void) {
    reply(performBootstrap())
  }

  func bootoutService(withReply reply: @escaping (Bool) -> Void) {
    reply(performBootout())
  }

  func kickstartService(withReply reply: @escaping (Bool) -> Void) {
    reply(performKickstart())
  }

  func checkServiceStatus(withReply reply: @escaping (Bool) -> Void) {
    if Self.usesModernLaunchctl {
      let (success, _) = runLaunchctl(["print", serviceTarget])
      reply(success)
    } else {
      let (success, _) = runLaunchctl(["list", plistLabel])
      reply(success)
    }
  }

  // MARK: - Log file operations

  func readStartupLog(withReply reply: @escaping (String?) -> Void) {
    reply(safeReadLogFile(at: startupLogURL))
  }

  func recreateStartupLog(withReply reply: @escaping (Bool) -> Void) {
    guard ensureLogDirectory() else {
      reply(false)
      return
    }
    reply(safeRecreateLogFile(at: startupLogURL))
  }

  // MARK: - CA certificate operations

  func readCACertData(atPath path: String, withReply reply: @escaping (Data?) -> Void) {
    guard !path.isEmpty else {
      reply(nil)
      return
    }
    // Use the TOCTOU-safe reader that opens with O_NOFOLLOW and validates
    // ownership/permissions via fstat() on the same file descriptor,
    // eliminating the race window between validation and reading.
    guard let data = VmenuCore.safeReadCACertData(path) else {
      logger.warning("Refusing to read CA cert — failed safe read (path validation, symlink, permissions, or I/O error): \(path, privacy: .private)")
      reply(nil)
      return
    }
    reply(data)
  }

  func removeCACertFile(atPath path: String, withReply reply: @escaping (Bool) -> Void) {
    guard !path.isEmpty else {
      reply(false)
      return
    }
    guard FileManager.default.fileExists(atPath: path) else {
      reply(true) // Already gone — success.
      return
    }
    // Validate the path string (absolute, not in unsafe dirs).
    guard VmenuCore.validateCACertPath(path) else {
      logger.warning("Refusing to remove — failed path validation: \(path, privacy: .private)")
      reply(false)
      return
    }
    // Open with O_NOFOLLOW to atomically reject symlinks, then fstat the
    // descriptor to verify ownership and type on the *actual* file we
    // opened — eliminating the TOCTOU window between validation and
    // deletion that the previous lstat + removeItem approach had.
    let fd = open(path, O_RDONLY | O_NOFOLLOW)
    guard fd >= 0 else {
      if errno == ELOOP {
        logger.warning("Refusing to remove — path is a symbolic link: \(path, privacy: .private)")
      } else {
        logger.warning("Refusing to remove — cannot open file: \(path, privacy: .private)")
      }
      reply(false)
      return
    }
    // Capture the inode of the file we validated.
    var statBuf = stat()
    guard fstat(fd, &statBuf) == 0 else {
      close(fd)
      reply(false)
      return
    }
    close(fd)
    let validatedInode = statBuf.st_ino
    let validatedDevice = statBuf.st_dev
    // Verify it is a regular file, owned by us or root, not group/world-writable.
    guard (statBuf.st_mode & S_IFMT) == S_IFREG else {
      logger.warning("Refusing to remove — not a regular file: \(path, privacy: .private)")
      reply(false)
      return
    }
    let currentUID = getuid()
    guard statBuf.st_uid == currentUID || statBuf.st_uid == 0 else {
      logger.warning("Refusing to remove — not owned by current user or root: \(path, privacy: .private)")
      reply(false)
      return
    }
    if (statBuf.st_mode & S_IWGRP) != 0 || (statBuf.st_mode & S_IWOTH) != 0 {
      logger.warning("Refusing to remove — group or world writable: \(path, privacy: .private)")
      reply(false)
      return
    }
    // Re-lstat immediately before unlink and verify the inode matches,
    // narrowing the TOCTOU window to the minimum possible without
    // resorting to unlinkat on a parent directory fd.
    var preBuf = stat()
    guard lstat(path, &preBuf) == 0,
          preBuf.st_ino == validatedInode,
          preBuf.st_dev == validatedDevice,
          (preBuf.st_mode & S_IFMT) == S_IFREG
    else {
      logger.warning("Refusing to remove — file changed between validation and removal: \(path, privacy: .private)")
      reply(false)
      return
    }
    guard unlink(path) == 0 else {
      let err = String(cString: strerror(errno))
      logger.error("Failed to remove CA cert: \(err, privacy: .public)")
      reply(false)
      return
    }
    reply(true)
  }

  // MARK: - Private helpers

  private func runLaunchctl(_ arguments: [String]) -> (Bool, Int32) {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/bin/launchctl")
    task.arguments = arguments
    let pipe = Pipe()
    task.standardOutput = pipe
    task.standardError = pipe
    do {
      try task.run()
      task.waitUntilExit()
      return (task.terminationStatus == 0, task.terminationStatus)
    } catch {
      return (false, -1)
    }
  }

  private func performBootout() -> Bool {
    if Self.usesModernLaunchctl {
      let (_, status) = runLaunchctl(["bootout", serviceTarget])
      return status == 0 || status == 3 || status == 113
    } else {
      let (success, _) = runLaunchctl(["unload", plistURL.path])
      return success
    }
  }

  private func performBootstrap() -> Bool {
    if Self.usesModernLaunchctl {
      let (success, _) = runLaunchctl(["bootstrap", domainTarget, plistURL.path])
      return success
    } else {
      let (success, _) = runLaunchctl(["load", plistURL.path])
      return success
    }
  }

  private func performKickstart() -> Bool {
    if Self.usesModernLaunchctl {
      let (success, _) = runLaunchctl(["kickstart", serviceTarget])
      return success
    } else {
      let (success, _) = runLaunchctl(["start", plistLabel])
      return success
    }
  }

  /// Build the expected LaunchAgent plist as a dictionary.
  ///
  /// Using `PropertyListSerialization` instead of string interpolation
  /// eliminates any risk of XML injection from path values that might
  /// contain characters like `<`, `>`, `&`, or `"`.
  private func expectedPlistDictionary() -> [String: Any] {
    let vaultPath = locateVaultBinary() ?? "/opt/homebrew/bin/vault"
    return [
      "Label": plistLabel,
      "ProgramArguments": [
        vaultPath,
        "server",
        "-dev",
        "-dev-tls",
      ],
      "RunAtLoad": false,
      "KeepAlive": false,
      "StandardOutPath": startupLogURL.path,
      "StandardErrorPath": operationsLogURL.path,
    ] as [String: Any]
  }

  /// Serialize the plist dictionary to XML data.
  private func serializePlist(_ dict: [String: Any]) -> Data? {
    try? PropertyListSerialization.data(
      fromPropertyList: dict,
      format: .xml,
      options: 0
    )
  }

  private func performCreateOrUpdatePlist() -> Bool {
    guard ensureLogDirectory() else {
      logger.error("vmenu-helper: aborting plist creation — log directory unavailable")
      return false
    }

    let expectedDict = expectedPlistDictionary()
    guard let plistData = serializePlist(expectedDict) else {
      logger.error("vmenu-helper: failed to serialize plist")
      return false
    }

    let launchAgentsDir = FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent("Library/LaunchAgents")
    do {
      try FileManager.default.createDirectory(
        at: launchAgentsDir,
        withIntermediateDirectories: true
      )
    } catch {
      logger.error("vmenu-helper: failed to create LaunchAgents directory: \(error.localizedDescription, privacy: .public)")
      return false
    }

    // Compare against the existing plist structurally (as dictionaries)
    // rather than byte-for-byte, so insignificant formatting differences
    // (e.g. from a different PropertyListSerialization version) don't
    // trigger unnecessary rewrites.
    if FileManager.default.fileExists(atPath: plistURL.path) {
      if let existingData = try? Data(contentsOf: plistURL),
         let existingDict = try? PropertyListSerialization.propertyList(
           from: existingData, format: nil) as? [String: Any],
         NSDictionary(dictionary: existingDict).isEqual(to: expectedDict) {
        return true
      }
      _ = performBootout()
    }

    do {
      try plistData.write(to: plistURL, options: .atomic)
    } catch {
      logger.error("vmenu-helper: failed to write plist: \(error.localizedDescription, privacy: .public)")
      return false
    }

    do {
      try FileManager.default.setAttributes(
        [.posixPermissions: 0o600],
        ofItemAtPath: plistURL.path
      )
    } catch {
      logger.error("vmenu-helper: failed to set plist permissions: \(error.localizedDescription, privacy: .public)")
      try? FileManager.default.removeItem(atPath: plistURL.path)
      return false
    }

    return true
  }

  // MARK: - File safety helpers

  @discardableResult
  private func ensureLogDirectory() -> Bool {
    let fileManager = FileManager.default
    var isDir: ObjCBool = false
    if fileManager.fileExists(atPath: logDir.path, isDirectory: &isDir) {
      return isDir.boolValue
    }
    do {
      try fileManager.createDirectory(
        at: logDir,
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700]
      )
      return true
    } catch {
      logger.error("vmenu-helper: failed to create log directory: \(error.localizedDescription, privacy: .public)")
      return false
    }
  }

  private func isRegularFile(atPath path: String) -> Bool {
    var statBuf = stat()
    guard lstat(path, &statBuf) == 0 else { return false }
    return (statBuf.st_mode & S_IFMT) == S_IFREG
  }

  /// Maximum log file size (2 MiB).
  ///
  /// Vault startup logs are typically a few KiB.  A generous upper bound
  /// prevents reading unexpectedly large files.
  private static let maxLogFileSize: off_t = 2 * 1_024 * 1_024

  private func safeReadLogFile(at url: URL) -> String? {
    let path = url.path

    // Open with O_NOFOLLOW so the call fails atomically if the path is
    // a symlink, then fstat the descriptor to verify the file is regular
    // and within size limits — eliminating the TOCTOU window that the
    // previous lstat + String(contentsOf:) approach had.
    let fd = open(path, O_RDONLY | O_NOFOLLOW)
    guard fd >= 0 else {
      // ENOENT (file doesn't exist yet) is expected before Vault starts.
      if errno != ENOENT {
        logger.error("vmenu-helper: refusing to read \(path) — open failed (errno \(errno))")
      }
      return nil
    }
    defer { close(fd) }

    var statBuf = stat()
    guard fstat(fd, &statBuf) == 0 else { return nil }

    // Must be a regular file.
    guard (statBuf.st_mode & S_IFMT) == S_IFREG else {
      logger.error("vmenu-helper: refusing to read \(path) — not a regular file")
      return nil
    }

    let fileSize = Int(statBuf.st_size)
    guard fileSize >= 0, statBuf.st_size <= Self.maxLogFileSize else {
      logger.error("vmenu-helper: refusing to read \(path) — file too large (\(fileSize) bytes)")
      return nil
    }
    guard fileSize > 0 else { return "" }

    var buffer = Data(count: fileSize)
    let bytesRead = buffer.withUnsafeMutableBytes { rawBuffer -> Int in
      guard let base = rawBuffer.baseAddress else { return 0 }
      return read(fd, base, fileSize)
    }
    guard bytesRead == fileSize else { return nil }

    return String(data: buffer, encoding: .utf8)
  }

  @discardableResult
  private func safeRecreateLogFile(at url: URL) -> Bool {
    let path = url.path

    // If the file already exists, open it with O_NOFOLLOW to reject
    // symlinks atomically, verify it is a regular file via fstat on the
    // same descriptor, then unlink.  This eliminates the TOCTOU window
    // that the previous lstat + FileManager.removeItem approach had.
    let existingFd = open(path, O_RDONLY | O_NOFOLLOW)
    if existingFd >= 0 {
      var statBuf = stat()
      let fstatOK = fstat(existingFd, &statBuf) == 0
      close(existingFd)

      guard fstatOK else {
        logger.error("vmenu-helper: fstat failed for \(path)")
        return false
      }
      guard (statBuf.st_mode & S_IFMT) == S_IFREG else {
        logger.error("vmenu-helper: refusing to recreate \(path) — not a regular file")
        return false
      }

      // Re-lstat and verify inode matches right before unlink to narrow
      // the race window.
      var preBuf = stat()
      guard lstat(path, &preBuf) == 0,
            preBuf.st_ino == statBuf.st_ino,
            preBuf.st_dev == statBuf.st_dev,
            (preBuf.st_mode & S_IFMT) == S_IFREG
      else {
        logger.error("vmenu-helper: refusing to recreate \(path) — file changed between validation and removal")
        return false
      }

      guard unlink(path) == 0 else {
        let err = String(cString: strerror(errno))
        logger.error("vmenu-helper: failed to remove \(path): \(err)")
        return false
      }
    } else if errno != ENOENT {
      // ENOENT is fine (file doesn't exist yet).  ELOOP means it's a
      // symlink — reject.  Any other error is unexpected.
      if errno == ELOOP {
        logger.error("vmenu-helper: refusing to recreate \(path) — path is a symbolic link")
      } else {
        let err = String(cString: strerror(errno))
        logger.error("vmenu-helper: cannot open \(path) for recreation: \(err)")
      }
      return false
    }

    let fileDescriptor = open(path, O_CREAT | O_EXCL | O_WRONLY, 0o600)
    guard fileDescriptor >= 0 else {
      let err = String(cString: strerror(errno))
      logger.error("vmenu-helper: exclusive create of \(path) failed: \(err)")
      return false
    }
    close(fileDescriptor)
    return true
  }
}

// MARK: - Main entry point

let delegate = HelperDelegate()
let listener = NSXPCListener(machServiceName: vmenuHelperMachServiceName)
listener.delegate = delegate
listener.resume()

// Run the run loop forever. The helper is a long-running agent managed by
// SMAppService. It will be started automatically when the main app is
// launched and can be stopped when the app terminates.
RunLoop.current.run()
