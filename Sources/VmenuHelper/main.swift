import Foundation
import VmenuCore
import VmenuXPCProtocol

// MARK: - Helper Delegate

/// XPC listener delegate that creates connection handlers for each
/// incoming connection from the main app.
final class HelperDelegate: NSObject, NSXPCListenerDelegate {
  func listener(
    _ listener: NSXPCListener,
    shouldAcceptNewConnection newConnection: NSXPCConnection
  ) -> Bool {
    // Validate the connecting process is our main app.
    // In a production build you would check the code-signing requirement
    // here. For now we accept connections and rely on the Mach service
    // name being scoped to our app bundle.
    let interface = NSXPCInterface(with: VmenuHelperProtocol.self)
    newConnection.exportedInterface = interface
    newConnection.exportedObject = HelperHandler()
    newConnection.resume()
    return true
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
    guard FileManager.default.fileExists(atPath: path) else {
      reply(nil)
      return
    }
    guard isRegularFile(atPath: path) else {
      print("vmenu-helper: refusing to read \(path) — not a regular file")
      reply(nil)
      return
    }
    guard VmenuCore.validateCACertPath(path) else {
      print("vmenu-helper: refusing to read \(path) — failed path validation")
      reply(nil)
      return
    }
    do {
      let data = try Data(contentsOf: URL(fileURLWithPath: path))
      reply(data)
    } catch {
      print("vmenu-helper: failed to read CA cert \(path): \(error.localizedDescription)")
      reply(nil)
    }
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
    guard isRegularFile(atPath: path) else {
      print("vmenu-helper: refusing to remove \(path) — not a regular file")
      reply(false)
      return
    }
    // Validate the path is safe (not a symlink, not in /tmp, etc.)
    guard VmenuCore.validateCACertPath(path) else {
      print("vmenu-helper: refusing to remove \(path) — failed path validation")
      reply(false)
      return
    }
    do {
      try FileManager.default.removeItem(atPath: path)
      reply(true)
    } catch {
      print("vmenu-helper: failed to remove CA cert \(path): \(error.localizedDescription)")
      reply(false)
    }
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

  private func expectedPlistContent() -> String {
    let vaultPath = locateVaultBinary() ?? "/opt/homebrew/bin/vault"
    return """
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
        <key>Label</key>
        <string>\(plistLabel)</string>
        <key>ProgramArguments</key>
        <array>
            <string>\(vaultPath)</string>
            <string>server</string>
            <string>-dev</string>
            <string>-dev-tls</string>
        </array>
        <key>RunAtLoad</key>
        <false/>
        <key>KeepAlive</key>
        <false/>
        <key>StandardOutPath</key>
        <string>\(startupLogURL.path)</string>
        <key>StandardErrorPath</key>
        <string>\(operationsLogURL.path)</string>
    </dict>
    </plist>
    """
  }

  private func performCreateOrUpdatePlist() -> Bool {
    guard ensureLogDirectory() else {
      print("vmenu-helper: aborting plist creation — log directory unavailable")
      return false
    }

    let plistContent = expectedPlistContent()

    let launchAgentsDir = FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent("Library/LaunchAgents")
    do {
      try FileManager.default.createDirectory(
        at: launchAgentsDir,
        withIntermediateDirectories: true
      )
    } catch {
      print("vmenu-helper: failed to create LaunchAgents directory: \(error.localizedDescription)")
      return false
    }

    if FileManager.default.fileExists(atPath: plistURL.path) {
      if let existing = try? String(contentsOf: plistURL, encoding: .utf8),
         existing == plistContent {
        return true
      }
      _ = performBootout()
    }

    do {
      try plistContent.write(to: plistURL, atomically: true, encoding: .utf8)
    } catch {
      print("vmenu-helper: failed to write plist \(plistURL.path): \(error.localizedDescription)")
      return false
    }

    do {
      try FileManager.default.setAttributes(
        [.posixPermissions: 0o600],
        ofItemAtPath: plistURL.path
      )
    } catch {
      print("vmenu-helper: failed to set plist permissions: \(error.localizedDescription)")
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
      print("vmenu-helper: failed to create log directory: \(error.localizedDescription)")
      return false
    }
  }

  private func isRegularFile(atPath path: String) -> Bool {
    var statBuf = stat()
    guard lstat(path, &statBuf) == 0 else { return false }
    return (statBuf.st_mode & S_IFMT) == S_IFREG
  }

  private func safeReadLogFile(at url: URL) -> String? {
    let path = url.path
    guard FileManager.default.fileExists(atPath: path) else { return nil }
    guard isRegularFile(atPath: path) else {
      print("vmenu-helper: refusing to read \(path) — not a regular file")
      return nil
    }
    return try? String(contentsOf: url, encoding: .utf8)
  }

  @discardableResult
  private func safeRecreateLogFile(at url: URL) -> Bool {
    let path = url.path
    let fileManager = FileManager.default

    if fileManager.fileExists(atPath: path) {
      guard isRegularFile(atPath: path) else {
        print("vmenu-helper: refusing to recreate \(path) — not a regular file")
        return false
      }
      do {
        try fileManager.removeItem(atPath: path)
      } catch {
        print("vmenu-helper: failed to remove \(path): \(error.localizedDescription)")
        return false
      }
    }

    let fileDescriptor = open(path, O_CREAT | O_EXCL | O_WRONLY, 0o600)
    guard fileDescriptor >= 0 else {
      let err = String(cString: strerror(errno))
      print("vmenu-helper: exclusive create of \(path) failed: \(err)")
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
