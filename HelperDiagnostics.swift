import AppKit
import OSLog
import Security
import ServiceManagement

/// Unified logger for the diagnostics module.
private let logger = Logger(subsystem: "com.brianshumate.vmenu", category: "diagnostics")

/// Thread-safe storage for verbose logging flag.
/// Using an actor-independent approach so XPCClient can read it without
/// crossing actor boundaries.
final class VerboseLoggingStorage: @unchecked Sendable {
  private var _enabled = false
  private let lock = NSLock()

  var enabled: Bool {
    get {
      lock.lock()
      defer { lock.unlock() }
      return _enabled
    }
    set {
      lock.lock()
      defer { lock.unlock() }
      _enabled = newValue
    }
  }
}

/// Global verbose logging storage accessible from any isolation context.
let verboseLoggingStorage = VerboseLoggingStorage()

/// Collects diagnostic information about the XPC helper for troubleshooting.
///
/// Use `HelperDiagnostics.collect()` to gather all relevant diagnostic data,
/// then inspect `HelperDiagnostics.shared.report` for a human-readable summary
/// or access individual properties programmatically.
@MainActor
final class HelperDiagnostics: @unchecked Sendable {
  static let shared = HelperDiagnostics()

  /// Whether verbose diagnostic logging is enabled.
  /// When enabled, XPC operations log detailed debug information to Console.app.
  /// Toggle via "Diagnose Helper" in the menu or set programmatically.
  ///
  /// This property is backed by thread-safe storage so it can be read from
  /// any isolation context (needed by XPCClient which is not @MainActor).
  static var verboseLoggingEnabled: Bool {
    get { verboseLoggingStorage.enabled }
    set { verboseLoggingStorage.enabled = newValue }
  }

  // MARK: - Diagnostic Data

  struct DiagnosticReport: Sendable {
    let timestamp: Date
    let macOSVersion: String
    let macOSMajorVersion: Int
    let appBundlePath: String
    let appBundleIdentifier: String?
    let isInApplicationsFolder: Bool
    let helperBundlePath: String
    let helperExists: Bool
    let helperCodeSigningStatus: String
    let helperTeamID: String?
    let isAdHocSigned: Bool
    let smAppServiceStatus: String
    let xpcConnectionStatus: String
    let lastXPCError: String?
    let launchdHelperPlistExists: Bool
    let suggestedActions: [String]

    var formattedReport: String {
      var lines: [String] = []
      lines.append("=== vmenu Helper Diagnostics ===")
      lines.append("Timestamp: \(ISO8601DateFormatter().string(from: timestamp))")
      lines.append("")
      lines.append("--- System ---")
      lines.append("macOS Version: \(macOSVersion)")
      lines.append("Stricter Launch Constraints: \(macOSMajorVersion >= 26 ? "Yes (macOS 26+)" : "No")")
      lines.append("")
      lines.append("--- App Bundle ---")
      lines.append("Bundle Path: \(appBundlePath)")
      lines.append("Bundle ID: \(appBundleIdentifier ?? "nil")")
      lines.append("In /Applications: \(isInApplicationsFolder ? "✓ Yes" : "✗ No")")
      lines.append("")
      lines.append("--- Helper Binary ---")
      lines.append("Helper Path: \(helperBundlePath)")
      lines.append("Helper Exists: \(helperExists ? "✓ Yes" : "✗ No")")
      lines.append("Code Signing: \(helperCodeSigningStatus)")
      lines.append("Team ID: \(helperTeamID ?? "none (ad-hoc)")")
      lines.append("Ad-hoc Signed: \(isAdHocSigned ? "Yes" : "No")")
      lines.append("")
      lines.append("--- Service Status ---")
      lines.append("SMAppService Status: \(smAppServiceStatus)")
      lines.append("XPC Connection: \(xpcConnectionStatus)")
      if let error = lastXPCError {
        lines.append("Last XPC Error: \(error)")
      }
      lines.append("Embedded LaunchAgent Plist: \(launchdHelperPlistExists ? "✓ Found" : "✗ Not found")")
      lines.append("")
      if !suggestedActions.isEmpty {
        lines.append("--- Suggested Actions ---")
        for (index, action) in suggestedActions.enumerated() {
          lines.append("\(index + 1). \(action)")
        }
      }
      return lines.joined(separator: "\n")
    }
  }

  private(set) var lastReport: DiagnosticReport?
  private(set) var lastXPCError: String?

  func recordXPCError(_ error: Error) {
    let nsError = error as NSError
    lastXPCError = "domain=\(nsError.domain) code=\(nsError.code) - \(error.localizedDescription)"
    logger.error("[DIAG] XPC Error recorded: \(self.lastXPCError ?? "unknown", privacy: .public)")
  }

  // MARK: - Helper Code Signing Check

  /// Result of checking the helper binary's code signature.
  private struct CodeSigningResult {
    let status: String
    let teamID: String?
    let isAdHoc: Bool
  }

  /// Check the code signing status of the helper binary.
  private func checkCodeSigning(helperPath: String, helperExists: Bool) -> CodeSigningResult {
    guard helperExists else {
      return CodeSigningResult(status: "Helper binary not found", teamID: nil, isAdHoc: false)
    }

    var staticCode: SecStaticCode?
    let url = URL(fileURLWithPath: helperPath)
    let createStatus = SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode)

    guard createStatus == errSecSuccess, let code = staticCode else {
      return CodeSigningResult(
        status: "Error creating static code (status: \(createStatus))",
        teamID: nil,
        isAdHoc: false
      )
    }

    var signingInfo: CFDictionary?
    let infoStatus = SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &signingInfo)

    guard infoStatus == errSecSuccess, let info = signingInfo as? [String: Any] else {
      return CodeSigningResult(
        status: "Error reading signing info (status: \(infoStatus))",
        teamID: nil,
        isAdHoc: false
      )
    }

    var status = "Unknown"
    if let identifier = info[kSecCodeInfoIdentifier as String] as? String {
      status = "Signed (id: \(identifier))"
    }

    let teamID = info[kSecCodeInfoTeamIdentifier as String] as? String
    var isAdHoc = false

    if let flags = info[kSecCodeInfoFlags as String] as? UInt32 {
      isAdHoc = (flags & 0x0002) != 0
      if isAdHoc {
        status += " [ad-hoc]"
      }
    }

    return CodeSigningResult(status: status, teamID: teamID, isAdHoc: isAdHoc)
  }

  // MARK: - Suggested Actions Builder

  /// Build list of suggested actions based on diagnostic findings.
  private func buildSuggestedActions(
    isInApplications: Bool,
    osVersion: OperatingSystemVersion,
    helperExists: Bool,
    isAdHoc: Bool,
    smStatus: String
  ) -> [String] {
    var actions: [String] = []

    if !isInApplications && osVersion.majorVersion >= 26 {
      actions.append("Move vmenu.app to /Applications (required on macOS 26+ for ad-hoc signed helpers)")
    }

    if !helperExists {
      actions.append("Helper binary missing — reinstall vmenu")
    }

    if isAdHoc && osVersion.majorVersion >= 26 {
      actions.append("For development: run 'sudo systemextensionsctl developer on'")
      actions.append("For production: sign with Developer ID")
    }

    if smStatus.contains("requires approval") {
      actions.append("Open System Settings > General > Login Items and enable vmenu")
    }

    if smStatus.contains("not registered") {
      actions.append("Try quitting and relaunching vmenu")
    }

    if lastXPCError != nil {
      actions.append("Check Console.app for 'com.brianshumate.vmenu' entries")
      actions.append("Look for 'Launch Constraint Violation' errors")
    }

    return actions
  }

  /// Collect comprehensive diagnostic information.
  ///
  /// This method gathers all relevant data about the helper's state and
  /// returns a structured report. It also logs key findings to Console.app.
  func collect() -> DiagnosticReport {
    logger.info("[DIAG] Collecting helper diagnostics...")

    let osVersion = ProcessInfo.processInfo.operatingSystemVersion
    let macOSVersionString = "\(osVersion.majorVersion).\(osVersion.minorVersion).\(osVersion.patchVersion)"

    let bundlePath = Bundle.main.bundlePath
    let bundleID = Bundle.main.bundleIdentifier
    let isInApplications = bundlePath.hasPrefix("/Applications/")
    let helperPath = "\(bundlePath)/Contents/MacOS/com.brianshumate.vmenu.helper"
    let helperExists = FileManager.default.fileExists(atPath: helperPath)

    // Check helper code signing
    let codeSigningResult = checkCodeSigning(helperPath: helperPath, helperExists: helperExists)

    // Check SMAppService status
    let smStatus = HelperAgentManager.statusDescription

    // Check XPC connection status
    let xpcStatus = XPCClient.shared.hasActiveConnection ? "Active" : "Not connected"

    // Check launchd plist
    let embeddedPlistPath = "\(bundlePath)/Contents/Library/LaunchAgents/com.brianshumate.vmenu.helper.plist"
    let plistExists = FileManager.default.fileExists(atPath: embeddedPlistPath)

    // Build suggested actions
    let actions = buildSuggestedActions(
      isInApplications: isInApplications,
      osVersion: osVersion,
      helperExists: helperExists,
      isAdHoc: codeSigningResult.isAdHoc,
      smStatus: smStatus
    )

    let report = DiagnosticReport(
      timestamp: Date(),
      macOSVersion: macOSVersionString,
      macOSMajorVersion: osVersion.majorVersion,
      appBundlePath: bundlePath,
      appBundleIdentifier: bundleID,
      isInApplicationsFolder: isInApplications,
      helperBundlePath: helperPath,
      helperExists: helperExists,
      helperCodeSigningStatus: codeSigningResult.status,
      helperTeamID: codeSigningResult.teamID,
      isAdHocSigned: codeSigningResult.isAdHoc,
      smAppServiceStatus: smStatus,
      xpcConnectionStatus: xpcStatus,
      lastXPCError: lastXPCError,
      launchdHelperPlistExists: plistExists,
      suggestedActions: actions
    )

    lastReport = report

    // Log key findings
    logger.info("[DIAG] macOS: \(macOSVersionString), In /Applications: \(isInApplications), Helper exists: \(helperExists)")
    logger.info("[DIAG] SMAppService: \(smStatus, privacy: .public), Ad-hoc: \(codeSigningResult.isAdHoc)")
    if !actions.isEmpty {
      logger.warning("[DIAG] Suggested actions: \(actions.joined(separator: "; "), privacy: .public)")
    }

    return report
  }

  /// Run diagnostics and copy the report to the clipboard.
  func collectAndCopyToClipboard() {
    let report = collect()
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(report.formattedReport, forType: .string)
    logger.info("[DIAG] Diagnostic report copied to clipboard")
  }

  /// Check if launchd knows about the helper service.
  ///
  /// Uses `launchctl print` to check if the service is registered in the
  /// current user's GUI domain.
  func checkLaunchdServiceStatus() -> (registered: Bool, output: String) {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/bin/launchctl")
    let uid = getuid()
    task.arguments = ["print", "gui/\(uid)/com.brianshumate.vmenu.helper"]

    let pipe = Pipe()
    task.standardOutput = pipe
    task.standardError = pipe

    do {
      try task.run()
      task.waitUntilExit()
      let data = pipe.fileHandleForReading.readDataToEndOfFile()
      let output = String(data: data, encoding: .utf8) ?? ""
      let registered = task.terminationStatus == 0
      return (registered, output)
    } catch {
      return (false, "Failed to run launchctl: \(error.localizedDescription)")
    }
  }
}
