import AppKit
import SwiftUI
import UserNotifications

struct VaultStatus {
  var sealType: String = "-"
  var initialized: String = "-"
  var sealed: String = "-"
  var totalShares: String = "-"
  var threshold: String = "-"
  var version: String = "-"
  var buildDate: String = "-"
  var storageType: String = "-"
  var clusterName: String = "-"
  var clusterId: String = "-"
  var haEnabled: String = "-"

  static func parse(from output: String) -> VaultStatus {
    var status = VaultStatus()
    let pairs = parseKeyValuePairs(from: output)
    for (key, value) in pairs {
      applyField(key: key, value: value, to: &status)
    }
    return status
  }

  private static func parseKeyValuePairs(from output: String) -> [(String, String)] {
    let lines = output.components(separatedBy: .newlines)
    var pairs: [(String, String)] = []

    for line in lines {
      let trimmed = line.trimmingCharacters(in: .whitespaces)

      if trimmed.isEmpty || trimmed.hasPrefix("Key") || trimmed.hasPrefix("---") {
        continue
      }

      // Split on 2+ consecutive spaces to separate key and value columns
      guard let separatorRange = trimmed.range(
        of: "\\s{2,}",
        options: .regularExpression
      ) else {
        continue
      }

      let key = String(trimmed[trimmed.startIndex..<separatorRange.lowerBound])
        .trimmingCharacters(in: .whitespaces)
      let value = String(trimmed[separatorRange.upperBound...])
        .trimmingCharacters(in: .whitespaces)

      if !key.isEmpty, !value.isEmpty {
        pairs.append((key, value))
      }
    }

    return pairs
  }

  private static func applyField(key: String, value: String, to status: inout VaultStatus) {
    switch key {
    case "Seal Type": status.sealType = value
    case "Initialized": status.initialized = value
    case "Sealed": status.sealed = value
    case "Total Shares": status.totalShares = value
    case "Threshold": status.threshold = value
    case "Version": status.version = value
    case "Build Date": status.buildDate = value
    case "Storage Type": status.storageType = value
    case "Cluster Name": status.clusterName = value
    case "Cluster ID": status.clusterId = value
    case "HA Enabled": status.haEnabled = value
    default: break
    }
  }
}

@MainActor
class VaultManager: ObservableObject {
  static let shared = VaultManager()

  @Published var isRunning = false
  @Published var vaultAddr = ""
  @Published var vaultCACert = ""
  @Published var isVaultAvailable = true
  @Published var statusOutput = ""
  @Published var parsedStatus: VaultStatus?
  @Published var isRefreshing = false

  // Is Vault sealed?
  var isSealed: Bool {
    guard let status = parsedStatus else { return true }
    return status.sealed != "false"
  }

  private let plistLabel = "com.hashicorp.vault"
  nonisolated private var plistURL: URL {
    FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent("Library/LaunchAgents/com.hashicorp.vault.plist")
  }

  /// The launchd domain target for the current user, e.g. "gui/501"
  nonisolated private var domainTarget: String {
    "gui/\(getuid())"
  }

  /// The fully-qualified service target, e.g. "gui/501/com.hashicorp.vault"
  nonisolated private var serviceTarget: String {
    "\(domainTarget)/\(plistLabel)"
  }

  /// The major macOS version (e.g. 13 for Ventura, 14 for Sonoma, 15 for
  /// Sequoia, 26 for Tahoe). Used to choose between modern and legacy
  /// launchctl subcommands.
  nonisolated private static let macOSMajorVersion: Int = {
    ProcessInfo.processInfo.operatingSystemVersion.majorVersion
  }()

  /// Whether the OS supports the modern `bootstrap`/`bootout`/`kickstart`
  /// subcommands. These were introduced in macOS 10.10 (Yosemite), so all
  /// versions we target (macOS 13+) support them. However we keep the
  /// check explicit so the intent is clear and future-proof.
  nonisolated private static let usesModernLaunchctl: Bool = {
    macOSMajorVersion >= 13
  }()

  // MARK: - launchctl helpers

  /// Run a launchctl subcommand and return (success, terminationStatus).
  nonisolated private func runLaunchctl(_ arguments: [String]) -> (Bool, Int32) {
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

  /// Bootout (unload) the service. Silently ignores errors when the service
  /// is not loaded.
  ///
  /// Modern (macOS 13+): `launchctl bootout gui/<uid>/com.hashicorp.vault`
  /// Legacy fallback:     `launchctl unload <plist-path>`
  ///
  /// Known acceptable exit codes:
  ///   0   – success
  ///   3   – "no such process" (already unloaded)
  ///   113 – ESRCH / "Could not find specified service"
  @discardableResult
  nonisolated private func bootoutService() -> Bool {
    if Self.usesModernLaunchctl {
      let (_, status) = runLaunchctl(["bootout", serviceTarget])
      return status == 0 || status == 3 || status == 113
    } else {
      let (success, _) = runLaunchctl(["unload", plistURL.path])
      return success
    }
  }

  /// Bootstrap (load) the service into the current user's GUI domain.
  ///
  /// Modern (macOS 13+): `launchctl bootstrap gui/<uid> <plist-path>`
  /// Legacy fallback:     `launchctl load <plist-path>`
  @discardableResult
  nonisolated private func bootstrapService() -> Bool {
    if Self.usesModernLaunchctl {
      let (success, _) = runLaunchctl(["bootstrap", domainTarget, plistURL.path])
      return success
    } else {
      let (success, _) = runLaunchctl(["load", plistURL.path])
      return success
    }
  }

  /// Kick-start the service (ensures it is running even without RunAtLoad).
  ///
  /// Modern (macOS 13+): `launchctl kickstart gui/<uid>/com.hashicorp.vault`
  /// Legacy fallback:     `launchctl start com.hashicorp.vault`
  @discardableResult
  nonisolated private func kickstartService() -> Bool {
    if Self.usesModernLaunchctl {
      let (success, _) = runLaunchctl(["kickstart", serviceTarget])
      return success
    } else {
      let (success, _) = runLaunchctl(["start", plistLabel])
      return success
    }
  }

  init() {
    // Defer all process work to avoid re-entrant run loop
  }

  func performInitialCheck() {
    guard !hasPerformedInitialCheck else { return }
    hasPerformedInitialCheck = true
    DispatchQueue.global(qos: .userInitiated).async {
      let available = self.checkVaultAvailabilitySync()
      let running = self.checkVaultStatusSync()
      DispatchQueue.main.async {
        self.isVaultAvailable = available
        self.isRunning = running
        if running {
          self.parseEnvironmentVariables()
          self.refreshStatus()
        }
      }
    }
  }

  // Background timer that periodically checks whether Vault is running
  func startPolling(interval: TimeInterval = 10) {
    guard pollingTimer == nil else { return }
    pollingTimer = Timer.scheduledTimer(
      withTimeInterval: interval,
      repeats: true
    ) { [weak self] _ in
      guard let self else { return }
      DispatchQueue.global(qos: .utility).async {
        let running = self.checkVaultStatusSync()
        DispatchQueue.main.async {
          if self.isRunning != running {
            self.isRunning = running
            if running {
              self.parseEnvironmentVariables()
              self.refreshStatus()
            } else {
              self.vaultAddr = ""
              self.vaultCACert = ""
              self.parsedStatus = nil
            }
          }
        }
      }
    }

    startStatusRefreshPolling()
  }

  // Periodically refresh `vault status` to keep seal state and other details
  // current. Uses a longer interval (5s) than the launchctl check since it
  // spawns a process and makes an HTTP request to the Vault server.
  private func startStatusRefreshPolling(interval: TimeInterval = 5) {
    guard statusRefreshTimer == nil else { return }
    statusRefreshTimer = Timer.scheduledTimer(
      withTimeInterval: interval,
      repeats: true
    ) { [weak self] _ in
      guard let self else { return }
      MainActor.assumeIsolated {
        guard self.isRunning, self.isVaultAvailable else { return }
        self.refreshStatus()
      }
    }
  }

  private var hasPerformedInitialCheck = false
  private var pollingTimer: Timer?
  private var statusRefreshTimer: Timer?

  // Synchronously check vault availability (safe to call off the main thread)
  nonisolated private func checkVaultAvailabilitySync() -> Bool {
    return findVaultPath() != nil
  }

  /// Synchronously check whether the Vault launchd service is loaded.
  ///
  /// Modern (macOS 13+): `launchctl print gui/<uid>/com.hashicorp.vault`
  /// Legacy fallback:     `launchctl list com.hashicorp.vault`
  nonisolated private func checkVaultStatusSync() -> Bool {
    if Self.usesModernLaunchctl {
      let (success, _) = runLaunchctl(["print", serviceTarget])
      return success
    } else {
      let (success, _) = runLaunchctl(["list", plistLabel])
      return success
    }
  }

  func checkVaultAvailability() {
    DispatchQueue.global(qos: .userInitiated).async {
      let available = self.checkVaultAvailabilitySync()
      DispatchQueue.main.async {
        self.isVaultAvailable = available
      }
    }
  }

  // The plist content this app expects
  nonisolated private func expectedPlistContent() -> String {
    let vaultPath = findVaultPath() ?? "/opt/homebrew/bin/vault"
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
            <string>-dev-root-token-id=root</string>
            <string>-dev-tls</string>
        </array>
        <key>RunAtLoad</key>
        <false/>
        <key>KeepAlive</key>
        <false/>
        <key>StandardOutPath</key>
        <string>/tmp/vault.startup.log</string>
        <key>StandardErrorPath</key>
        <string>/tmp/vault.operations.log</string>
    </dict>
    </plist>
    """
  }

  nonisolated private func createOrUpdatePlist() {
    let plistContent = expectedPlistContent()

    let launchAgentsDir = FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent("Library/LaunchAgents")
    try? FileManager.default.createDirectory(
      at: launchAgentsDir,
      withIntermediateDirectories: true
    )

    if FileManager.default.fileExists(atPath: plistURL.path) {
      if let existing = try? String(contentsOf: plistURL, encoding: .utf8),
       existing == plistContent {
        return  // plist is already up to date
      }
      // Must bootout before overwriting, otherwise bootstrap will fail
      bootoutService()
    }

    try? plistContent.write(to: plistURL, atomically: true, encoding: .utf8)
  }

  /// Locate the `vault` binary by searching well-known directories first,
  /// then falling back to the user's login shell PATH.
  ///
  /// macOS GUI apps (menu bar extras, etc.) inherit a minimal PATH from
  /// launchd (`/usr/bin:/bin:/usr/sbin:/sbin`) that does **not** include
  /// Homebrew, MacPorts, or ~/bin.  Relying solely on `/usr/bin/which` will
  /// therefore fail for most users.  We solve this by:
  ///
  /// 1. Probing a curated list of common install locations (fast, no
  ///    subprocess).
  /// 2. Falling back to a login-shell evaluation of `which vault` so that
  ///    any custom PATH entries still work.
  nonisolated private func findVaultPath() -> String? {
    let fileManager = FileManager.default
    let home = fileManager.homeDirectoryForCurrentUser.path

    // Well-known locations where vault is commonly installed.
    let candidates = [
      "\(home)/bin/vault",                       // ~/bin (user-local)
      "/opt/homebrew/bin/vault",                 // Homebrew on Apple Silicon
      "/usr/local/bin/vault",                    // Homebrew on Intel / manual
      "/opt/homebrew/sbin/vault",
      "/usr/local/sbin/vault",
      "\(home)/.local/bin/vault",                // pipx / user-local
      "/opt/local/bin/vault"                     // MacPorts
    ]

    for path in candidates where fileManager.isExecutableFile(atPath: path) {
      return path
    }

    // Fallback: ask the user's default login shell for the full PATH,
    // then run `which vault` inside it.  This picks up anything the
    // static list above might miss.
    if let shellPath = loginShellWhich("vault") {
      return shellPath
    }

    return nil
  }

  /// Run `which <binary>` inside the user's login shell so we get the
  /// full interactive/login PATH, not the minimal GUI-app PATH.
  nonisolated private func loginShellWhich(_ binary: String) -> String? {
    let shell = ProcessInfo.processInfo.environment["SHELL"] ?? "/bin/zsh"
    let task = Process()
    task.executableURL = URL(fileURLWithPath: shell)
    // `-l` = login shell (sources profile), `-c` = run command.
    task.arguments = ["-l", "-c", "which \(binary)"]

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
        if let path, !path.isEmpty {
          return path
        }
      }
    } catch {
      // Ignore – caller will get nil.
    }
    return nil
  }

  func startVault() {
    guard isVaultAvailable else { return }

    DispatchQueue.global(qos: .userInitiated).async {
      self.createOrUpdatePlist()

      // Bootout any stale registration so we can cleanly bootstrap
      self.bootoutService()

      // Truncate startup log to avoid stale values from previous runs
      try? "".write(toFile: "/tmp/vault.startup.log", atomically: true, encoding: .utf8)

      // Bootstrap loads the plist into launchd
      if !self.bootstrapService() {
        print("Failed to bootstrap service")
        return
      }

      // Kick-start ensures the job actually runs (RunAtLoad is false)
      self.kickstartService()

      DispatchQueue.main.async {
        self.isRunning = true
      }

      // Wait for Vault to finish writing its startup log.
      // If the log is still empty after the initial delay,
      // retry a few times before giving up.
      DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 2) {
        var attempts = 0
        let maxAttempts = 5
        while attempts < maxAttempts {
          let logContent = (try? String(
            contentsOfFile: "/tmp/vault.startup.log",
            encoding: .utf8
          )) ?? ""
          if logContent.contains("VAULT_ADDR") {
            break
          }
          attempts += 1
          Thread.sleep(forTimeInterval: 1)
        }
        DispatchQueue.main.async {
          self.parseEnvironmentVariables()
          self.refreshStatus()
        }
      }
    }
  }

  func stopVault() {
    DispatchQueue.global(qos: .userInitiated).async {
      self.bootoutService()
      DispatchQueue.main.async {
        self.isRunning = false
        self.vaultAddr = ""
        self.vaultCACert = ""
        self.parsedStatus = nil
      }
    }
  }

  func restartVault() {
    DispatchQueue.global(qos: .userInitiated).async {
      self.bootoutService()
      DispatchQueue.main.async {
        self.isRunning = false
        self.vaultAddr = ""
        self.vaultCACert = ""
        self.parsedStatus = nil
      }

      Thread.sleep(forTimeInterval: 1.0)
      DispatchQueue.main.async {
        self.startVault()
      }
    }
  }

  private func parseEnvironmentVariables() {
    let startupLogURL = URL(fileURLWithPath: "/tmp/vault.startup.log")

    guard let content = try? String(contentsOf: startupLogURL, encoding: .utf8) else { return }

    // Iterate in reverse so we always pick up the values from the most
    // recent Vault launch (operational log is appended to across restarts).
    let lines = content.components(separatedBy: .newlines)
    var foundAddr = false
    var foundCACert = false
    for line in lines.reversed() {
      if !foundAddr, line.contains("export VAULT_ADDR=") {
        if let range = line.range(of: "export VAULT_ADDR=") {
          let addr = String(line[range.upperBound...])
          vaultAddr = addr.trimmingCharacters(in: CharacterSet(charactersIn: "\"'\n"))
          foundAddr = true
        }
      }
      if !foundCACert, line.contains("export VAULT_CACERT=") {
        if let range = line.range(of: "export VAULT_CACERT=") {
          let cert = String(line[range.upperBound...])
          vaultCACert = cert.trimmingCharacters(in: CharacterSet(charactersIn: "\"'\n"))
          foundCACert = true
        }
      }
      if foundAddr && foundCACert { break }
    }
  }

  /// Run `vault status` off the main thread and return the raw output plus
  /// the parsed status.  The caller must supply the current environment
  /// values so this method can remain `nonisolated`.
  nonisolated private func runVaultStatus(
    addr: String,
    caCert: String
  ) -> (String, VaultStatus?) {
    guard let vaultPath = findVaultPath() else {
      return ("Could not find vault binary in PATH", nil)
    }

    let task = Process()
    task.executableURL = URL(fileURLWithPath: vaultPath)
    task.arguments = ["status"]

    let pipe = Pipe()
    task.standardOutput = pipe
    task.standardError = pipe

    var env = ProcessInfo.processInfo.environment
    if !addr.isEmpty { env["VAULT_ADDR"] = addr }
    if !caCert.isEmpty { env["VAULT_CACERT"] = caCert }
    task.environment = env

    do {
      try task.run()
      task.waitUntilExit()
      let data = pipe.fileHandleForReading.readDataToEndOfFile()
      let output = String(data: data, encoding: .utf8) ?? "Failed to read status output"
      return (output, VaultStatus.parse(from: output))
    } catch {
      return ("Failed to run vault status: \(error.localizedDescription)", nil)
    }
  }

  // Silently refresh parsed status without opening the status window
  func refreshStatus() {
    guard isVaultAvailable, isRunning else { return }

    isRefreshing = true
    let addr = vaultAddr
    let caCert = vaultCACert
    DispatchQueue.global(qos: .userInitiated).async {
      let (output, parsed) = self.runVaultStatus(addr: addr, caCert: caCert)
      DispatchQueue.main.async {
        self.statusOutput = output
        self.parsedStatus = parsed
        self.isRefreshing = false
      }
    }
  }

  func fetchStatus() {
    guard isVaultAvailable else { return }

    let addr = vaultAddr
    let caCert = vaultCACert
    DispatchQueue.global(qos: .userInitiated).async {
      let (output, parsed) = self.runVaultStatus(addr: addr, caCert: caCert)
      DispatchQueue.main.async {
        self.statusOutput = output
        self.parsedStatus = parsed
        self.showStatusWindow()
      }
    }
  }

  private var statusWindow: NSWindow?
  private var aboutWindow: NSWindow?

  /// Dismiss the MenuBarExtra popover so the status-bar icon remains
  /// clickable afterwards.
  ///
  /// On macOS 26, calling `close()` or `orderOut(nil)` on the popover
  /// window leaves the MenuBarExtra's internal toggle state out of sync —
  /// subsequent clicks on the icon do nothing.  The correct fix is to
  /// simulate a click on the `NSStatusBarButton` that owns the popover,
  /// which goes through AppKit's normal state machine and properly marks
  /// the popover as dismissed.
  private func dismissMenuBarExtra() {
    // The NSStatusBarButton lives inside a small system-owned
    // NSStatusBarWindow (always present in NSApp.windows).
    for window in NSApp.windows {
      guard let button = window.contentView?.findStatusBarButton() else {
        continue
      }
      button.performClick(nil)
      return
    }
  }

  /// Activate the application, bridging the API change between macOS 13 and 14+.
  ///
  /// `NSApplication.activate(ignoringOtherApps:)` was deprecated in macOS 14
  /// in favour of the parameterless `activate()`. We call the modern API when
  /// available and fall back to the deprecated variant on macOS 13.
  private func activateApp() {
    if #available(macOS 14.0, *) {
      NSApp.activate()
    } else {
      NSApp.activate(ignoringOtherApps: true)
    }
  }

  func showAboutWindow() {
    if let existing = aboutWindow {
      existing.close()
    }

    // Dismiss MenuBarExtra popover properly
    dismissMenuBarExtra()

    let contentView = NSHostingView(rootView: AboutView())

    let window = NSWindow(
      contentRect: NSRect(x: 0, y: 0, width: 320, height: 300),
      styleMask: [.titled, .closable],
      backing: .buffered,
      defer: false
    )
    window.title = "About vmenu"
    window.contentView = contentView
    window.center()
    window.isReleasedWhenClosed = false
    window.level = .statusBar
    window.makeKeyAndOrderFront(nil)
    activateApp()

    aboutWindow = window
  }

  func showStatusWindow() {
    // Close existing status window if open
    if let existing = statusWindow {
      existing.close()
    }

    // Dismiss MenuBarExtra popover properly
    dismissMenuBarExtra()

    let contentView: NSView
    if let status = parsedStatus {
      contentView = NSHostingView(
        rootView: StatusPopoverView(status: status, rawOutput: statusOutput)
      )
    } else {
      contentView = NSHostingView(
        rootView: StatusErrorView(errorMessage: statusOutput)
      )
    }

    let window = NSWindow(
      contentRect: NSRect(x: 0, y: 0, width: 520, height: 540),
      styleMask: [.titled, .closable, .miniaturizable],
      backing: .buffered,
      defer: false
    )
    window.title = "Vault Status"
    window.contentView = contentView
    window.center()
    window.isReleasedWhenClosed = false
    window.level = .statusBar
    window.makeKeyAndOrderFront(nil)
    activateApp()

    statusWindow = window
  }
}

struct MenuRowButton: View {
  let title: String
  let icon: String
  var shortcut: String? = nil
  let action: () -> Void

  @State private var isHovered = false
  @Environment(\.isEnabled) private var isEnabled

  var body: some View {
    Button(action: action) {
      HStack(spacing: 8) {
        Image(systemName: icon)
          .font(.system(size: 12))
          .frame(width: 20)
        Text(title)
          .font(.system(size: 13))
        Spacer()
        if let shortcut {
          Text(shortcut)
            .font(.system(size: 11))
            .foregroundColor(.secondary)
        }
      }
      .foregroundColor(isHovered && isEnabled ? .white : .primary)
      .padding(.horizontal, 10)
      .padding(.vertical, 6)
      .background(
        RoundedRectangle(cornerRadius: 6)
          .fill(isHovered && isEnabled ? Color.accentColor : Color.clear)
      )
      .contentShape(Rectangle())
    }
    .buttonStyle(.plain)
    .opacity(isEnabled ? 1.0 : 0.4)
    .onHover { hovering in
      isHovered = hovering
    }
  }
}

struct EnvCopyRowButton: View {
  let label: String
  let value: String
  @Binding var copyFeedback: String?
  let action: () -> Void

  @State private var isHovered = false

  var body: some View {
    Button(action: action) {
      HStack(spacing: 8) {
        Image(systemName: "doc.on.clipboard")
          .font(.system(size: 12))
          .foregroundColor(isHovered ? .white : .accentColor)
          .frame(width: 20)
        VStack(alignment: .leading, spacing: 1) {
          Text(label)
            .font(.system(size: 12, weight: .medium))
            .foregroundColor(isHovered ? .white : .primary)
          Text(value)
            .font(.system(size: 10, design: .monospaced))
            .foregroundColor(isHovered ? .white.opacity(0.7) : .secondary)
            .lineLimit(1)
            .truncationMode(.middle)
        }
        Spacer()
        if copyFeedback == label {
          Image(systemName: "checkmark")
            .font(.system(size: 10, weight: .bold))
            .foregroundColor(isHovered ? .white : .green)
        } else {
          Text("Copy")
            .font(.system(size: 10))
            .foregroundColor(isHovered ? .white.opacity(0.7) : .secondary)
        }
      }
      .padding(.horizontal, 10)
      .padding(.vertical, 6)
      .background(
        RoundedRectangle(cornerRadius: 6)
          .fill(isHovered ? Color.accentColor : Color.clear)
      )
      .contentShape(Rectangle())
    }
    .buttonStyle(.plain)
    .onHover { hovering in
      isHovered = hovering
    }
  }
}

// Loading indicator
struct DottedLoadingIndicator: View {
  let dotCount: Int
  let dotSize: CGFloat
  let spacing: CGFloat

  init(dotCount: Int = 5, dotSize: CGFloat = 4, spacing: CGFloat = 6) {
    self.dotCount = dotCount
    self.dotSize = dotSize
    self.spacing = spacing
  }

  var body: some View {
    TimelineView(.periodic(from: .now, by: 0.18)) { timeline in
      let tick = Int(timeline.date.timeIntervalSinceReferenceDate / 0.18)
      let activeIndex = tick % dotCount

      HStack(spacing: spacing) {
        ForEach(0..<dotCount, id: \.self) { index in
          Circle()
            .fill(Color.secondary)
            .frame(width: dotSize, height: dotSize)
            .opacity(dotOpacity(index: index, active: activeIndex))
        }
      }
      .animation(.easeInOut(duration: 0.16), value: activeIndex)
    }
  }

  private func dotOpacity(index: Int, active: Int) -> Double {
    let distance = min(
      abs(index - active),
      dotCount - abs(index - active)
    )
    switch distance {
    case 0: return 1.0
    case 1: return 0.5
    default: return 0.15
    }
  }
}

struct VaultMenuView: View {
  @ObservedObject private var vaultManager = VaultManager.shared
  @State private var copyFeedback: String?

  var body: some View {
    VStack(alignment: .leading, spacing: 0) {
      if !vaultManager.isVaultAvailable {
        missingVaultView
      } else {
        headerSection
        Divider()
          .padding(.horizontal, 12)
        controlSection
        if vaultManager.isRunning {
          Divider()
            .padding(.horizontal, 12)
          environmentSection
        }
        Divider()
          .padding(.horizontal, 12)
        quitSection
      }
    }
    .frame(width: 360)
  }

  private var missingVaultView: some View {
    VStack(spacing: 12) {
      Image(systemName: "exclamationmark.triangle.fill")
        .font(.system(size: 32))
        .foregroundColor(.orange)

      Text("Vault Not Installed")
        .font(.headline)
        .fontWeight(.bold)

      Text("The vault binary was not found in your PATH.\nInstall it with Homebrew:")
        .font(.caption)
        .foregroundColor(.secondary)
        .multilineTextAlignment(.center)

      Text("brew install hashicorp/tap/vault")
        .font(.system(.caption, design: .monospaced))
        .padding(.horizontal, 10)
        .padding(.vertical, 4)
        .background(
          RoundedRectangle(cornerRadius: 6)
            .fill(Color(nsColor: .textBackgroundColor))
        )

      Button("Download from HashiCorp") {
        if let url = URL(string: "https://developer.hashicorp.com/vault/tutorials/getting-started/getting-started-install") {
          NSWorkspace.shared.open(url)
        }
      }
      .buttonStyle(.borderedProminent)
      .controlSize(.small)

      Divider()
        .padding(.horizontal, 20)

      menuButton(title: "Quit vmenu", icon: "power", shortcut: "⌘Q") {
        NSApplication.shared.terminate(nil)
      }
    }
    .padding(16)
  }

  private var headerSection: some View {
    VStack(spacing: 0) {
      HStack(spacing: 10) {
        Image(systemName: "lock.shield.fill")
          .font(.system(size: 22, weight: .semibold))
          .foregroundColor(.secondary)

        VStack(alignment: .leading, spacing: 1) {
          Text("Vault dev mode server")
            .font(.system(size: 14, weight: .bold))
            .foregroundColor(.primary)
        }

        Spacer()

        statusBadge
      }
      .padding(.horizontal, 14)
      .padding(.vertical, 10)
      .background(
        RoundedRectangle(cornerRadius: 8)
          .fill(Color(nsColor: .controlBackgroundColor))
      )
      .padding(.horizontal, 8)
      .padding(.top, 8)

      if vaultManager.isRunning {
        VStack(spacing: 6) {
          if let status = vaultManager.parsedStatus {
            if !vaultManager.vaultAddr.isEmpty {
              detailRow(
                label: "Address",
                value: vaultManager.vaultAddr,
                icon: "network"
              )
            }
            HStack(spacing: 12) {
              detailPill(label: "v\(status.version)", icon: "tag")
              sealStatusPill(sealed: status.sealed != "false")
              detailPill(label: status.storageType, icon: "internaldrive")
              Spacer()
            }
          } else {
            HStack {
              Spacer()
              DottedLoadingIndicator()
              Spacer()
            }
          }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .background(
          RoundedRectangle(cornerRadius: 8)
            .fill(Color(nsColor: .controlBackgroundColor))
        )
        .padding(.horizontal, 8)
        .padding(.top, 4)
      }
    }
    .padding(.bottom, 8)
  }

  // Display state derived from running + seal status.
  private var displayState: VaultDisplayState {
    guard vaultManager.isRunning else { return .stopped }
    return vaultManager.isSealed ? .sealed : .running
  }

  private var statusBadge: some View {
    let stateColor = displayState.swiftUIColor
    let label: String = {
      switch displayState {
      case .stopped: return "Stopped"
      case .sealed:  return "Sealed"
      case .running: return "Running"
      }
    }()

    return HStack(spacing: 5) {
      Circle()
        .fill(stateColor)
        .frame(width: 8, height: 8)
        .shadow(color: stateColor.opacity(0.6), radius: 3)
      Text(label)
        .font(.system(size: 11, weight: .semibold))
    }
    .foregroundColor(.secondary)
    .padding(.horizontal, 10)
    .padding(.vertical, 5)
    .background(
      Capsule()
        .fill(Color(nsColor: .separatorColor).opacity(0.3))
    )
  }

  private func detailRow(label: String, value: String, icon: String) -> some View {
    HStack(spacing: 6) {
      Image(systemName: icon)
        .font(.system(size: 10, weight: .medium))
        .foregroundColor(.secondary)
        .frame(width: 14)
      Text(label)
        .font(.system(size: 11, weight: .medium))
        .foregroundColor(.secondary)
      Text(value)
        .font(.system(size: 11, weight: .medium, design: .monospaced))
        .foregroundColor(.primary)
        .lineLimit(1)
      Spacer()
    }
  }

  private func detailPill(label: String, icon: String) -> some View {
    HStack(spacing: 3) {
      Image(systemName: icon)
        .font(.system(size: 9))
      Text(label)
        .font(.system(size: 10, weight: .medium))
    }
    .foregroundColor(.secondary)
    .padding(.horizontal, 7)
    .padding(.vertical, 3)
    .background(
      Capsule()
        .fill(Color(nsColor: .separatorColor).opacity(0.2))
    )
  }

  private func sealStatusPill(sealed: Bool) -> some View {
    HStack(spacing: 3) {
      Image(systemName: sealed ? "lock.fill" : "lock.open.fill")
        .font(.system(size: 9))
      Text(sealed ? "Sealed" : "Unsealed")
        .font(.system(size: 10, weight: .medium))
    }
    .foregroundColor(.secondary)
    .padding(.horizontal, 7)
    .padding(.vertical, 3)
    .background(
      Capsule()
        .fill(Color(nsColor: .separatorColor).opacity(0.2))
    )
  }

  private var controlSection: some View {
    VStack(spacing: 2) {
      menuButton(
        title: vaultManager.isRunning ? "Stop Vault" : "Start Vault",
        icon: vaultManager.isRunning ? "stop.fill" : "play.fill",
        shortcut: "⌘S"
      ) {
        if vaultManager.isRunning {
          vaultManager.stopVault()
        } else {
          vaultManager.startVault()
        }
      }
      .disabled(!vaultManager.isVaultAvailable)

      menuButton(title: "Restart Vault", icon: "arrow.clockwise", shortcut: "⌘R") {
        vaultManager.restartVault()
      }
      .disabled(!vaultManager.isVaultAvailable || !vaultManager.isRunning)

      menuButton(title: "View Status", icon: "info.circle", shortcut: "⌘I") {
        vaultManager.fetchStatus()
      }
      .disabled(!vaultManager.isVaultAvailable || !vaultManager.isRunning)
    }
    .padding(.vertical, 4)
    .padding(.horizontal, 4)
  }

  // MARK: - Environment

  private var environmentSection: some View {
    VStack(spacing: 2) {
      if !vaultManager.vaultAddr.isEmpty {
        envCopyRow(label: "VAULT_ADDR", value: vaultManager.vaultAddr)
      }
      if !vaultManager.vaultCACert.isEmpty {
        envCopyRow(label: "VAULT_CACERT", value: vaultManager.vaultCACert)
      }
    }
    .padding(.vertical, 4)
    .padding(.horizontal, 4)
  }

  private func envCopyRow(label: String, value: String) -> some View {
    EnvCopyRowButton(label: label, value: value, copyFeedback: $copyFeedback) {
      copyToClipboard("export \(label)=\(value)")
      copyFeedback = label
      DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
        if copyFeedback == label { copyFeedback = nil }
      }
    }
  }

  // MARK: - Quit

  private var quitSection: some View {
    VStack(spacing: 2) {
      menuButton(title: "About vmenu", icon: "info.circle.fill") {
        VaultManager.shared.showAboutWindow()
      }
      menuButton(title: "Quit vmenu", icon: "power", shortcut: "⌘Q") {
        NSApplication.shared.terminate(nil)
      }
    }
    .padding(.vertical, 4)
    .padding(.horizontal, 4)
  }

  // MARK: - Helpers

  private func menuButton(
    title: String,
    icon: String,
    shortcut: String? = nil,
    action: @escaping () -> Void
  ) -> some View {
    MenuRowButton(title: title, icon: icon, shortcut: shortcut, action: action)
  }

  private func copyToClipboard(_ text: String) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(text, forType: .string)
  }
}

struct StatusPopoverView: View {
  let status: VaultStatus
  let rawOutput: String

  @State private var showRawOutput = false

  var body: some View {
    VStack(spacing: 0) {
      headerView
      Divider()
      ScrollView {
        VStack(alignment: .leading, spacing: 16) {
          statusSection
          clusterSection
          rawOutputSection
        }
        .padding(20)
      }
    }
    .frame(width: 500, height: 520)
    .background(Color(nsColor: .windowBackgroundColor))
  }

  private var headerView: some View {
    HStack {
      Image(systemName: "server.rack")
        .font(.title3)
        .foregroundColor(.accentColor)

      VStack(alignment: .leading, spacing: 2) {
        Text("Vault Status")
          .font(.headline)
        Text("Development Server")
          .font(.caption)
          .foregroundColor(.secondary)
      }

      Spacer()

      sealStatusBadge
    }
    .padding(12)
    .background(Color(nsColor: .controlBackgroundColor))
  }

  private var sealStatusBadge: some View {
    let isSealed = status.sealed != "false"
    let badgeColor: Color = isSealed ? .orange : .green

    return HStack(spacing: 4) {
      Circle()
        .fill(badgeColor)
        .frame(width: 8, height: 8)
      Text(isSealed ? "Sealed" : "Unsealed")
        .font(.caption)
        .fontWeight(.medium)
    }
    .padding(.horizontal, 10)
    .padding(.vertical, 5)
    .background(
      Capsule()
        .fill(badgeColor.opacity(0.15))
    )
  }

  private var statusSection: some View {
    VStack(alignment: .leading, spacing: 12) {
      Text("Server Information")
        .font(.subheadline)
        .fontWeight(.semibold)
        .foregroundColor(.secondary)

      LazyVGrid(columns: [
        GridItem(.flexible()),
        GridItem(.flexible())
      ], spacing: 12) {
        StatusItemView(label: "Version", value: status.version, icon: "info.circle")
        StatusItemView(
          label: "Storage",
          value: status.storageType.capitalized,
          icon: "internaldrive"
        )
        StatusItemView(
          label: "Seal Type",
          value: status.sealType.capitalized,
          icon: "lock.shield"
        )
        StatusItemView(
          label: "HA Enabled",
          value: status.haEnabled.capitalized,
          icon: "heart.fill"
        )
      }

      HStack(spacing: 16) {
        StatusItemView(
          label: "Initialized",
          value: status.initialized.capitalized,
          icon: "checkmark.circle"
        )
        StatusItemView(label: "Key Shares", value: status.totalShares, icon: "number")
        StatusItemView(
          label: "Key Threshold",
          value: status.threshold,
          icon: "slider.horizontal.3"
        )
      }
    }
  }

  private var clusterSection: some View {
    VStack(alignment: .leading, spacing: 12) {
      Text("Cluster Details")
        .font(.subheadline)
        .fontWeight(.semibold)
        .foregroundColor(.secondary)

      VStack(spacing: 8) {
        if status.clusterName != "-" {
          StatusRowView(label: "Cluster Name", value: status.clusterName)
        }
        if status.clusterId != "-" {
          StatusRowView(label: "Cluster ID", value: status.clusterId)
        }
      }
      .padding(12)
      .background(
        RoundedRectangle(cornerRadius: 8)
          .fill(Color(nsColor: .controlBackgroundColor))
      )
    }
  }

  private var rawOutputSection: some View {
    DisclosureGroup(isExpanded: $showRawOutput) {
      VStack(alignment: .leading, spacing: 8) {
        HStack {
          Spacer()

          Button {
            copyToClipboard(rawOutput)
          } label: {
            Label("Copy", systemImage: "doc.on.clipboard")
              .font(.caption)
          }
          .buttonStyle(.borderless)
        }

        Text(rawOutput)
          .font(.system(.caption, design: .monospaced))
          .foregroundColor(.secondary)
          .fixedSize(horizontal: true, vertical: false)
          .padding(12)
          .frame(maxWidth: .infinity, alignment: .leading)
          .background(
            RoundedRectangle(cornerRadius: 8)
              .fill(Color(nsColor: .textBackgroundColor))
          )
      }
    } label: {
      Text("Raw Output")
        .font(.subheadline)
        .fontWeight(.semibold)
        .foregroundColor(.secondary)
    }
  }

  private func copyToClipboard(_ text: String) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(text, forType: .string)
  }
}

struct StatusItemView: View {
  let label: String
  let value: String
  let icon: String

  var body: some View {
    HStack(spacing: 8) {
      Image(systemName: icon)
        .font(.caption)
        .foregroundColor(.accentColor)
        .frame(width: 16)

      VStack(alignment: .leading, spacing: 2) {
        Text(label)
          .font(.caption2)
          .foregroundColor(.secondary)
          .fixedSize(horizontal: true, vertical: false)
        Text(value)
          .font(.subheadline)
          .fontWeight(.medium)
          .fixedSize(horizontal: true, vertical: false)
      }

      Spacer()
    }
    .padding(10)
    .background(
      RoundedRectangle(cornerRadius: 8)
        .fill(Color(nsColor: .controlBackgroundColor))
    )
  }
}

struct StatusRowView: View {
  let label: String
  let value: String

  var body: some View {
    HStack {
      Text(label)
        .font(.caption)
        .foregroundColor(.secondary)
        .fixedSize(horizontal: true, vertical: false)
      Spacer()
      Text(value)
        .font(.system(.caption, design: .monospaced))
        .fixedSize(horizontal: true, vertical: false)
    }
  }
}

struct StatusErrorView: View {
  let errorMessage: String

  var body: some View {
    VStack(spacing: 16) {
      Image(systemName: "exclamationmark.triangle.fill")
        .font(.system(size: 40))
        .foregroundColor(.orange)

      Text("Failed to Get Status")
        .font(.headline)

      Text(errorMessage)
        .font(.caption)
        .foregroundColor(.secondary)
        .multilineTextAlignment(.center)
        .padding(.horizontal)

      Button("Dismiss") {
        NSApp.keyWindow?.close()
      }
      .keyboardShortcut(.return, modifiers: [])
    }
    .padding(30)
    .frame(width: 300)
  }
}

struct AboutView: View {
  private let appVersion: String = {
    Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.1"
  }()

  private let buildNumber: String = {
    Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "1.1"
  }()

  var body: some View {
    VStack(spacing: 16) {
      Image(systemName: "lock.shield.fill")
        .font(.system(size: 48))
        .foregroundColor(.accentColor)

      VStack(spacing: 4) {
        Text("vmenu")
          .font(.system(size: 20, weight: .bold))
        Text("Version \(appVersion) (\(buildNumber))")
          .font(.system(size: 12))
          .foregroundColor(.secondary)
      }

      Text("A macOS menu bar app for Vault.")
        .font(.system(size: 12))
        .foregroundColor(.secondary)
        .multilineTextAlignment(.center)
        .lineSpacing(2)

      Divider()
        .padding(.horizontal, 40)

      VStack(spacing: 4) {
        Text("Made with ❤️ and 🤖 by [Brian Shumate](https://brianshumate.com/)")
          .font(.system(size: 11, weight: .medium))
          .foregroundColor(.primary)
          .tint(.primary)

        Button("GitHub Repository") {
          if let url = URL(string: "https://github.com/brianshumate/vmenu") {
            NSWorkspace.shared.open(url)
          }
        }
        .buttonStyle(.link)
        .font(.system(size: 11))
      }

      Text("MMXXVI.")
        .font(.system(size: 10))
        .foregroundColor(.secondary)
    }
    .padding(24)
    .frame(width: 320)
    .background(Color(nsColor: .windowBackgroundColor))
  }
}

// Represents the three visual states of the menu bar icon
enum VaultDisplayState {
  case stopped
  case sealed
  case running

  var dotColor: NSColor {
    switch self {
    case .stopped: return .systemRed
    case .sealed: return .systemOrange
    case .running: return .systemGreen
    }
  }

  var swiftUIColor: Color {
    switch self {
    case .stopped: return .red
    case .sealed: return .orange
    case .running: return .green
    }
  }
}

// Dynamic menu bar image (red: stopped, orange: sealed, green: unsealed)
private func makeVaultMenuBarImage(state: VaultDisplayState = .stopped) -> NSImage {
  let size = NSSize(width: 18, height: 16)

  func trianglePath(in rect: NSRect) -> NSBezierPath {
    let inset: CGFloat = 1.5
    let path = NSBezierPath()
    path.move(to: NSPoint(x: inset, y: rect.maxY - inset))
    path.line(to: NSPoint(x: rect.maxX - inset, y: rect.maxY - inset))
    path.line(to: NSPoint(x: rect.midX, y: inset))
    path.close()
    path.lineWidth = 1.5
    path.lineJoinStyle = .round
    return path
  }

  // Menu bar icon – stroke adapts to light/dark appearance.
  let composite = NSImage(size: size, flipped: false) { rect in
    let path = trianglePath(in: rect)
    NSColor.labelColor.setStroke()
    path.stroke()

    let dotRadius: CGFloat = 2.5
    let inset: CGFloat = 1.5
    let centroidY = ((rect.maxY - inset) * 2 + inset) / 3.0
    let dotCenter = NSPoint(x: rect.midX, y: centroidY)
    let dotRect = NSRect(
      x: dotCenter.x - dotRadius,
      y: dotCenter.y - dotRadius,
      width: dotRadius * 2,
      height: dotRadius * 2
    )
    let dotPath = NSBezierPath(ovalIn: dotRect)
    state.dotColor.setFill()
    dotPath.fill()

    return true
  }
  composite.isTemplate = false
  return composite
}

// MARK: - NSView helper to locate the NSStatusBarButton inside a status-bar window

extension NSView {
  /// Recursively search the view hierarchy for an NSStatusBarButton.
  fileprivate func findStatusBarButton() -> NSStatusBarButton? {
    if let button = self as? NSStatusBarButton {
      return button
    }
    for subview in subviews {
      if let found = subview.findStatusBarButton() {
        return found
      }
    }
    return nil
  }
}

// MARK: - Menu bar visibility monitor

/// Monitors whether vmenu's status bar icon is visible on the menu bar.
///
/// macOS can hide menu bar extras when the menu bar is too crowded (e.g. on
/// MacBooks with a notch). This class periodically checks the underlying
/// `NSStatusBarWindow` and fires a local notification if the icon has been
/// hidden by the OS.
@MainActor
class MenuBarVisibilityMonitor {
  static let shared = MenuBarVisibilityMonitor()

  /// Whether the icon was visible on the last check.
  private var wasVisible = true

  /// Avoid spamming notifications — only notify once per hide event.
  private var hasNotifiedHidden = false

  private var timer: Timer?

  /// Start periodic visibility checks.
  func startMonitoring(interval: TimeInterval = 5) {
    guard timer == nil else { return }
    // Brief delay so the MenuBarExtra has time to install its status item.
    DispatchQueue.main.asyncAfter(deadline: .now() + 3) { [weak self] in
      MainActor.assumeIsolated {
        self?.checkVisibility()
        self?.timer = Timer.scheduledTimer(
          withTimeInterval: interval,
          repeats: true
        ) { [weak self] _ in
          MainActor.assumeIsolated {
            self?.checkVisibility()
          }
        }
      }
    }
  }

  func stopMonitoring() {
    timer?.invalidate()
    timer = nil
  }

  /// Find the `NSStatusBarWindow` that hosts vmenu's status item button and
  /// determine whether it is actually on-screen.
  private func checkVisibility() {
    let isVisible = findStatusBarWindowVisible()

    if wasVisible && !isVisible {
      // Transitioned from visible → hidden
      if !hasNotifiedHidden {
        hasNotifiedHidden = true
        sendHiddenNotification()
      }
    } else if !wasVisible && isVisible {
      // Transitioned from hidden → visible
      hasNotifiedHidden = false
    }

    wasVisible = isVisible
  }

  /// Walk `NSApp.windows` to locate the status-bar window that contains our
  /// `NSStatusBarButton`, then check whether that window is actually
  /// on-screen within visible display bounds.
  private func findStatusBarWindowVisible() -> Bool {
    // The status bar button lives in a small system-managed window whose
    // class name is NSStatusBarWindow. If we can't find it at all, assume
    // visible (the MenuBarExtra may not have been installed yet).
    for window in NSApp.windows {
      guard window.contentView?.findStatusBarButton() != nil else { continue }

      // The window must be visible and ordered on screen.
      guard window.isVisible, window.occlusionState.contains(.visible) else {
        return false
      }

      // Check that the window's frame intersects with at least one
      // screen's visible area. When the OS hides the icon, the window
      // may be pushed offscreen or have a zero-width frame.
      let frame = window.frame
      if frame.width < 1 || frame.height < 1 {
        return false
      }

      let onAnyScreen = NSScreen.screens.contains { screen in
        screen.frame.intersects(frame)
      }
      return onAnyScreen
    }

    // Could not find the status bar window — assume visible (startup race).
    return true
  }

  /// Whether we are running inside a proper app bundle **and** were launched
  /// through LaunchServices (e.g. `open vmenu.app`).
  ///
  /// `UNUserNotificationCenter` requires both a valid `bundleIdentifier` and
  /// a properly registered launch context.  When the binary is executed
  /// directly from the terminal (even inside a .app bundle), the framework
  /// throws an uncatchable `NSInternalInconsistencyException`.
  ///
  /// We combine the bundle-identifier check with a LaunchServices-based
  /// heuristic: if the running app can be found via `NSRunningApplication`
  /// with a non-empty `bundleURL` that points to a .app wrapper, it was
  /// launched properly.
  private static let hasAppBundle: Bool = {
    guard Bundle.main.bundleIdentifier != nil else { return false }
    // Verify the process was launched through LaunchServices by checking
    // that our bundle URL ends with ".app" (i.e. we are inside a real
    // app bundle, not a bare executable).
    guard Bundle.main.bundlePath.hasSuffix(".app") else { return false }
    // Additional check: NSRunningApplication should know about us with
    // an activation policy other than "prohibited" if we were launched
    // via LaunchServices.
    return NSRunningApplication.current.activationPolicy != .prohibited
  }()

  /// Safely obtain the `UNUserNotificationCenter`.  Returns `nil` when
  /// the call would throw an Objective-C exception (e.g. missing bundle
  /// proxy).
  private static func notificationCenter() -> UNUserNotificationCenter? {
    guard hasAppBundle else { return nil }
    // UNUserNotificationCenter.current() can throw an
    // NSInternalInconsistencyException that Swift cannot catch.
    // The hasAppBundle guard above should prevent this, but as an
    // extra safety net we mark this clearly.
    return UNUserNotificationCenter.current()
  }

  private func sendHiddenNotification() {
    guard let center = Self.notificationCenter() else { return }

    let content = UNMutableNotificationContent()
    content.title = "vmenu Icon Hidden"
    content.body = "Your vmenu menu bar icon is currently hidden "
      + "by macOS. Try closing other menu bar apps or "
      + "rearranging icons to make it visible again."
    content.sound = .default

    let request = UNNotificationRequest(
      identifier: "vmenu-icon-hidden-\(UUID().uuidString)",
      content: content,
      trigger: nil  // Deliver immediately
    )

    center.add(request) { error in
      if let error {
        print(
          "Failed to deliver menu bar visibility "
          + "notification: \(error.localizedDescription)"
        )
      }
    }
  }

  /// Request notification permission. Call once at app startup.
  func requestNotificationPermission() {
    guard let center = Self.notificationCenter() else { return }

    center.requestAuthorization(options: [.alert, .sound]) { granted, error in
      if let error {
        print("Notification permission error: \(error.localizedDescription)")
      }
      if !granted {
        print(
          "vmenu: Notification permission not granted "
          + "— menu bar visibility alerts will be silent."
        )
      }
    }
  }
}

class AppDelegate: NSObject, NSApplicationDelegate {
  func applicationDidFinishLaunching(_ notification: Notification) {
    guard ensureSingleInstance() else { return }
    VaultManager.shared.performInitialCheck()
    VaultManager.shared.startPolling()

    // Request notification permission and start monitoring menu bar
    // icon visibility so the user is alerted when macOS hides the icon.
    MenuBarVisibilityMonitor.shared.requestNotificationPermission()
    MenuBarVisibilityMonitor.shared.startMonitoring()
  }

  /// Returns `true` if this is the only running instance. If another
  /// instance is already running, shows an alert and terminates the app.
  private func ensureSingleInstance() -> Bool {
    guard let bundleID = Bundle.main.bundleIdentifier else { return true }

    let runningInstances = NSRunningApplication.runningApplications(
      withBundleIdentifier: bundleID
    )

    // More than one means us + an already-running instance
    if runningInstances.count > 1 {
      let alert = NSAlert()
      alert.messageText = "vmenu is already running"
      alert.informativeText = "Another instance of vmenu is "
        + "active in the menu bar. Only one instance "
        + "can run at a time."
      alert.alertStyle = .warning
      alert.addButton(withTitle: "OK")
      alert.runModal()
      NSApp.terminate(nil)
      return false
    }

    return true
  }
}

@main
struct VmenuApp: App {
  @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
  @ObservedObject private var vaultManager = VaultManager.shared

  private var displayState: VaultDisplayState {
    guard vaultManager.isRunning else { return .stopped }
    return vaultManager.isSealed ? .sealed : .running
  }

  var body: some Scene {
    MenuBarExtra {
      VaultMenuView()
    } label: {
      Image(nsImage: makeVaultMenuBarImage(state: displayState))
    }
    .menuBarExtraStyle(.window)
  }
}
