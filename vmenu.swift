import AppKit
import Security
import SwiftUI
import UserNotifications
import VmenuCore

/// Lightweight HTTP client for the Vault REST API.
///
/// Replaces the previous approach of spawning a `vault status` process on
/// every poll cycle.  A direct `URLSession` call to `/v1/sys/seal-status`
/// (and optionally `/v1/sys/leader`) is ~5× faster (~7 ms vs ~38 ms) and
/// avoids forking ~720 processes per hour.
///
/// The dev-mode TLS certificate that Vault generates is not trusted by the
/// system keychain, so this client uses a custom `URLSessionDelegate` that
/// loads the CA certificate from the path in `VAULT_CACERT` and evaluates
/// server trust against it.
class VaultHTTPClient: NSObject, URLSessionDelegate {

  /// The `URLSession` configured with this object as its delegate so that
  /// the custom TLS trust evaluation is used for every request.
  private lazy var session: URLSession = {
    let config = URLSessionConfiguration.ephemeral
    config.timeoutIntervalForRequest = 5
    config.timeoutIntervalForResource = 5
    return URLSession(configuration: config, delegate: self, delegateQueue: nil)
  }()

  /// Path to the CA certificate PEM file (from `VAULT_CACERT`).
  /// Updated by the caller whenever the environment variables are parsed.
  var caCertPath: String = ""

  /// Fetch seal status from the Vault HTTP API.
  ///
  /// Calls `GET /v1/sys/seal-status` (unauthenticated) and decodes the
  /// JSON response into a `SealStatusResponse`.
  func fetchSealStatus(addr: String) async throws -> SealStatusResponse {
    guard let url = URL(string: "\(addr)/v1/sys/seal-status") else {
      throw URLError(.badURL)
    }
    let (data, _) = try await session.data(from: url)
    return try JSONDecoder().decode(SealStatusResponse.self, from: data)
  }

  /// Fetch leader information from the Vault HTTP API.
  ///
  /// Calls `GET /v1/sys/leader` (unauthenticated) and decodes the JSON
  /// response.  Used to obtain `ha_enabled`, which the seal-status
  /// endpoint does not include.
  func fetchLeader(addr: String) async throws -> LeaderResponse {
    guard let url = URL(string: "\(addr)/v1/sys/leader") else {
      throw URLError(.badURL)
    }
    let (data, _) = try await session.data(from: url)
    return try JSONDecoder().decode(LeaderResponse.self, from: data)
  }

  /// Fetch complete Vault status by combining seal-status and leader
  /// responses into a `VaultStatus`.
  func fetchVaultStatus(addr: String) async -> (String, VaultStatus?) {
    do {
      let sealStatus = try await fetchSealStatus(addr: addr)
      // Leader endpoint may fail (e.g. during init) — treat as optional.
      let leader = try? await fetchLeader(addr: addr)
      let status = VaultStatus(from: sealStatus, leader: leader)
      return (status.formatAsTable(), status)
    } catch {
      return ("Failed to fetch Vault status: \(error.localizedDescription)", nil)
    }
  }

  func urlSession(
    _ session: URLSession,
    didReceive challenge: URLAuthenticationChallenge,
    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
  ) {
    guard challenge.protectionSpace.authenticationMethod
      == NSURLAuthenticationMethodServerTrust,
      let serverTrust = challenge.protectionSpace.serverTrust
    else {
      completionHandler(.performDefaultHandling, nil)
      return
    }

    // When no CA cert path is configured, fail closed: reject the
    // connection rather than falling through to the system trust store.
    // Vault dev-mode TLS certs are not in the system store, so this
    // prevents silent fallback that could mask configuration errors.
    guard !caCertPath.isEmpty else {
      completionHandler(.cancelAuthenticationChallenge, nil)
      return
    }

    // Validate the CA cert path before reading it.  Reject symlinks,
    // paths inside world-writable directories, and non-regular files
    // to prevent symlink-based MITM attacks.
    guard validateCACertPath(caCertPath) else {
      print("vmenu: CA cert path failed validation — rejecting TLS challenge")
      completionHandler(.cancelAuthenticationChallenge, nil)
      return
    }

    guard let certData = try? Data(contentsOf: URL(fileURLWithPath: caCertPath)),
          let cert = loadCertificate(from: certData)
    else {
      print("vmenu: failed to load CA certificate — rejecting TLS challenge")
      completionHandler(.cancelAuthenticationChallenge, nil)
      return
    }

    SecTrustSetAnchorCertificates(serverTrust, [cert] as CFArray)
    SecTrustSetAnchorCertificatesOnly(serverTrust, true)

    var error: CFError?
    if SecTrustEvaluateWithError(serverTrust, &error) {
      completionHandler(.useCredential, URLCredential(trust: serverTrust))
    } else {
      completionHandler(.cancelAuthenticationChallenge, nil)
    }
  }

  // MARK: - CA Certificate Path Validation

  /// Validate that `path` is safe to read as a CA certificate.
  ///
  /// Delegates to `VmenuCore.validateCACertPath(_:)` which checks that the
  /// path is absolute, not in a world-writable directory, not a symlink,
  /// is a regular file, is owned by the current user or root, and is not
  /// group- or world-writable.
  func validateCACertPath(_ path: String) -> Bool {
    let result = VmenuCore.validateCACertPath(path)
    if !result {
      print("vmenu: CA cert path failed validation: \(path)")
    }
    return result
  }

  // MARK: - Certificate Loading

  /// Load a DER or PEM certificate from raw data.
  private func loadCertificate(from data: Data) -> SecCertificate? {
    // Try DER first.
    if let cert = SecCertificateCreateWithData(nil, data as CFData) {
      return cert
    }
    // Try PEM: strip header/footer and base64-decode.
    if let pemString = String(data: data, encoding: .utf8) {
      let base64 = pemString
        .components(separatedBy: "\n")
        .filter { !$0.hasPrefix("-----") }
        .joined()
      if let derData = Data(base64Encoded: base64) {
        return SecCertificateCreateWithData(nil, derData as CFData)
      }
    }
    return nil
  }
}

/// JSON response from `GET /v1/sys/seal-status`.
///
/// This endpoint does not require authentication and returns all fields
/// that `vault status` displays.
struct SealStatusResponse: Codable, Equatable {
  let type: String
  let initialized: Bool
  let sealed: Bool
  /// Key threshold required to unseal (maps to `t` in the JSON).
  let threshold: Int
  /// Total number of key shares (maps to `n` in the JSON).
  let totalShares: Int
  let progress: Int
  let nonce: String
  let version: String
  let buildDate: String
  let migration: Bool
  let clusterName: String?
  let clusterId: String?
  let recoverySeal: Bool
  let storageType: String?

  enum CodingKeys: String, CodingKey {
    case type, initialized, sealed, progress, nonce, version
    case threshold = "t"
    case totalShares = "n"
    case buildDate = "build_date"
    case migration
    case clusterName = "cluster_name"
    case clusterId = "cluster_id"
    case recoverySeal = "recovery_seal"
    case storageType = "storage_type"
  }
}

/// JSON response from `GET /v1/sys/leader`.
struct LeaderResponse: Codable, Equatable {
  let haEnabled: Bool
  let isSelf: Bool
  let leaderAddress: String
  let leaderClusterAddress: String

  enum CodingKeys: String, CodingKey {
    case haEnabled = "ha_enabled"
    case isSelf = "is_self"
    case leaderAddress = "leader_address"
    case leaderClusterAddress = "leader_cluster_address"
  }
}

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

  /// Construct from the Vault HTTP API JSON responses.
  init(from sealStatus: SealStatusResponse, leader: LeaderResponse? = nil) {
    self.sealType = sealStatus.type
    self.initialized = String(sealStatus.initialized)
    self.sealed = String(sealStatus.sealed)
    self.totalShares = String(sealStatus.totalShares)
    self.threshold = String(sealStatus.threshold)
    self.version = sealStatus.version
    self.buildDate = sealStatus.buildDate
    self.storageType = sealStatus.storageType ?? "-"
    self.clusterName = sealStatus.clusterName ?? "-"
    self.clusterId = sealStatus.clusterId ?? "-"
    self.haEnabled = leader.map { String($0.haEnabled) } ?? "-"
  }

  /// Default memberwise initializer.
  init(
    sealType: String = "-",
    initialized: String = "-",
    sealed: String = "-",
    totalShares: String = "-",
    threshold: String = "-",
    version: String = "-",
    buildDate: String = "-",
    storageType: String = "-",
    clusterName: String = "-",
    clusterId: String = "-",
    haEnabled: String = "-"
  ) {
    self.sealType = sealType
    self.initialized = initialized
    self.sealed = sealed
    self.totalShares = totalShares
    self.threshold = threshold
    self.version = version
    self.buildDate = buildDate
    self.storageType = storageType
    self.clusterName = clusterName
    self.clusterId = clusterId
    self.haEnabled = haEnabled
  }

  /// Format as a key-value table matching the `vault status` CLI output.
  func formatAsTable() -> String {
    var rows: [(String, String)] = [
      ("Seal Type", sealType),
      ("Initialized", initialized),
      ("Sealed", sealed),
      ("Total Shares", totalShares),
      ("Threshold", threshold),
      ("Version", version),
      ("Build Date", buildDate),
      ("Storage Type", storageType),
      ("Cluster Name", clusterName),
      ("Cluster ID", clusterId),
      ("HA Enabled", haEnabled)
    ]

    rows = rows.filter { $0.1 != "-" }

    guard !rows.isEmpty else { return "" }

    let maxKeyLen = rows.map(\.0.count).max() ?? 0
    let padded = max(maxKeyLen + 4, 16)

    var lines = [
      "Key" + String(repeating: " ", count: padded - 3) + "Value",
      "---" + String(repeating: " ", count: padded - 3) + "-----"
    ]

    for (key, value) in rows {
      let padding = String(repeating: " ", count: padded - key.count)
      lines.append(key + padding + value)
    }

    return lines.joined(separator: "\n")
  }
}

@MainActor
class VaultManager: ObservableObject {
  static let shared = VaultManager()

  @Published var isRunning = false
  @Published var vaultAddr = ""
  @Published var vaultCACert = ""
  @Published var vaultToken = ""
  @Published var unsealKey = ""
  @Published var isVaultAvailable = true
  @Published var statusOutput = ""
  @Published var parsedStatus: VaultStatus?
  @Published var isRefreshing = false

  /// HTTP client for direct Vault API calls (replaces `vault status` process
  /// spawning).  Reused across polling cycles so the underlying URLSession
  /// connection pool stays warm.
  private let httpClient = VaultHTTPClient()

  /// Window references for status and about panels.
  var statusWindow: NSWindow?
  var aboutWindow: NSWindow?

  /// Is Vault sealed?
  var isSealed: Bool {
    guard let status = parsedStatus else { return true }
    return status.sealed != "false"
  }

  private let plistLabel = "com.hashicorp.vault"
  nonisolated private var plistURL: URL {
    FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent("Library/LaunchAgents/com.hashicorp.vault.plist")
  }

  /// User-private log directory under ~/Library/Logs/vmenu.
  ///
  /// Using a directory inside the user's home avoids the world-writable
  /// `/tmp` directory, which is susceptible to symlink attacks and
  /// information disclosure from other local users.
  nonisolated private var logDir: URL {
    FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent("Library/Logs/vmenu")
  }

  /// Path to the Vault startup log (environment variables, tokens, etc.).
  nonisolated private var startupLogURL: URL {
    logDir.appendingPathComponent("vault.startup.log")
  }

  /// Path to the Vault stderr / operations log.
  nonisolated private var operationsLogURL: URL {
    logDir.appendingPathComponent("vault.operations.log")
  }

  /// Create the log directory with owner-only permissions (0700) if it does
  /// not already exist.  Returns `true` on success.
  @discardableResult
  nonisolated private func ensureLogDirectory() -> Bool {
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
      print("vmenu: failed to create log directory: \(error.localizedDescription)")
      return false
    }
  }

  /// Verify that the file at `path` is a regular file (not a symlink or
  /// other special file).  Uses `lstat()` so the check is not
  /// dereferenced through symlinks.
  nonisolated private func isRegularFile(atPath path: String) -> Bool {
    var statBuf = stat()
    guard lstat(path, &statBuf) == 0 else { return false }
    return (statBuf.st_mode & S_IFMT) == S_IFREG
  }

  /// Safely read the contents of a log file after verifying it is a regular
  /// file (not a symlink).  Returns `nil` if the file does not exist or
  /// fails the safety check.
  nonisolated private func safeReadLogFile(at url: URL) -> String? {
    let path = url.path
    guard FileManager.default.fileExists(atPath: path) else { return nil }
    guard isRegularFile(atPath: path) else {
      print("vmenu: refusing to read \(path) — not a regular file")
      return nil
    }
    return try? String(contentsOf: url, encoding: .utf8)
  }

  /// Safely write (or truncate) a log file with owner-only permissions
  /// (0600).  Refuses to write if the path already exists as a symlink or
  /// other non-regular file.
  nonisolated private func safeWriteLogFile(at url: URL, contents: String) {
    let path = url.path
    let fileManager = FileManager.default

    // If the file already exists, verify it is a regular file.
    if fileManager.fileExists(atPath: path) {
      guard isRegularFile(atPath: path) else {
        print("vmenu: refusing to write \(path) — not a regular file")
        return
      }
    }

    // Write atomically, then set restrictive permissions.
    do {
      try contents.write(to: url, atomically: true, encoding: .utf8)
      try fileManager.setAttributes(
        [.posixPermissions: 0o600],
        ofItemAtPath: path
      )
    } catch {
      print("vmenu: failed to write \(path): \(error.localizedDescription)")
    }
  }

  /// Atomically replace (or create) a log file to close the TOCTOU race
  /// window between truncation and Vault startup.
  ///
  /// Instead of truncating in-place (which leaves a gap where another
  /// process could inject content), this method:
  ///
  /// 1. Removes the existing file (after verifying it is regular).
  /// 2. Creates a new empty file with `O_CREAT | O_EXCL | O_WRONLY` and
  ///    owner-only permissions (0600), which fails if the path was
  ///    recreated (e.g. as a symlink) between the remove and open.
  ///
  /// Returns `true` on success, `false` if the operation failed.
  @discardableResult
  nonisolated private func safeRecreateLogFile(at url: URL) -> Bool {
    let path = url.path
    let fileManager = FileManager.default

    // If the file already exists, verify it is regular before removing.
    if fileManager.fileExists(atPath: path) {
      guard isRegularFile(atPath: path) else {
        print("vmenu: refusing to recreate \(path) — not a regular file")
        return false
      }
      do {
        try fileManager.removeItem(atPath: path)
      } catch {
        print("vmenu: failed to remove \(path): \(error.localizedDescription)")
        return false
      }
    }

    // Create exclusively — O_EXCL makes this fail if the path was
    // recreated between the remove above and this open, closing the
    // TOCTOU window against symlink attacks.
    let fileDescriptor = open(path, O_CREAT | O_EXCL | O_WRONLY, 0o600)
    guard fileDescriptor >= 0 else {
      let err = String(cString: strerror(errno))
      print("vmenu: exclusive create of \(path) failed: \(err)")
      return false
    }
    close(fileDescriptor)
    return true
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

  /// Remove the CA certificate file that `VAULT_CACERT` points to.
  ///
  /// Vault dev-mode TLS generates a fresh CA certificate on every launch,
  /// so the old file is stale once the server stops.  Removing it avoids
  /// stale-cert confusion and keeps the filesystem tidy; a new file will
  /// be created on the next `vault server -dev-tls` start.
  private func removeCACertFile() {
    let path = vaultCACert
    guard !path.isEmpty else { return }
    guard FileManager.default.fileExists(atPath: path) else { return }
    guard isRegularFile(atPath: path) else {
      print("vmenu: refusing to remove \(path) — not a regular file")
      return
    }
    do {
      try FileManager.default.removeItem(atPath: path)
    } catch {
      print("vmenu: failed to remove CA cert \(path): \(error.localizedDescription)")
    }
  }

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

  /// Background timer that periodically checks whether Vault is running.
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
              self.removeCACertFile()
              self.vaultAddr = ""
              self.vaultCACert = ""
              self.vaultToken = ""
              self.unsealKey = ""
              self.parsedStatus = nil
            }
          }
        }
      }
    }

    startStatusRefreshPolling()
  }

  /// Periodically refresh seal status via direct HTTP API calls to keep seal
  /// state and other details current.  Uses a shorter interval than the old
  /// process-spawning approach since in-process HTTP is ~5× faster (~7 ms
  /// vs ~38 ms) with no fork overhead.
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

  /// Synchronously check vault availability (safe to call off the main thread).
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

  /// The plist content this app expects.
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

  /// Create or update the LaunchAgent plist, returning `true` on success.
  ///
  /// Returns `false` if any step fails (log directory creation, LaunchAgents
  /// directory creation, plist write, or permission hardening) so the caller
  /// can abort rather than proceeding with a stale or missing plist.
  @discardableResult
  nonisolated private func createOrUpdatePlist() -> Bool {
    // Ensure the log directory exists with restrictive permissions before
    // writing a plist that references it.
    guard ensureLogDirectory() else {
      print("vmenu: aborting plist creation — log directory unavailable")
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
      print("vmenu: failed to create LaunchAgents directory: \(error.localizedDescription)")
      return false
    }

    if FileManager.default.fileExists(atPath: plistURL.path) {
      if let existing = try? String(contentsOf: plistURL, encoding: .utf8),
       existing == plistContent {
        return true  // plist is already up to date
      }
      // Must bootout before overwriting, otherwise bootstrap will fail
      bootoutService()
    }

    do {
      try plistContent.write(to: plistURL, atomically: true, encoding: .utf8)
    } catch {
      print("vmenu: failed to write plist \(plistURL.path): \(error.localizedDescription)")
      return false
    }

    // Restrict plist permissions to owner-only (0600) since the file
    // contains the Vault root token, binary path, and log file paths.
    do {
      try FileManager.default.setAttributes(
        [.posixPermissions: 0o600],
        ofItemAtPath: plistURL.path
      )
    } catch {
      print("vmenu: failed to set plist permissions: \(error.localizedDescription)")
      // The plist was written but may be world-readable — remove it
      // rather than leaving sensitive data with loose permissions.
      try? FileManager.default.removeItem(atPath: plistURL.path)
      return false
    }

    return true
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
      "\(home)/bin/vault",  // ~/bin (user-local)
      "/opt/homebrew/bin/vault",  // Homebrew on Apple Silicon
      "/usr/local/bin/vault",  // Homebrew on Intel / manual
      "/opt/homebrew/sbin/vault",
      "/usr/local/sbin/vault",
      "\(home)/.local/bin/vault",  // pipx / user-local
      "/opt/local/bin/vault"  // MacPorts
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

  /// Search for `binary` on a broad PATH using `/usr/bin/which` directly.
  ///
  /// This avoids shell evaluation entirely — no `sh -c` interpolation and
  /// no reliance on the `$SHELL` environment variable — eliminating any
  /// risk of command injection or execution of a malicious shell binary.
  nonisolated private func loginShellWhich(_ binary: String) -> String? {
    // Reject binaries that contain path separators or shell metacharacters.
    // The function is only expected to resolve simple command names (e.g. "vault").
    let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_"))
    guard !binary.isEmpty,
          binary.unicodeScalars.allSatisfy({ allowed.contains($0) })
    else {
      return nil
    }

    let home = FileManager.default.homeDirectoryForCurrentUser.path

    // Construct an explicit, broad PATH that covers common install locations.
    // This replaces sourcing the login shell profile to discover the PATH.
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
        // Only accept absolute paths that point to an executable file.
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

}

// MARK: - VaultManager Lifecycle & Status

extension VaultManager {
  func startVault() {
    guard isVaultAvailable else { return }

    Task.detached(priority: .userInitiated) {
      guard self.createOrUpdatePlist() else {
        print("vmenu: aborting start — plist creation failed")
        return
      }

      // Bootout any stale registration so we can cleanly bootstrap
      self.bootoutService()

      // Atomically recreate the startup log to avoid stale values and
      // close the TOCTOU race window between truncation and Vault
      // writing.  Uses O_CREAT|O_EXCL to prevent symlink injection.
      guard self.safeRecreateLogFile(at: self.startupLogURL) else {
        print("vmenu: aborting start — could not recreate startup log")
        return
      }

      // Bootstrap loads the plist into launchd
      if !self.bootstrapService() {
        print("Failed to bootstrap service")
        return
      }

      // Kick-start ensures the job actually runs (RunAtLoad is false)
      self.kickstartService()

      await MainActor.run {
        self.isRunning = true
      }

      // Wait for Vault to finish writing its startup log.
      // Uses Task.sleep instead of Thread.sleep to avoid blocking a
      // GCD thread pool thread.
      try? await Task.sleep(nanoseconds: 2_000_000_000)
      let maxAttempts = 5
      for _ in 0..<maxAttempts {
        let logContent = self.safeReadLogFile(at: self.startupLogURL) ?? ""
        if logContent.contains("VAULT_ADDR") {
          break
        }
        try? await Task.sleep(nanoseconds: 1_000_000_000)
      }
      await MainActor.run {
        self.parseEnvironmentVariables()
        self.refreshStatus()
      }
    }
  }

  func stopVault() {
    Task.detached(priority: .userInitiated) {
      self.bootoutService()
      await MainActor.run {
        self.removeCACertFile()
        self.isRunning = false
        self.vaultAddr = ""
        self.vaultCACert = ""
        self.vaultToken = ""
        self.unsealKey = ""
        self.parsedStatus = nil
      }
    }
  }

  func restartVault() {
    Task.detached(priority: .userInitiated) {
      self.bootoutService()
      await MainActor.run {
        self.removeCACertFile()
        self.isRunning = false
        self.vaultAddr = ""
        self.vaultCACert = ""
        self.vaultToken = ""
        self.unsealKey = ""
        self.parsedStatus = nil
      }

      try? await Task.sleep(nanoseconds: 1_000_000_000)
      await MainActor.run {
        self.startVault()
      }
    }
  }

  internal func parseEnvironmentVariables() {
    guard let content = safeReadLogFile(at: startupLogURL) else { return }

    // Delegate to the shared, testable parser in VmenuCore.
    let env = VmenuCore.parseEnvironmentVariables(from: content)

    // Validate VAULT_ADDR points to a loopback address.  In dev mode
    // Vault always listens on localhost; a non-loopback address indicates
    // injected or tampered log content.
    if !env.vaultAddr.isEmpty {
      if isLoopbackVaultAddr(env.vaultAddr) {
        vaultAddr = env.vaultAddr
      } else {
        print("vmenu: ignoring non-loopback VAULT_ADDR: \(env.vaultAddr)")
        vaultAddr = ""
      }
    }

    // Validate the CA cert path before accepting it.  This rejects
    // symlinks, paths in world-writable directories, and files with
    // unsafe ownership/permissions to prevent MITM via cert substitution.
    if !env.vaultCACert.isEmpty {
      if httpClient.validateCACertPath(env.vaultCACert) {
        vaultCACert = env.vaultCACert
        httpClient.caCertPath = env.vaultCACert
      } else {
        print("vmenu: ignoring unsafe VAULT_CACERT path: \(env.vaultCACert)")
        vaultCACert = ""
        httpClient.caCertPath = ""
      }
    }

    // Validate the token contains only safe printable ASCII characters
    // and is within a reasonable length.  Vault tokens are displayed in
    // the UI and copied to the clipboard; rejecting unexpected characters
    // prevents injected content from reaching the pasteboard or confusing
    // the UI.
    if !env.vaultToken.isEmpty {
      if isValidVaultToken(env.vaultToken) {
        vaultToken = env.vaultToken
      } else {
        print("vmenu: ignoring invalid VAULT_TOKEN (unexpected characters or length)")
        vaultToken = ""
      }
    }

    // Validate the unseal key contains only base64 characters and is
    // within a reasonable length.  Like the token, this value is displayed
    // and copied to clipboard.
    if !env.unsealKey.isEmpty {
      if isValidVaultUnsealKey(env.unsealKey) {
        unsealKey = env.unsealKey
      } else {
        print("vmenu: ignoring invalid Unseal Key (unexpected characters or length)")
        unsealKey = ""
      }
    }
  }
  /// Silently refresh parsed status without opening the status window.
  ///
  /// Uses the Vault HTTP API directly (`/v1/sys/seal-status` and
  /// `/v1/sys/leader`) instead of spawning a `vault status` process.
  func refreshStatus() {
    guard isVaultAvailable, isRunning, !vaultAddr.isEmpty else { return }

    isRefreshing = true
    httpClient.caCertPath = vaultCACert
    let addr = vaultAddr
    Task.detached(priority: .userInitiated) {
      let (output, parsed) = await self.httpClient.fetchVaultStatus(addr: addr)
      await MainActor.run {
        self.statusOutput = output
        self.parsedStatus = parsed
        self.isRefreshing = false
      }
    }
  }

  func fetchStatus() {
    guard isVaultAvailable, !vaultAddr.isEmpty else { return }

    httpClient.caCertPath = vaultCACert
    let addr = vaultAddr
    Task.detached(priority: .userInitiated) {
      let (output, parsed) = await self.httpClient.fetchVaultStatus(addr: addr)
      await MainActor.run {
        self.statusOutput = output
        self.parsedStatus = parsed
        self.showStatusWindow()
      }
    }
  }

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
        rootView: StatusPopoverView(status: status, rawOutput: statusOutput, unsealKey: unsealKey)
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
    window.title = "Vault server status"
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
    .focusable(false)
    .opacity(isEnabled ? 1.0 : 0.4)
    .onHover { hovering in
      isHovered = hovering
    }
  }
}

struct EnvCopyRowButton: View {
  let label: String
  let value: String
  /// When `true` the value is masked by default with a show/hide toggle.
  var isSensitive: Bool = false
  @Binding var copyFeedback: String?
  let action: () -> Void

  @State private var isHovered = false
  @State private var isRevealed = false

  /// The text shown in the value line — masked or plain.
  private var displayValue: String {
    if isSensitive && !isRevealed {
      return String(repeating: "•", count: min(value.count, 32))
    }
    return value
  }

  var body: some View {
    HStack(spacing: 8) {
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
            Text(displayValue)
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
        .contentShape(Rectangle())
      }
      .buttonStyle(.plain)
      .focusable(false)

      if isSensitive {
        Button {
          isRevealed.toggle()
        } label: {
          Image(systemName: isRevealed ? "eye.slash" : "eye")
            .font(.system(size: 10))
            .foregroundColor(isHovered ? .white.opacity(0.7) : .secondary)
        }
        .buttonStyle(.borderless)
        .focusable(false)
        .help(isRevealed ? "Hide \(label)" : "Reveal \(label)")
      }
    }
    .padding(.horizontal, 10)
    .padding(.vertical, 6)
    .background(
      RoundedRectangle(cornerRadius: 6)
        .fill(isHovered ? Color.accentColor : Color.clear)
    )
    .onHover { hovering in
      isHovered = hovering
    }
  }
}

/// Loading indicator.
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

  /// Display state derived from running + seal status.
  private var displayState: VaultDisplayState {
    guard vaultManager.isRunning else { return .stopped }
    return vaultManager.isSealed ? .sealed : .running
  }

  private var statusBadge: some View {
    let stateColor = displayState.swiftUIColor
    let label: String = {
      switch displayState {
      case .stopped: return "Stopped"
      case .sealed: return "Sealed"
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

      menuButton(title: "Server Status", icon: "info.circle", shortcut: "⌘I") {
        vaultManager.fetchStatus()
      }
      .disabled(!vaultManager.isVaultAvailable || !vaultManager.isRunning)
    }
    .padding(.vertical, 4)
    .padding(.horizontal, 4)
  }

  private var environmentSection: some View {
    VStack(spacing: 2) {
      if !vaultManager.vaultAddr.isEmpty {
        envCopyRow(label: "VAULT_ADDR", value: vaultManager.vaultAddr)
      }
      if !vaultManager.vaultCACert.isEmpty {
        envCopyRow(label: "VAULT_CACERT", value: vaultManager.vaultCACert)
      }
      if !vaultManager.vaultToken.isEmpty {
        envCopyRow(label: "VAULT_TOKEN", value: vaultManager.vaultToken, isSensitive: true)
      }
    }
    .padding(.vertical, 4)
    .padding(.horizontal, 4)
  }

  private func envCopyRow(label: String, value: String, isSensitive: Bool = false) -> some View {
    EnvCopyRowButton(label: label, value: value, isSensitive: isSensitive, copyFeedback: $copyFeedback) {
      let text = "export \(label)=\(value)"
      copyToClipboard(text, autoExpire: isSensitive)
      copyFeedback = label
      DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
        if copyFeedback == label { copyFeedback = nil }
      }
    }
  }

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

  private func menuButton(
    title: String,
    icon: String,
    shortcut: String? = nil,
    action: @escaping () -> Void
  ) -> some View {
    MenuRowButton(title: title, icon: icon, shortcut: shortcut, action: action)
  }

  /// Copy text to the system clipboard.
  ///
  /// When `autoExpire` is `true` the clipboard is automatically cleared
  /// after 30 seconds if it still contains the copied value.  This limits
  /// the window during which other applications can snoop the secret via
  /// `NSPasteboard`.
  private func copyToClipboard(_ text: String, autoExpire: Bool = false) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(text, forType: .string)

    if autoExpire {
      let changeCount = NSPasteboard.general.changeCount
      DispatchQueue.main.asyncAfter(deadline: .now() + 30) {
        // Only clear if the pasteboard hasn't been written to since our
        // copy — avoids wiping unrelated content the user copied later.
        if NSPasteboard.general.changeCount == changeCount {
          NSPasteboard.general.clearContents()
        }
      }
    }
  }
}

struct AboutView: View {
  private let appVersion: String = {
    Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.3"
  }()

  private let buildNumber: String = {
    Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "1.3"
  }()

  var body: some View {
    VStack(spacing: 16) {
      Image(systemName: "lock.shield.fill")
        .font(.system(size: 48))
        .foregroundColor(.accentColor)

      VStack(spacing: 4) {
        Text("vmenu")
          .font(.system(size: 20, weight: .bold))
        Text("Version \(appVersion)" + (buildNumber != appVersion ? " (\(buildNumber))" : ""))
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

/// Represents the three visual states of the menu bar icon.
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

/// Dynamic menu bar image (red: stopped, orange: sealed, green: unsealed).
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
