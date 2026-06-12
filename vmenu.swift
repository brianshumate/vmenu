import AppKit
import OSLog
import Security
import ServiceManagement
import SwiftUI
@preconcurrency import UserNotifications
import VmenuCore
import VmenuXPCProtocol

/// Unified logger for the main app process.
///
/// Uses `os_log` via the `Logger` API so messages go through the unified
/// logging system with proper privacy annotations instead of `print()`,
/// which leaks operational details to any process running `log stream`.
private let logger = Logger(subsystem: "com.brianshumate.vmenu", category: "app")

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
final class VaultHTTPClient: NSObject, URLSessionDelegate, @unchecked Sendable {

  /// The `URLSession` configured with this object as its delegate so that
  /// the custom TLS trust evaluation is used for every request.
  private lazy var session: URLSession = {
    let config = URLSessionConfiguration.ephemeral
    config.timeoutIntervalForRequest = 10
    config.timeoutIntervalForResource = 10
    return URLSession(configuration: config, delegate: self, delegateQueue: nil)
  }()

  /// Serializes access to the mutable certificate state below.
  ///
  /// These fields are written from the `@MainActor` (when environment
  /// variables are parsed) and read on the `URLSession` delegate queue (a
  /// background queue) during TLS challenges.  Without synchronization that
  /// is a genuine cross-thread data race; the lock makes every get/set
  /// atomic.  Same pattern as `VerboseLoggingStorage`.
  private let stateLock = NSLock()
  private var _caCertPath = ""
  private var _caCertData: Data?
  private var _cachedCertificate: SecCertificate?

  /// Path to the CA certificate PEM file (from `VAULT_CACERT`).
  /// Updated by the caller whenever the environment variables are parsed.
  var caCertPath: String {
    get {
      stateLock.lock()
      defer { stateLock.unlock() }
      return _caCertPath
    }
    set {
      stateLock.lock()
      defer { stateLock.unlock() }
      _caCertPath = newValue
    }
  }

  /// CA certificate data cached from the helper.
  /// The sandboxed app cannot read arbitrary filesystem paths, so the helper
  /// reads the CA cert file and passes the raw data back over XPC for TLS
  /// trust evaluation.  Setting this property also parses and caches the
  /// SecCertificate so TLS challenges reuse the parsed object.
  var caCertData: Data? {
    get {
      stateLock.lock()
      defer { stateLock.unlock() }
      return _caCertData
    }
    set {
      // Parse outside the lock — `loadCertificate` is pure and the DER/PEM
      // decode shouldn't block other accessors.
      let parsed = newValue.flatMap { loadCertificate(from: $0) }
      stateLock.lock()
      defer { stateLock.unlock() }
      _caCertData = newValue
      _cachedCertificate = parsed
    }
  }

  /// Atomic snapshot of the certificate state for the TLS challenge handler,
  /// so the "has data" check and the parsed certificate cannot be torn apart
  /// by a concurrent write on the main actor.
  private func certificateState() -> (hasData: Bool, certificate: SecCertificate?) {
    stateLock.lock()
    defer { stateLock.unlock() }
    return (_caCertData != nil, _cachedCertificate)
  }

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
      // Provide a more specific message when the failure is caused by
      // missing CA cert data (TLS challenge cancelled) vs. a genuine
      // network error.  The CA cert is loaded via XPC, so if the
      // helper is unreachable the cert data will be nil and every
      // HTTPS request will fail with a cancelled challenge.
      let msg: String
      if caCertData == nil, addr.lowercased().hasPrefix("https") {
        msg = String(
          localized: """
            Unable to verify the Vault server's TLS certificate. \
            The CA certificate could not be loaded — the vmenu helper \
            process may not be running.

            Details: \(error.localizedDescription)
            """,
          comment: "Error message when TLS fails due to missing CA certificate"
        )
      } else {
        msg = String(
          localized:
            "Unable to reach the Vault server. Check that it is running and try again.\n\nDetails: \(error.localizedDescription)",
          comment: "Error message when Vault HTTP API is unreachable"
        )
      }
      return (msg, nil)
    }
  }

  func urlSession(
    _ session: URLSession,
    didReceive challenge: URLAuthenticationChallenge,
    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
  ) {
    guard
      challenge.protectionSpace.authenticationMethod
        == NSURLAuthenticationMethodServerTrust,
      let serverTrust = challenge.protectionSpace.serverTrust
    else {
      completionHandler(.performDefaultHandling, nil)
      return
    }

    // Snapshot the certificate state atomically so a concurrent update on
    // the main actor cannot tear the "has data" check apart from the parsed
    // certificate read.
    let (hasData, cachedCert) = certificateState()

    // When no CA cert data is available, fail closed: reject the
    // connection rather than falling through to the system trust store.
    // Vault dev-mode TLS certs are not in the system store, so this
    // prevents silent fallback that could mask configuration errors.
    guard hasData else {
      completionHandler(.cancelAuthenticationChallenge, nil)
      return
    }

    guard let cert = cachedCert else {
      logger.warning("Failed to load CA certificate — rejecting TLS challenge")
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

  // MARK: - Certificate Loading

  /// Load a DER or PEM certificate from raw data.
  private func loadCertificate(from data: Data) -> SecCertificate? {
    // Try DER first.
    if let cert = SecCertificateCreateWithData(nil, data as CFData) {
      return cert
    }
    // Try PEM: strip header/footer and base64-decode.
    if let pemString = String(data: data, encoding: .utf8) {
      let base64 =
        pemString
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

// MARK: - XPC Client

/// Manages the connection to the out-of-sandbox XPC helper agent.
///
/// The helper agent (`com.brianshumate.vmenu.helper`) is registered via
/// `SMAppService.agent` and performs all operations that the App Sandbox
/// forbids: `launchctl` process spawning, plist/log file I/O, and `vault`
/// binary discovery.
///
/// macOS 26 (Tahoe) changes:
/// - XPC connections can become stale more aggressively due to improved
///   resource management in launchd.
/// - SMAppService registration may require explicit unregister before
///   re-registration in certain edge cases.
/// - The helper should use `KeepAlive` with `SuccessfulExit = false` to
///   ensure launchd restarts it after unexpected termination.
/// - Launch constraints are stricter - helper must be properly code-signed
///   with explicit bundle identifier matching the Mach service name.
final class XPCClient: @unchecked Sendable {
  static let shared = XPCClient()

  private var connection: NSXPCConnection?

  /// Whether verbose XPC logging is enabled.
  /// Reads from thread-safe storage for runtime toggling.
  private var debugLogging: Bool {
    verboseLoggingStorage.enabled
  }

  /// Whether there's an active (non-nil) XPC connection.
  /// Used by diagnostics to report connection state.
  var hasActiveConnection: Bool {
    connectionQueue.sync { connection != nil }
  }

  /// Tracks consecutive XPC failures to trigger recovery.
  private var consecutiveFailures = 0

  /// Maximum failures before attempting helper re-registration.
  private let maxFailuresBeforeRecovery = 2

  /// Prevents concurrent recovery attempts.
  private var isRecovering = false

  /// Serial queue protecting `connection`.
  ///
  /// Replaces the previous `NSLock`-based approach.  `NSLock` is not
  /// reentrant, so if `conn.resume()` triggered an immediate
  /// invalidation callback while `getConnection()` held the lock the
  /// app would deadlock.  A serial `DispatchQueue` naturally serialises
  /// access and the `async` dispatch in the handlers avoids reentrancy.
  private let connectionQueue = DispatchQueue(label: "com.brianshumate.vmenu.xpc-connection")

  /// Obtain (or create) the XPC connection to the helper.
  ///
  /// The invalidation and interruption handlers already clear `connection`
  /// when the helper dies or is interrupted, so `getConnection()` creates a
  /// new connection on demand.  Age-based proactive refresh is omitted: it
  /// forced reconnects during steady use and the handlers are the reliable
  /// source of truth for stale connections.
  private func getConnection() -> NSXPCConnection {
    connectionQueue.sync {
      if let existing = connection {
        if debugLogging {
          logger.info("[XPC-DEBUG] Reusing existing connection")
        }
        return existing
      }

      if debugLogging {
        logger.info("[XPC-DEBUG] Creating new XPC connection to \(vmenuHelperMachServiceName)")
      }

      let conn = NSXPCConnection(
        machServiceName: vmenuHelperMachServiceName,
        options: []
      )
      conn.remoteObjectInterface = NSXPCInterface(with: VmenuHelperProtocol.self)

      // On macOS 26, invalidation can happen more frequently due to
      // improved resource management. Log at debug level to avoid
      // alarming users during normal operation.
      conn.invalidationHandler = { [weak self] in
        guard let self else { return }
        if self.debugLogging {
          logger.warning("[XPC-DEBUG] Connection INVALIDATED — helper may have crashed or been terminated")
        }
        self.connectionQueue.async { [weak self] in
          self?.connection = nil
        }
      }
      conn.interruptionHandler = { [weak self] in
        guard let self else { return }
        if self.debugLogging {
          logger.warning("[XPC-DEBUG] Connection INTERRUPTED — helper may be unresponsive")
        }
        self.connectionQueue.async { [weak self] in
          self?.connection = nil
        }
      }
      if debugLogging {
        logger.info("[XPC-DEBUG] Resuming XPC connection...")
      }
      conn.resume()
      if debugLogging {
        logger.info("[XPC-DEBUG] XPC connection resumed successfully")
      }
      connection = conn
      return conn
    }
  }

  /// Reset the connection, forcing a fresh one on next access.
  private func resetConnection() {
    connectionQueue.sync {
      connection?.invalidate()
      connection = nil
    }
  }

  /// Record a successful XPC call, resetting the failure counter.
  private func recordSuccess() {
    connectionQueue.sync {
      consecutiveFailures = 0
    }
  }

  /// Record an XPC failure and attempt recovery if needed.
  private func recordFailureAndRecover() async {
    let shouldRecover = connectionQueue.sync { () -> Bool in
      consecutiveFailures += 1
      if consecutiveFailures >= maxFailuresBeforeRecovery && !isRecovering {
        isRecovering = true
        return true
      }
      return false
    }

    if shouldRecover {
      logger.warning("Multiple XPC failures detected — attempting helper recovery")
      resetConnection()

      // On macOS 26, we need a more aggressive recovery strategy:
      // 1. First try to unregister to clear any stale state
      // 2. Wait for launchd to clean up
      // 3. Re-register the helper
      await MainActor.run {
        HelperAgentManager.forceReregister()
      }

      connectionQueue.sync {
        consecutiveFailures = 0
        isRecovering = false
      }
    }
  }

  /// Get a typed proxy to the helper, calling `errorHandler` on XPC failure.
  func proxy(errorHandler: @escaping (Error) -> Void) -> VmenuHelperProtocol? {
    let conn = getConnection()
    if debugLogging {
      logger.info("[XPC-DEBUG] Getting remote object proxy...")
    }
    let proxy = conn.remoteObjectProxyWithErrorHandler { [weak self] error in
      // Always record errors in diagnostics for later inspection
      Task { @MainActor in
        HelperDiagnostics.shared.recordXPCError(error)
      }
      if self?.debugLogging == true {
        let nsError = error as NSError
        logger.error("[XPC-DEBUG] XPC proxy error: domain=\(nsError.domain) code=\(nsError.code) - \(error.localizedDescription, privacy: .public)")
      }
      errorHandler(error)
    } as? VmenuHelperProtocol
    if debugLogging {
      if proxy != nil {
        logger.info("[XPC-DEBUG] Got proxy successfully")
      } else {
        logger.error("[XPC-DEBUG] Failed to get proxy - cast to VmenuHelperProtocol failed")
      }
    }
    return proxy
  }

  /// Convenience: get a proxy that logs errors.
  func proxy() -> VmenuHelperProtocol? {
    proxy { error in
      logger.error("XPC error: \(error.localizedDescription, privacy: .public)")
    }
  }

  /// Invalidate the connection (e.g. on app termination).
  func invalidate() {
    connectionQueue.sync {
      connection?.invalidate()
      connection = nil
    }
  }

  /// Ensure the helper is reachable, attempting recovery if needed.
  ///
  /// Call this before operations that require the helper to be healthy.
  /// Returns `true` if the helper is reachable after any recovery attempts.
  @discardableResult
  func ensureHelperReachable() async -> Bool {
    // First, check current status.
    let status = await MainActor.run { HelperAgentManager.status }
    if debugLogging {
      logger.info("[XPC-DEBUG] ensureHelperReachable - SMAppService status: \(String(describing: status))")
      // Additional diagnostic info
      let statusDesc = await MainActor.run { HelperAgentManager.statusDescription }
      logger.info("[XPC-DEBUG] Status description: \(statusDesc)")
    }

    // On macOS 26, if the status is .notRegistered or .notFound, we
    // should attempt registration before trying to connect.
    if status == .notRegistered || status == .notFound {
      logger.info("Helper not registered — registering before connection attempt")
      await MainActor.run {
        HelperAgentManager.register()
      }
      // Give launchd time to process the registration.
      try? await Task.sleep(nanoseconds: 300_000_000)
    }

    // Try a simple XPC call with a timeout.
    let reachable = await withTaskGroup(of: Bool.self) { group in
      group.addTask {
        // Actual health check.
        _ = await self.findVaultPath()
        return true
      }
      group.addTask {
        // Timeout after 2 seconds.
        try? await Task.sleep(nanoseconds: 2_000_000_000)
        return false
      }

      // First result wins.
      if let result = await group.next() {
        group.cancelAll()
        return result
      }
      return false
    }

    if reachable {
      recordSuccess()
      return true
    }

    // Not reachable — attempt recovery.
    logger.warning("Helper not reachable — attempting recovery")
    await recordFailureAndRecover()

    // Wait a moment for launchd to spawn the helper (longer on macOS 26
    // due to more thorough process validation).
    try? await Task.sleep(nanoseconds: 750_000_000)

    // Try again.
    let secondAttempt = await withTaskGroup(of: Bool.self) { group in
      group.addTask {
        _ = await self.findVaultPath()
        return true
      }
      group.addTask {
        try? await Task.sleep(nanoseconds: 2_000_000_000)
        return false
      }

      if let result = await group.next() {
        group.cancelAll()
        return result
      }
      return false
    }

    if secondAttempt {
      recordSuccess()
      logger.info("Helper recovered successfully")
    } else {
      logger.error("Helper recovery failed — XPC operations will fail")
    }

    return secondAttempt
  }

  // MARK: - Async wrappers

  /// Default timeout for XPC calls in nanoseconds (5 seconds).
  private static let xpcTimeout: UInt64 = 5_000_000_000

  /// Result wrapper for XPC calls that distinguishes success from timeout.
  private enum XPCResult<T: Sendable>: Sendable {
    case success(T)
    case timeout
  }

  /// One-shot latch that lets exactly one of two racing paths (the XPC reply
  /// or the timeout) resume the shared continuation.  The loser's later call
  /// is a safe no-op, which both prevents a fatal double-resume and ensures
  /// the continuation is never leaked when the timeout wins.
  private final class XPCResumeLatch: @unchecked Sendable {
    private let lock = NSLock()
    private var claimed = false
    /// Returns `true` to the first caller only.
    func claim() -> Bool {
      lock.lock()
      defer { lock.unlock() }
      if claimed { return false }
      claimed = true
      return true
    }
  }

  /// Wrapper that adds timeout and error tracking to XPC calls.
  ///
  /// On macOS 26, XPC calls can hang if the helper process is in a bad
  /// state. This wrapper ensures we don't block indefinitely and properly
  /// track failures for recovery.
  ///
  /// A single continuation is resumed by whichever of the reply or the
  /// timeout fires first (guarded by `XPCResumeLatch`).  If the timeout wins
  /// and the helper later replies — or never replies — there is no leaked
  /// continuation and no double-resume, because the latch rejects the second
  /// caller.
  private func withXPCTimeout<T: Sendable>(
    defaultValue: T,
    operation: @escaping @Sendable (@escaping (T) -> Void) -> Void
  ) async -> T {
    let latch = XPCResumeLatch()
    let result: XPCResult<T> = await withCheckedContinuation { continuation in
      let timeoutTask = Task {
        try? await Task.sleep(nanoseconds: Self.xpcTimeout)
        if latch.claim() {
          continuation.resume(returning: .timeout)
        }
      }
      operation { value in
        if latch.claim() {
          timeoutTask.cancel()
          continuation.resume(returning: .success(value))
        }
      }
    }

    switch result {
    case .success(let value):
      recordSuccess()
      return value
    case .timeout:
      logger.warning("XPC call timed out after \(Self.xpcTimeout / 1_000_000_000)s — scheduling recovery")
      Task { await recordFailureAndRecover() }
      return defaultValue
    }
  }

  /// Async wrapper around `findVaultPath`.
  func findVaultPath() async -> String? {
    await withXPCTimeout(defaultValue: nil) { reply in
      guard let helper = self.proxy(errorHandler: { _ in reply(nil) }) else {
        reply(nil)
        return
      }
      helper.findVaultPath(withReply: reply)
    }
  }

  /// Async wrapper around `createOrUpdatePlist`.
  func createOrUpdatePlist() async -> Bool {
    await withXPCTimeout(defaultValue: false) { reply in
      guard let helper = self.proxy(errorHandler: { _ in reply(false) }) else {
        reply(false)
        return
      }
      helper.createOrUpdatePlist(withReply: reply)
    }
  }

  /// Async wrapper around `bootstrapService`.
  func bootstrapService() async -> Bool {
    await withXPCTimeout(defaultValue: false) { reply in
      guard let helper = self.proxy(errorHandler: { _ in reply(false) }) else {
        reply(false)
        return
      }
      helper.bootstrapService(withReply: reply)
    }
  }

  /// Async wrapper around `bootoutService`.
  func bootoutService() async -> Bool {
    await withXPCTimeout(defaultValue: false) { reply in
      guard let helper = self.proxy(errorHandler: { _ in reply(false) }) else {
        reply(false)
        return
      }
      helper.bootoutService(withReply: reply)
    }
  }

  /// Async wrapper around `kickstartService`.
  func kickstartService() async -> Bool {
    await withXPCTimeout(defaultValue: false) { reply in
      guard let helper = self.proxy(errorHandler: { _ in reply(false) }) else {
        reply(false)
        return
      }
      helper.kickstartService(withReply: reply)
    }
  }

  /// Async wrapper around `checkServiceStatus`.
  func checkServiceStatus() async -> Bool {
    await withXPCTimeout(defaultValue: false) { reply in
      guard let helper = self.proxy(errorHandler: { _ in reply(false) }) else {
        reply(false)
        return
      }
      helper.checkServiceStatus(withReply: reply)
    }
  }

  /// Async wrapper around `readStartupLog`.
  func readStartupLog() async -> String? {
    await withXPCTimeout(defaultValue: nil) { reply in
      guard let helper = self.proxy(errorHandler: { _ in reply(nil) }) else {
        reply(nil)
        return
      }
      helper.readStartupLog(withReply: reply)
    }
  }

  /// Async wrapper around `recreateStartupLog`.
  func recreateStartupLog() async -> Bool {
    await withXPCTimeout(defaultValue: false) { reply in
      guard let helper = self.proxy(errorHandler: { _ in reply(false) }) else {
        reply(false)
        return
      }
      helper.recreateStartupLog(withReply: reply)
    }
  }

  /// Async wrapper around `readCACertData`.
  func readCACertData(atPath path: String) async -> Data? {
    await withXPCTimeout(defaultValue: nil) { reply in
      guard let helper = self.proxy(errorHandler: { _ in reply(nil) }) else {
        reply(nil)
        return
      }
      helper.readCACertData(atPath: path, withReply: reply)
    }
  }

  /// Async wrapper around `removeCACertFile`.
  func removeCACertFile(atPath path: String) async -> Bool {
    await withXPCTimeout(defaultValue: false) { reply in
      guard let helper = self.proxy(errorHandler: { _ in reply(false) }) else {
        reply(false)
        return
      }
      helper.removeCACertFile(atPath: path, withReply: reply)
    }
  }
}

// MARK: - SMAppService helper registration

/// Manages the lifecycle of the XPC helper agent via `SMAppService`.
///
/// During development, the helper agent can become stuck in a bad state
/// after frequent start/stop/uninstall cycles.  This class provides
/// robust registration and recovery logic to ensure the helper is
/// reachable when the main app needs it.
///
/// macOS 26 (Tahoe) notes:
/// - SMAppService registration is more strict about plist validity.
/// - The `requiresApproval` status is new and indicates the user must
///   approve the helper in System Settings > Login Items.
/// - Recovery may require explicit unregistration followed by a delay
///   before re-registration to allow launchd to fully clean up.
@MainActor
enum HelperAgentManager {
  /// SMAppService is not Sendable but we only access it from @MainActor.
  private static var _service: SMAppService?

  private static var service: SMAppService {
    if _service == nil {
      _service = SMAppService.agent(plistName: "com.brianshumate.vmenu.helper.plist")
    }
    // swiftlint:disable:next force_unwrapping
    return _service!
  }

  /// Current status of the helper agent.
  static var status: SMAppService.Status {
    service.status
  }

  /// Human-readable description of the current helper status.
  static var statusDescription: String {
    switch status {
    case .notRegistered:
      return String(
        localized: "Helper not registered",
        comment: "Helper agent status description")
    case .enabled:
      return String(
        localized: "Helper enabled",
        comment: "Helper agent status description")
    case .requiresApproval:
      return String(
        localized: "Helper requires approval in System Settings",
        comment: "Helper agent status description")
    case .notFound:
      return String(
        localized: "Helper not found in app bundle",
        comment: "Helper agent status description")
    @unknown default:
      return String(
        localized: "Helper status unknown",
        comment: "Helper agent status description")
    }
  }

  /// Check if the helper binary can be launched.
  /// On macOS 26, ad-hoc signed helpers may fail launch constraint validation.
  static func diagnoseLaunchConstraints() {
    // Get the helper path from the bundle
    guard let bundlePath = Bundle.main.bundlePath as String? else {
      logger.error("[HELPER-DIAG] Cannot determine bundle path")
      return
    }
    let helperPath = "\(bundlePath)/Contents/MacOS/com.brianshumate.vmenu.helper"

    logger.info("[HELPER-DIAG] Bundle path: \(bundlePath, privacy: .public)")
    logger.info("[HELPER-DIAG] Helper path: \(helperPath, privacy: .public)")

    // Check if running from /Applications (required on macOS 26 for ad-hoc signed apps)
    let isInApplications = bundlePath.hasPrefix("/Applications/")
    if isInApplications {
      logger.info("[HELPER-DIAG] App is in /Applications ✓")
    } else {
      logger.warning("[HELPER-DIAG] App is NOT in /Applications - helper may fail launch constraints")
      logger.warning("[HELPER-DIAG] Current location: \(bundlePath, privacy: .public)")
      logger.warning("[HELPER-DIAG] Please move to /Applications for proper operation on macOS 26")
    }

    // Check if helper exists
    if FileManager.default.fileExists(atPath: helperPath) {
      logger.info("[HELPER-DIAG] Helper binary exists")
    } else {
      logger.error("[HELPER-DIAG] Helper binary NOT FOUND at expected path")
      return
    }

    // Check code signing
    var staticCode: SecStaticCode?
    let url = URL(fileURLWithPath: helperPath)
    let createStatus = SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode)
    if createStatus != errSecSuccess {
      logger.error("[HELPER-DIAG] Failed to create static code: \(createStatus)")
      return
    }

    guard let code = staticCode else {
      logger.error("[HELPER-DIAG] Static code is nil")
      return
    }

    // Get signing info
    var signingInfo: CFDictionary?
    let infoStatus = SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &signingInfo)
    if infoStatus == errSecSuccess, let info = signingInfo as? [String: Any] {
      if let identifier = info[kSecCodeInfoIdentifier as String] as? String {
        logger.info("[HELPER-DIAG] Code signing identifier: \(identifier, privacy: .public)")
      }
      if let teamID = info[kSecCodeInfoTeamIdentifier as String] as? String {
        logger.info("[HELPER-DIAG] Team identifier: \(teamID, privacy: .public)")
      } else {
        logger.warning("[HELPER-DIAG] No team identifier (ad-hoc signed)")
      }
      if let flags = info[kSecCodeInfoFlags as String] as? UInt32 {
        // kSecCodeSignatureAdhoc = 0x0002
        let isAdhoc = (flags & 0x0002) != 0
        logger.info("[HELPER-DIAG] Ad-hoc signed: \(isAdhoc)")
        if isAdhoc {
          logger.warning("[HELPER-DIAG] Ad-hoc signing detected - may fail launch constraints on macOS 26")
          logger.warning("[HELPER-DIAG] For development, try: sudo systemextensionsctl developer on")
          logger.warning("[HELPER-DIAG] For production, use Developer ID signing")
        }
      }
    } else {
      logger.error("[HELPER-DIAG] Failed to get signing info: \(infoStatus)")
    }

    // Check macOS version
    let osVersion = ProcessInfo.processInfo.operatingSystemVersion
    logger.info("[HELPER-DIAG] macOS version: \(osVersion.majorVersion).\(osVersion.minorVersion).\(osVersion.patchVersion)")
    if osVersion.majorVersion >= 26 {
      logger.warning("[HELPER-DIAG] macOS 26+ detected - stricter launch constraints apply")
    }
  }

  /// Register the XPC helper agent with `SMAppService` so launchd knows
  /// to start it when the main app connects to the Mach service.
  ///
  /// The helper's launchd plist must be embedded in the app bundle at:
  ///   `Contents/Library/LaunchAgents/com.brianshumate.vmenu.helper.plist`
  ///
  /// `SMAppService.agent(plistName:)` requires macOS 13+, which is below
  /// vmenu's macOS 14+ deployment target.
  static func register() {
    // Debug: Log current status before registration attempt
    let currentStatus = status
    logger.info("[HELPER-DEBUG] Pre-registration status: \(String(describing: currentStatus))")
    logger.info("[HELPER-DEBUG] Attempting to register helper agent...")

    do {
      try service.register()
      logger.info("[HELPER-DEBUG] Helper agent registered successfully")
      // Log post-registration status
      let newStatus = status
      logger.info("[HELPER-DEBUG] Post-registration status: \(String(describing: newStatus))")
    } catch {
      let nsError = error as NSError
      logger.error("[HELPER-DEBUG] Registration failed: domain=\(nsError.domain) code=\(nsError.code)")
      logger.error("[HELPER-DEBUG] Error details: \(error.localizedDescription, privacy: .public)")
      // Log additional debug info
      if let underlyingError = nsError.userInfo[NSUnderlyingErrorKey] as? NSError {
        let desc = underlyingError.localizedDescription
        logger.error(
          "[HELPER-DEBUG] Underlying error: domain=\(underlyingError.domain) code=\(underlyingError.code) - \(desc, privacy: .public)"
        )
      }
      // kSMErrorAlreadyRegistered = 1 (ServiceManagement framework)
      if nsError.domain == "SMAppService" && nsError.code == 1 {
        logger.debug("Helper agent already registered")
      }
    }
  }

  /// Unregister the helper agent, then re-register it.
  ///
  /// This forces launchd to reload the helper configuration, which can
  /// fix stuck states that occur during development when the app is
  /// frequently rebuilt, started, stopped, and uninstalled.
  ///
  /// On macOS 26, we use a longer delay between unregister and register
  /// to ensure launchd has fully cleaned up the previous registration.
  static func forceReregister() {
    logger.info("Force re-registering helper agent (status: \(String(describing: status)))")

    // Unregister first to clear any stale state.
    do {
      try service.unregister()
      logger.debug("Helper agent unregistered")
    } catch {
      // Unregister can fail if not registered; that's fine.
      logger.debug("Unregister returned error (may be expected): \(error.localizedDescription, privacy: .public)")
    }

    // Re-register after a short delay so launchd can clean up the
    // previous registration.  This runs on @MainActor so we dispatch
    // the re-registration asynchronously to avoid blocking the UI.
    Task { @MainActor in
      try? await Task.sleep(nanoseconds: 250_000_000)
      do {
        try service.register()
        logger.info("Helper agent re-registered successfully")
      } catch {
        logger.error(
          "Failed to re-register helper agent: \(error.localizedDescription, privacy: .public)")
      }
    }
  }

  /// Open System Settings to the Login Items pane where users can
  /// approve the helper if it requires approval.
  ///
  /// On macOS 26, this uses the `x-apple.systempreferences` URL scheme
  /// with the Login Items anchor.
  static func openLoginItemsSettings() {
    // The URL for Login Items in System Settings.
    // This works on macOS 13+ and is the correct anchor for macOS 26.
    if let url = URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension") {
      NSWorkspace.shared.open(url)
    }
  }
}

/// Legacy function for backward compatibility.
@MainActor
func registerHelperAgent() {
  // Run diagnostics first on macOS 26+
  let osVersion = ProcessInfo.processInfo.operatingSystemVersion
  if osVersion.majorVersion >= 26 {
    HelperAgentManager.diagnoseLaunchConstraints()
  }
  HelperAgentManager.register()
}

// MARK: - Window Delegate

/// Handles window lifecycle events for the About and Status windows.
///
/// On macOS 26, LSUIElement menu-bar apps that switch to `.accessory`
/// activation policy to bring a window to front must revert to
/// `.accessory` (or `.prohibited`) after the window closes, otherwise
/// the MenuBarExtra's click handling can become desynchronized.
///
/// This delegate also clears the owning `VaultManager`'s window reference
/// so the next "About" / "Status" action creates a fresh window instead
/// of trying to reuse a deallocated one.
class VaultWindowDelegate: NSObject, NSWindowDelegate {
  func windowWillClose(_ notification: Notification) {
    guard let window = notification.object as? NSWindow else { return }

    // Clear the VaultManager reference that corresponds to this window.
    let manager = VaultManager.shared
    if window === manager.aboutWindow {
      manager.aboutWindow = nil
    } else if window === manager.statusWindow {
      manager.statusWindow = nil
      // Balance the fast-refresh consumer registered in showStatusWindow().
      manager.endFastRefresh()
    }

    // If no managed windows remain visible, restore the activation
    // policy so the MenuBarExtra's internal toggle state stays in sync
    // and the app doesn't linger in the Dock on macOS 26.
    let hasVisibleWindows =
      (manager.aboutWindow?.isVisible == true)
      || (manager.statusWindow?.isVisible == true)

    if !hasVisibleWindows {
      // Revert to accessory — the app has no Dock icon but is still
      // eligible for activation when the user clicks the menu bar icon.
      NSApp.setActivationPolicy(.accessory)
    }
  }
}

// MARK: - VaultManager

@MainActor
@Observable
class VaultManager {
  static let shared = VaultManager()

  var isRunning = false
  var vaultAddr = ""
  var vaultCACert = ""
  var vaultToken = ""
  var unsealKey = ""
  var isVaultAvailable = false
  var statusOutput = ""
  var parsedStatus: VaultStatus?
  var isRefreshing = false

  /// Indicates the XPC helper is not reachable.
  /// When `true`, the UI should show a warning and recovery options.
  var isHelperUnavailable = false

  /// Detailed message about why the helper is unavailable.
  var helperUnavailableReason: String = ""

  /// Whether debug mode is enabled (shows diagnostic menu items).
  /// Stored in UserDefaults and toggleable from the About window.
  var isDebugModeEnabled: Bool = UserDefaults.standard.bool(forKey: "isDebugModeEnabled") {
    didSet {
      UserDefaults.standard.set(isDebugModeEnabled, forKey: "isDebugModeEnabled")
    }
  }

  /// HTTP client for direct Vault API calls (replaces `vault status` process
  /// spawning).  Reused across polling cycles so the underlying URLSession
  /// connection pool stays warm.
  private let httpClient = VaultHTTPClient()

  /// XPC client for communicating with the unsandboxed helper agent.
  private let xpc = XPCClient.shared

  /// Window references for status and about panels.
  var statusWindow: NSWindow?
  var aboutWindow: NSWindow?

  /// Delegate that observes window close events so we can clean up
  /// references and restore the activation policy for this LSUIElement app.
  private let windowDelegate = VaultWindowDelegate()

  /// Three-state seal status.
  ///
  /// Distinguishes "not yet known" (status hasn't loaded) from "sealed" so
  /// callers don't silently treat an unloaded status as sealed.  Prefer this
  /// over `isSealed` in any new code that isn't already gated on `isRunning`.
  enum SealState {
    case sealed
    case unsealed
    case unknown
  }

  /// Current seal state derived from the parsed status, or `.unknown` when
  /// no status has been fetched yet.
  var sealState: SealState {
    guard let status = parsedStatus else { return .unknown }
    return status.sealed == "false" ? .unsealed : .sealed
  }

  /// Is Vault sealed?
  ///
  /// Treats `.unknown` as sealed for the benefit of callers that have
  /// already established the server is running (e.g. `displayState`).
  /// New code that needs to handle the not-yet-loaded case should use
  /// `sealState` instead.
  var isSealed: Bool {
    sealState != .unsealed
  }

  private var hasPerformedInitialCheck = false
  private var pollingTimer: Timer?
  private var statusRefreshTimer: Timer?

  /// Tracks failed helper recovery attempts to avoid spamming the user.
  private var helperRecoveryAttempts = 0
  private let maxHelperRecoveryAttempts = 3

  init() {
    // Defer all process work to avoid re-entrant run loop
  }

  /// Returns the appropriate error message when the helper is unreachable.
  private func helperUnreachableReason() -> String {
    let osVersion = ProcessInfo.processInfo.operatingSystemVersion
    if osVersion.majorVersion >= 26 {
      let bundlePath = Bundle.main.bundlePath
      let isInApplications = bundlePath.hasPrefix("/Applications/")

      if !isInApplications {
        return String(
          localized: """
            vmenu's helper process failed to start because the app is not installed in /Applications.

            On macOS 26 (Tahoe), ad-hoc signed apps must be installed in /Applications for their helper processes to launch.

            Please move vmenu.app to /Applications and relaunch.
            """,
          comment: "Error message when app is not in /Applications on macOS 26"
        )
      } else {
        return String(
          localized: """
            vmenu's helper process failed to start due to macOS security restrictions.

            This can happen with ad-hoc signed apps on macOS 26 (Tahoe).

            For development:
            • Use Developer ID signing
            • Or check Console.app for "Launch Constraint Violation" errors

            Try reinstalling vmenu from a fresh download.
            """,
          comment: "Error message when helper fails launch constraints on macOS 26 in Applications"
        )
      }
    } else {
      return String(
        localized: """
          vmenu cannot communicate with its helper process. \
          This may happen after a macOS update or if the app was moved. \
          Try restarting the app or reinstalling vmenu.
          """,
        comment: "Error message when helper is not reachable"
      )
    }
  }

  func performInitialCheck() {
    guard !hasPerformedInitialCheck else { return }
    hasPerformedInitialCheck = true

    Task {
      // Check helper status first to provide specific error messages.
      let status = HelperAgentManager.status
      logger.info("Initial helper status: \(String(describing: status))")

      // Handle requiresApproval status specifically on macOS 26.
      // Don't return — fall through to the reachability check so the
      // background polling can detect when the user approves the helper.
      if status == .requiresApproval {
        self.isHelperUnavailable = true
        self.helperUnavailableReason = String(
          localized: """
            The vmenu helper requires your approval to run.

            Open System Settings > General > Login Items, then \
            enable the toggle next to "vmenu" under "Allow in the Background".
            """,
          comment: "Error message when helper requires user approval"
        )
        logger.warning("Helper requires approval — showing in-app banner")
        // Don't auto-open System Settings; the in-app banner already
        // explains what to do and provides an explicit button.  Jumping
        // to System Settings without user intent violates HIG guidance
        // for permission flows and surprises first-launch users.
        // Don't return — let the background polling pick up approval.
      }

      // Ensure the helper is reachable before any operations.
      // This handles stale SMAppService registrations from development cycles.
      let helperReachable = await xpc.ensureHelperReachable()
      if !helperReachable {
        logger.error("Helper agent not reachable — Vault operations will be unavailable")
        self.isHelperUnavailable = true
        self.helperUnavailableReason = helperUnreachableReason()
        self.isVaultAvailable = false
        return
      }

      // Helper is working — clear any previous error state.
      self.isHelperUnavailable = false
      self.helperUnavailableReason = ""
      self.helperRecoveryAttempts = 0

      let available = await xpc.findVaultPath() != nil
      let running = await xpc.checkServiceStatus()
      self.isVaultAvailable = available
      self.isRunning = running
      if running {
        await self.parseEnvironmentVariables()
        self.refreshStatus()
      }
    }
  }

  /// Attempt to recover the helper connection.
  ///
  /// This can be called by the user via the UI when the helper is unavailable.
  /// It will attempt to re-register the helper and verify connectivity.
  func attemptHelperRecovery() {
    guard helperRecoveryAttempts < maxHelperRecoveryAttempts else {
      helperUnavailableReason = String(
        localized: """
          Multiple recovery attempts failed. Please try: \
          1) Quit and reopen vmenu \
          2) Restart your Mac \
          3) Reinstall vmenu from a fresh download
          """,
        comment: "Error message after multiple failed recovery attempts"
      )
      return
    }

    helperRecoveryAttempts += 1
    let currentAttempt = helperRecoveryAttempts
    let maxAttempts = maxHelperRecoveryAttempts
    logger.info("User-initiated helper recovery attempt \(currentAttempt)")

    Task {
      // Force re-registration.
      HelperAgentManager.forceReregister()

      // Wait for launchd to process.
      try? await Task.sleep(nanoseconds: 500_000_000)

      // Check if recovery worked.
      let reachable = await self.xpc.ensureHelperReachable()
      if reachable {
        logger.info("Helper recovery successful")
        self.isHelperUnavailable = false
        self.helperUnavailableReason = ""
        self.helperRecoveryAttempts = 0

        // Re-run initial check to restore normal operation.
        self.hasPerformedInitialCheck = false
        self.performInitialCheck()
      } else {
        logger.warning("Helper recovery attempt \(currentAttempt) failed")
        self.helperUnavailableReason = String(
          localized: """
            Recovery attempt \(currentAttempt) of \(maxAttempts) failed. \
            You can try again or check System Settings > General > Login Items \
            to ensure vmenu's helper is enabled.
            """,
          comment: "Error message after a failed recovery attempt"
        )
      }
    }
  }

  /// Open System Settings to the Login Items pane for manual helper approval.
  func openHelperSettings() {
    HelperAgentManager.openLoginItemsSettings()
  }

  /// Run comprehensive helper diagnostics and copy results to clipboard.
  ///
  /// Call this when troubleshooting helper connectivity issues. The report
  /// includes system info, code signing status, SMAppService state, and
  /// suggested remediation steps.
  func runDiagnosticsAndCopy() {
    HelperDiagnostics.shared.collectAndCopyToClipboard()
  }

  /// Toggle verbose diagnostic logging.
  ///
  /// When enabled, XPC operations log detailed debug information that can
  /// be viewed in Console.app by filtering for "com.brianshumate.vmenu".
  func toggleVerboseLogging() {
    HelperDiagnostics.verboseLoggingEnabled.toggle()
  }

  /// Whether verbose helper logging is currently enabled.
  var isVerboseLoggingEnabled: Bool {
    HelperDiagnostics.verboseLoggingEnabled
  }

  /// Get the last diagnostic report, if any.
  var lastDiagnosticReport: HelperDiagnostics.DiagnosticReport? {
    HelperDiagnostics.shared.lastReport
  }

  /// Background timer that periodically checks whether Vault is running.
  func startPolling(interval: TimeInterval = 10) {
    guard pollingTimer == nil else { return }
    pollingTimer = Timer.scheduledTimer(
      withTimeInterval: interval,
      repeats: true
    ) { [weak self] _ in
      guard let self else { return }
      Task { @MainActor in
        // Skip polling if helper is unavailable — we can't check anything.
        guard !self.isHelperUnavailable else {
          // Always attempt silent recovery — the user may approve the
          // helper in System Settings at any time, so we must keep
          // checking regardless of how many previous attempts failed.
          let reachable = await self.xpc.ensureHelperReachable()
          if reachable {
            logger.info("Helper became available during background check")
            self.isHelperUnavailable = false
            self.helperUnavailableReason = ""
            self.helperRecoveryAttempts = 0
            self.hasPerformedInitialCheck = false
            self.performInitialCheck()
          }
          return
        }

        let running = await self.xpc.checkServiceStatus()
        if self.isRunning != running {
          self.isRunning = running
          if running {
            await self.parseEnvironmentVariables()
          } else {
            _ = await self.xpc.removeCACertFile(atPath: self.vaultCACert)
            self.vaultAddr = ""
            self.vaultCACert = ""
            self.vaultToken = ""
            self.unsealKey = ""
            self.parsedStatus = nil
            self.httpClient.caCertData = nil
            self.httpClient.caCertPath = ""
          }
        }

        // Refresh seal status each cycle while running so the menu-bar icon
        // stays current even when no UI is open.  This 10-second cadence
        // replaces the old always-on 5-second fast poll; the faster cadence
        // now runs only while a UI surface is visible (see fast-refresh
        // consumers below).
        if self.isRunning {
          self.refreshStatus()
        }
      }
    }
  }

  // MARK: - Fast (UI-visible) refresh

  /// Number of visible UI surfaces (the menu popover and the status window)
  /// that want the faster 5-second refresh cadence.  When zero, the
  /// 10-second `pollingTimer` alone keeps the menu-bar icon current, which
  /// avoids needless wakeups, network traffic, and JSON decoding while
  /// nothing is on screen.
  private var fastRefreshConsumers = 0

  /// Register a visible UI surface that wants frequent status updates and
  /// trigger an immediate refresh so the surface opens with fresh data.
  func beginFastRefresh() {
    fastRefreshConsumers += 1
    if isRunning, isVaultAvailable {
      refreshStatus()
    }
    updateFastRefreshPolling()
  }

  /// Unregister a previously registered UI surface.
  func endFastRefresh() {
    fastRefreshConsumers = max(0, fastRefreshConsumers - 1)
    updateFastRefreshPolling()
  }

  /// Start or stop the 5-second fast-refresh timer based on whether any UI
  /// surface is currently visible.
  private func updateFastRefreshPolling() {
    if fastRefreshConsumers > 0 {
      startStatusRefreshPolling()
    } else {
      statusRefreshTimer?.invalidate()
      statusRefreshTimer = nil
    }
  }

  /// Periodically refresh seal status via direct HTTP API calls to keep seal
  /// state and other details current while a UI surface is open.  Uses a
  /// shorter interval than the background poll since in-process HTTP is ~5×
  /// faster (~7 ms vs ~38 ms) with no fork overhead.
  private func startStatusRefreshPolling(interval: TimeInterval = 5) {
    guard statusRefreshTimer == nil else { return }
    statusRefreshTimer = Timer.scheduledTimer(
      withTimeInterval: interval,
      repeats: true
    ) { [weak self] _ in
      guard let self else { return }
      Task { @MainActor in
        guard self.isRunning, self.isVaultAvailable else { return }
        self.refreshStatus()
      }
    }
  }

  /// Stop all polling timers and release resources.
  ///
  /// Called on application termination to ensure timers don't fire after
  /// the app has started shutting down.
  func stopPolling() {
    pollingTimer?.invalidate()
    pollingTimer = nil
    statusRefreshTimer?.invalidate()
    statusRefreshTimer = nil
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
  ///
  /// Fallback: if the `NSStatusBarButton` heuristic fails (e.g. because
  /// macOS 26 changed the view hierarchy), we close the popover-style
  /// windows directly.  This may cause the toggle-state desync, but is
  /// better than leaving the popover visible behind a new window.
  private func dismissMenuBarExtra() {
    // Primary: simulate a click on the status bar button.
    for window in NSApp.windows {
      guard let button = window.contentView?.findStatusBarButton() else {
        continue
      }
      button.performClick(nil)
      return
    }

    // Fallback: close any MenuBarExtra popover windows directly.
    // MenuBarExtra window-style popovers use `NSPanel` with a specific
    // style mask.  We look for panels that are visible, borderless, and
    // not our own managed windows.
    for window in NSApp.windows {
      if window !== statusWindow,
         window !== aboutWindow,
         window.isVisible,
         window is NSPanel,
         window.styleMask.contains(.nonactivatingPanel) {
        window.orderOut(nil)
      }
    }
  }

  /// Activate the application so its windows come to the foreground.
  ///
  /// For `LSUIElement` apps (no Dock icon), `NSApp.activate()` alone
  /// may not bring windows to front on macOS 26 because the app never
  /// "owns" the foreground.  We temporarily switch to `.accessory`
  /// activation policy so AppKit treats the app as eligible for
  /// activation, then rely on the window's `.floating` level and
  /// `orderFrontRegardless()` as a safety net.
  private func activateApp() {
    NSApp.setActivationPolicy(.accessory)
    NSApp.activate()
  }

  func showAboutWindow() {
    // Defer everything — including the MenuBarExtra dismissal — to the
    // next run-loop pass.  On macOS 26, dismissMenuBarExtra() calls
    // performClick(nil) on the NSStatusBarButton, which re-enters
    // AppKit's event handling while the SwiftUI button action is still
    // on the call stack.  Deferring the entire sequence avoids the
    // re-entrant crash/deadlock.
    DispatchQueue.main.async { [self] in
      dismissMenuBarExtra()

      if let existing = aboutWindow {
        aboutWindow = nil
        existing.orderOut(nil)
      }

      // Use NSHostingController instead of manually embedding an
      // NSHostingView.  The controller correctly manages safe-area
      // inset invalidation during window layout, avoiding the
      // constraint-engine crash that occurs when an NSHostingView
      // subview of an NSVisualEffectView triggers
      // invalidateSafeAreaInsets during the initial display cycle
      // under fullSizeContentView.
      let hostingController = NSHostingController(rootView: AboutView())

      let window = NSWindow(
        contentRect: NSRect(x: 0, y: 0, width: 320, height: 300),
        styleMask: [.titled, .closable],
        backing: .buffered,
        defer: false
      )
      window.title = String(localized: "About vmenu", comment: "Title for the About window")
      window.minSize = NSSize(width: 280, height: 260)
      window.contentViewController = hostingController
      window.isReleasedWhenClosed = false
      window.level = .floating
      window.delegate = self.windowDelegate

      // Ask the SwiftUI hosting controller for the ideal content size
      // before the window is visible.  sizeThatFits returns the view's
      // intrinsic ideal size.  Pass a large but finite proposal; using
      // .greatestFiniteMagnitude can return infinity for views that
      // don't constrain themselves, which causes setFrame to crash.
      // If the result is still infinite or NaN, fall back to the
      // window's minSize.
      var fittingSize = hostingController.sizeThatFits(in: CGSize(width: 10000, height: 10000))
      if !fittingSize.width.isFinite || fittingSize.width <= 0 {
        fittingSize.width = window.minSize.width
      }
      if !fittingSize.height.isFinite || fittingSize.height <= 0 {
        fittingSize.height = window.minSize.height
      }

      // Determine which screen the pointer is on (most natural choice
      // for a menu-bar app where the user just clicked a menu item).
      // Fall back to the main screen, then an arbitrary screen.
      let targetScreen =
        NSScreen.screens.first(where: { $0.frame.contains(NSEvent.mouseLocation) })
        ?? NSScreen.main
        ?? NSScreen.screens.first

      if let screen = targetScreen {
        // Convert to window frame (title bar height is included).
        let contentSize = NSSize(
          width: max(fittingSize.width, 280),
          height: max(fittingSize.height, 260)
        )
        let frameSize = window.frameRect(forContentRect: NSRect(origin: .zero, size: contentSize))

        // Center within the visible portion of the screen (avoids the
        // menu bar and Dock rather than centering in the raw screen rect).
        let visibleFrame = screen.visibleFrame
        let originX = visibleFrame.midX - frameSize.width / 2
        let originY = visibleFrame.midY - frameSize.height / 2
        window.setFrame(
          NSRect(origin: NSPoint(x: originX, y: originY), size: frameSize.size),
          display: false
        )
      } else {
        // No screen info available — fall back to AppKit's best guess.
        window.center()
      }

      self.activateApp()
      window.makeKeyAndOrderFront(nil)
      // Safety net: ensure the window is visible even if activate()
      // didn't bring the app to the foreground (LSUIElement apps).
      window.orderFrontRegardless()

      self.aboutWindow = window
    }
  }

  /// Position `window` centered on whichever screen currently contains the
  /// pointer, falling back to the main screen and then `center()`.
  private func centerOnPointerScreen(_ window: NSWindow) {
    let targetScreen =
      NSScreen.screens.first(where: { $0.frame.contains(NSEvent.mouseLocation) })
      ?? NSScreen.main
      ?? NSScreen.screens.first

    guard let screen = targetScreen else {
      window.center()
      return
    }
    let visibleFrame = screen.visibleFrame
    let windowFrame = window.frame
    let originX = visibleFrame.midX - windowFrame.width / 2
    let originY = visibleFrame.midY - windowFrame.height / 2
    window.setFrameOrigin(NSPoint(x: originX, y: originY))
  }

  func showStatusWindow() {
    // Defer everything to the next run-loop pass (same pattern as
    // showAboutWindow) to avoid re-entrant AppKit crashes on macOS 26.
    DispatchQueue.main.async { [self] in
      dismissMenuBarExtra()

      if let existing = statusWindow {
        statusWindow = nil
        existing.orderOut(nil)
      }

      let window = NSWindow(
        contentRect: NSRect(x: 0, y: 0, width: 540, height: 580),
        styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
        backing: .buffered,
        defer: false
      )
      window.title = String(
        localized: "Vault Server Status", comment: "Title for the status detail window")
      window.minSize = NSSize(width: 400, height: 400)

      // Set the NSVisualEffectView as contentView *before* adding the
      // NSHostingView subview with constraints.  See showAboutWindow()
      // comment for details on the crash this ordering prevents.
      let effectView = NSVisualEffectView()
      effectView.material = .windowBackground
      effectView.blendingMode = .behindWindow
      effectView.state = .active
      window.contentView = effectView

      let rootView: AnyView
      if let status = self.parsedStatus {
        rootView = AnyView(
          StatusPopoverView(
            status: status, rawOutput: self.statusOutput, unsealKey: self.unsealKey)
        )
      } else {
        rootView = AnyView(StatusErrorView(errorMessage: self.statusOutput))
      }
      let hostingView = NSHostingView(rootView: rootView)
      hostingView.translatesAutoresizingMaskIntoConstraints = false
      effectView.addSubview(hostingView)
      NSLayoutConstraint.activate([
        hostingView.leadingAnchor.constraint(equalTo: effectView.leadingAnchor),
        hostingView.trailingAnchor.constraint(equalTo: effectView.trailingAnchor),
        hostingView.topAnchor.constraint(equalTo: effectView.topAnchor),
        hostingView.bottomAnchor.constraint(equalTo: effectView.bottomAnchor)
      ])

      self.centerOnPointerScreen(window)

      window.isReleasedWhenClosed = false
      window.level = .floating
      window.delegate = self.windowDelegate
      self.activateApp()
      window.makeKeyAndOrderFront(nil)
      window.orderFrontRegardless()

      // Replacing an existing status window balances the consumer it
      // already registered; a brand-new window adds one.  Either way the
      // window is visible now, so ensure exactly one fast-refresh consumer
      // is attributed to it.
      if self.statusWindow == nil {
        self.beginFastRefresh()
      }
      self.statusWindow = window
    }
  }
}

// MARK: - VaultManager Lifecycle & Status

extension VaultManager {
  func startVault() {
    guard isVaultAvailable else { return }
    guard !isHelperUnavailable else {
      logger.warning("Cannot start Vault — helper is unavailable")
      return
    }

    Task {
      // Ensure the helper is reachable before attempting to start Vault.
      guard await xpc.ensureHelperReachable() else {
        logger.error("Aborting start — helper agent not reachable")
        self.isHelperUnavailable = true
        self.helperUnavailableReason = String(
          localized: """
            Cannot start Vault because vmenu's helper process is not responding. \
            Please try the recovery options below.
            """,
          comment: "Error message when helper becomes unavailable during operation"
        )
        return
      }

      // Create or update the plist via the helper.
      guard await xpc.createOrUpdatePlist() else {
        logger.error("Aborting start — plist creation failed")
        return
      }

      // Bootout any stale registration so we can cleanly bootstrap.
      _ = await xpc.bootoutService()

      // Atomically recreate the startup log via the helper.
      guard await xpc.recreateStartupLog() else {
        logger.error("Aborting start — could not recreate startup log")
        return
      }

      // Bootstrap loads the plist into launchd.
      if !(await xpc.bootstrapService()) {
        logger.error("Failed to bootstrap service")
        return
      }

      // Kick-start ensures the job actually runs (RunAtLoad is false).
      let kickstarted = await xpc.kickstartService()
      if !kickstarted {
        logger.error("Failed to kickstart Vault service — verifying via service status")
        // Give launchd a moment to settle, then check if the service
        // is actually running despite the kickstart exit code.
        try? await Task.sleep(nanoseconds: 500_000_000)
        let actuallyRunning = await xpc.checkServiceStatus()
        if !actuallyRunning {
          logger.error("Vault service is not running after kickstart failure")
          self.isRunning = false
          return
        }
      }

      self.isRunning = true
      await awaitVaultStartupAndVerify()
    }
  }

  /// Waits for Vault to write its startup log, verifies the process
  /// is still running, then parses environment variables and refreshes status.
  private func awaitVaultStartupAndVerify() async {
    // Wait for Vault to finish writing its startup log.
    try? await Task.sleep(nanoseconds: 2_000_000_000)
    let maxAttempts = 5
    for attempt in 0..<maxAttempts {
      if let logContent = await xpc.readStartupLog(),
        logContent.contains("VAULT_ADDR") {
        break
      }
      if attempt == maxAttempts - 1 {
        logger.warning("Vault startup log did not contain VAULT_ADDR after \(maxAttempts) attempts")
      }
      try? await Task.sleep(nanoseconds: 1_000_000_000)
    }

    // Verify Vault is still running after the startup wait — it may
    // have crashed during initialization.
    let stillRunning = await xpc.checkServiceStatus()
    if !stillRunning {
      logger.error("Vault process exited during startup")
      self.isRunning = false
      return
    }

    await self.parseEnvironmentVariables()
    self.refreshStatus()
  }

  func stopVault() {
    Task {
      _ = await xpc.bootoutService()
      _ = await xpc.removeCACertFile(atPath: self.vaultCACert)
      self.isRunning = false
      self.vaultAddr = ""
      self.vaultCACert = ""
      self.vaultToken = ""
      self.unsealKey = ""
      self.parsedStatus = nil
      self.httpClient.caCertData = nil
      self.httpClient.caCertPath = ""
    }
  }

  func restartVault() {
    Task {
      _ = await xpc.bootoutService()
      _ = await xpc.removeCACertFile(atPath: self.vaultCACert)
      self.isRunning = false
      self.vaultAddr = ""
      self.vaultCACert = ""
      self.vaultToken = ""
      self.unsealKey = ""
      self.parsedStatus = nil
      self.httpClient.caCertData = nil
      self.httpClient.caCertPath = ""

      try? await Task.sleep(nanoseconds: 1_000_000_000)
      self.startVault()
    }
  }

  /// Parse environment variables from the Vault startup log (read via XPC).
  internal func parseEnvironmentVariables() async {
    guard let content = await xpc.readStartupLog() else { return }

    let env = VmenuCore.parseEnvironmentVariables(from: content)

    // Validate VAULT_ADDR points to a loopback address.
    if !env.vaultAddr.isEmpty {
      if isLoopbackVaultAddr(env.vaultAddr) {
        vaultAddr = env.vaultAddr
      } else {
        logger.warning(
          "Ignoring non-loopback VAULT_ADDR: \(env.vaultAddr, privacy: .private)")
        vaultAddr = ""
      }
    }

    // Store the CA cert path. The helper validated it when writing. We
    // also ask the helper to read the cert data for TLS trust evaluation
    // since the sandbox prevents direct filesystem access.
    if !env.vaultCACert.isEmpty {
      vaultCACert = env.vaultCACert
      httpClient.caCertPath = env.vaultCACert
      // Read the CA cert data via XPC for TLS evaluation.
      await loadCACertData(path: env.vaultCACert)
    }

    // Validate the token contains only safe printable ASCII characters.
    if !env.vaultToken.isEmpty {
      if isValidVaultToken(env.vaultToken) {
        vaultToken = env.vaultToken
      } else {
        logger.warning("Ignoring invalid VAULT_TOKEN (unexpected characters or length)")
        vaultToken = ""
      }
    }

    // Validate the unseal key contains only base64 characters.
    if !env.unsealKey.isEmpty {
      if isValidVaultUnsealKey(env.unsealKey) {
        unsealKey = env.unsealKey
      } else {
        logger.warning("Ignoring invalid Unseal Key (unexpected characters or length)")
        unsealKey = ""
      }
    }
  }

  /// Ask the XPC helper to read the CA certificate file so the HTTP client
  /// can use it for TLS trust evaluation without sandbox-busting filesystem
  /// access.
  private func loadCACertData(path: String) async {
    // We use a dedicated XPC call to read the cert data.
    // The helper validates the path with the same checks as before.
    let certData = await XPCClient.shared.readCACertData(atPath: path)
    httpClient.caCertData = certData
  }

  /// Silently refresh parsed status without opening the status window.
  func refreshStatus() {
    guard isVaultAvailable, isRunning, !vaultAddr.isEmpty else { return }

    isRefreshing = true
    let addr = vaultAddr
    Task {
      let (output, parsed) = await httpClient.fetchVaultStatus(addr: addr)
      statusOutput = output
      parsedStatus = parsed
      isRefreshing = false
    }
  }

  func fetchStatus() {
    guard isVaultAvailable, !vaultAddr.isEmpty else { return }

    let addr = vaultAddr
    Task {
      let (output, parsed) = await httpClient.fetchVaultStatus(addr: addr)
      statusOutput = output
      parsedStatus = parsed
      showStatusWindow()
    }
  }
}

// MARK: - Clipboard Utility

/// Pasteboard type that signals clipboard managers to skip recording
/// this item.
///
/// This is the `org.nspasteboard.ConcealedType` convention adopted by
/// 1Password, iTerm2, Strongbox, and other macOS apps that copy
/// secrets.  When a clipboard manager sees this type on a pasteboard
/// item it should treat the contents as ephemeral / sensitive and not
/// persist them in history.
///
/// Reference: https://nspasteboard.org
private let concealedPasteboardType = NSPasteboard.PasteboardType(
  "org.nspasteboard.ConcealedType"
)

/// Copy text to the system clipboard.
///
/// When `autoExpire` is `true`:
/// - The `org.nspasteboard.ConcealedType` marker is added to the
///   pasteboard item so that clipboard managers (1Password, Maccy,
///   Paste, etc.) that respect the convention will not record the
///   value in their history.
/// - The clipboard is automatically cleared after 10 seconds if it
///   still contains the copied value.  This limits the window during
///   which other applications can read the secret via `NSPasteboard`.
///
/// Note: both protections are *best-effort*, not a strong guarantee.  The
/// concealed marker only defends against clipboard managers that honor the
/// convention, and the 10-second clear is racy against any process that
/// reads the pasteboard before it fires.  This is inherent to `NSPasteboard`
/// (any process can read the general pasteboard at any time) and acceptable
/// for a dev-mode secret, but it should not be mistaken for secure storage.
///
/// Shared implementation used by both `VaultMenuView` and
/// `StatusPopoverView` to avoid duplicated clipboard logic.
func copyToClipboard(_ text: String, autoExpire: Bool = false) {
  NSPasteboard.general.clearContents()
  NSPasteboard.general.setString(text, forType: .string)

  if autoExpire {
    // Mark the item as concealed so clipboard managers skip it.
    NSPasteboard.general.setString("", forType: concealedPasteboardType)

    let changeCount = NSPasteboard.general.changeCount
    DispatchQueue.main.asyncAfter(deadline: .now() + 10) {
      if NSPasteboard.general.changeCount == changeCount {
        NSPasteboard.general.clearContents()
      }
    }
  }
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
@MainActor
class MenuBarVisibilityMonitor {
  static let shared = MenuBarVisibilityMonitor()

  private var wasVisible = true
  private var hasNotifiedHidden = false
  private var timer: Timer?

  func startMonitoring(interval: TimeInterval = 5) {
    guard timer == nil else { return }
    DispatchQueue.main.asyncAfter(deadline: .now() + 3) { [weak self] in
      Task { @MainActor in
        self?.checkVisibility()
        self?.timer = Timer.scheduledTimer(
          withTimeInterval: interval,
          repeats: true
        ) { [weak self] _ in
          Task { @MainActor in
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

  private func checkVisibility() {
    let isVisible = findStatusBarWindowVisible()

    if wasVisible && !isVisible {
      if !hasNotifiedHidden {
        hasNotifiedHidden = true
        sendHiddenNotification()
      }
    } else if !wasVisible && isVisible {
      hasNotifiedHidden = false
    }

    wasVisible = isVisible
  }

  /// Weak cache of the window that hosts the status-bar button, so the
  /// recurring visibility check doesn't walk every window's full subview
  /// tree on each tick.  Re-scans only when the cached window has gone away
  /// or no longer hosts the button.
  private weak var cachedStatusWindow: NSWindow?

  private func statusBarWindow() -> NSWindow? {
    if let cached = cachedStatusWindow,
      NSApp.windows.contains(where: { $0 === cached }),
      cached.contentView?.findStatusBarButton() != nil {
      return cached
    }
    cachedStatusWindow = nil
    for window in NSApp.windows where window.contentView?.findStatusBarButton() != nil {
      cachedStatusWindow = window
      return window
    }
    return nil
  }

  private func findStatusBarWindowVisible() -> Bool {
    // No status-bar window found — treat as visible (the original behavior),
    // since absence usually means the icon hasn't been created yet rather
    // than that it was hidden.
    guard let window = statusBarWindow() else { return true }

    guard window.isVisible, window.occlusionState.contains(.visible) else {
      return false
    }

    let frame = window.frame
    if frame.width < 1 || frame.height < 1 {
      return false
    }

    return NSScreen.screens.contains { screen in
      screen.frame.intersects(frame)
    }
  }

  private static let hasAppBundle: Bool = {
    guard Bundle.main.bundleIdentifier != nil else { return false }
    guard Bundle.main.bundlePath.hasSuffix(".app") else { return false }
    return NSRunningApplication.current.activationPolicy != .prohibited
  }()

  private static func notificationCenter() -> UNUserNotificationCenter? {
    guard hasAppBundle else { return nil }
    return UNUserNotificationCenter.current()
  }

  private func sendHiddenNotification() {
    guard let center = Self.notificationCenter() else { return }

    // Use async API to stay on @MainActor instead of escaping into
    // a callback on an arbitrary UNUserNotification dispatch queue.
    Task { @MainActor in
      let settings = await center.notificationSettings()
      switch settings.authorizationStatus {
      case .denied:
        logger.info(
          "Notification permission denied — skipping menu bar visibility alert. Enable in System Settings > Notifications > vmenu."
        )
        return
      case .notDetermined:
        logger.info("Notification permission not determined — skipping alert")
        return
      default:
        break
      }

      let content = UNMutableNotificationContent()
      content.title = String(
        localized: "vmenu Icon Hidden",
        comment: "Notification title when menu bar icon is obscured by other icons")
      content.body = String(
        localized: """
          Your vmenu menu bar icon is currently hidden by macOS. \
          Try closing other menu bar apps or rearranging icons to make it visible again.
          """,
        comment: "Notification body explaining how to recover a hidden menu bar icon"
      )
      content.sound = .default

      let request = UNNotificationRequest(
        identifier: "vmenu-icon-hidden-\(UUID().uuidString)",
        content: content,
        trigger: nil
      )

      do {
        try await center.add(request)
      } catch {
        logger.error(
          "Failed to deliver menu bar visibility notification: \(error.localizedDescription, privacy: .public)"
        )
      }
    }
  }

  func requestNotificationPermission() {
    guard let center = Self.notificationCenter() else { return }

    // Use async API to stay on @MainActor instead of escaping into a
    // callback on UNUserNotificationServiceConnection's dispatch queue.
    // The callback-based requestAuthorization runs its completion handler
    // off the main thread, which violates @MainActor isolation on
    // macOS 26's strict Swift concurrency runtime and causes a crash
    // (dispatch_assert_queue_fail / EXC_BREAKPOINT).
    Task { @MainActor in
      do {
        let granted = try await center.requestAuthorization(options: [.alert, .sound])
        if !granted {
          logger.info(
            "Notification permission not granted — menu bar visibility alerts will be silent"
          )
        }
      } catch {
        logger.error(
          "Notification permission error: \(error.localizedDescription, privacy: .public)"
        )
      }
    }
  }
}

class AppDelegate: NSObject, NSApplicationDelegate {
  func applicationDidFinishLaunching(_ notification: Notification) {
    guard ensureSingleInstance() else { return }

    // Register the XPC helper agent with SMAppService so launchd can
    // start it on demand when the main app connects to the Mach service.
    registerHelperAgent()

    VaultManager.shared.performInitialCheck()
    VaultManager.shared.startPolling()

    MenuBarVisibilityMonitor.shared.requestNotificationPermission()
    MenuBarVisibilityMonitor.shared.startMonitoring()
  }

  func applicationWillTerminate(_ notification: Notification) {
    // Stop polling timers to release resources
    VaultManager.shared.stopPolling()
    MenuBarVisibilityMonitor.shared.stopMonitoring()
    // Invalidate XPC connection
    XPCClient.shared.invalidate()
  }

  @MainActor private func ensureSingleInstance() -> Bool {
    guard let bundleID = Bundle.main.bundleIdentifier else { return true }

    let runningInstances = NSRunningApplication.runningApplications(
      withBundleIdentifier: bundleID
    )

    if runningInstances.count > 1 {
      let alert = NSAlert()
      alert.messageText = String(
        localized: "vmenu is already running",
        comment: "Alert title when a second instance is launched")
      alert.informativeText = String(
        localized:
          "Another instance of vmenu is active in the menu bar. Only one instance can run at a time.",
        comment: "Alert body explaining only one instance is allowed"
      )
      alert.alertStyle = .warning
      alert.addButton(
        withTitle: String(
          localized: "OK", comment: "Dismiss button for the duplicate-instance alert"))
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
  private var vaultManager = VaultManager.shared

  private var displayState: VaultDisplayState {
    guard vaultManager.isRunning else { return .stopped }
    return vaultManager.isSealed ? .sealed : .running
  }

  /// Accessibility label for the menu bar icon so VoiceOver users can
  /// identify the app and its current state without seeing the icon.
  private var menuBarAccessibilityLabel: Text {
    switch displayState {
    case .stopped:
      return Text(
        "vmenu — Vault stopped",
        comment: "Menu bar icon accessibility label when Vault is stopped")
    case .sealed:
      return Text(
        "vmenu — Vault sealed",
        comment: "Menu bar icon accessibility label when Vault is sealed")
    case .running:
      return Text(
        "vmenu — Vault running",
        comment: "Menu bar icon accessibility label when Vault is running")
    }
  }

  var body: some Scene {
    MenuBarExtra {
      VaultMenuView()
    } label: {
      Image(nsImage: makeVaultMenuBarImage(state: displayState))
        .accessibilityLabel(menuBarAccessibilityLabel)
    }
    .menuBarExtraStyle(.window)
  }
}
