import AppKit
import OSLog
import Security
import ServiceManagement
import SwiftUI
import UserNotifications
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

    /// CA certificate data cached from the helper.
    /// The sandboxed app cannot read arbitrary filesystem paths, so the helper
    /// reads the CA cert file and passes the raw data back over XPC for TLS
    /// trust evaluation.
    var caCertData: Data?

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
            let msg = String(
                localized: "Unable to reach the Vault server. Check that it is running and try again.\n\nDetails: \(error.localizedDescription)",
                comment: "Error message when Vault HTTP API is unreachable"
            )
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

        // When no CA cert data is available, fail closed: reject the
        // connection rather than falling through to the system trust store.
        // Vault dev-mode TLS certs are not in the system store, so this
        // prevents silent fallback that could mask configuration errors.
        guard let certData = caCertData, !certData.isEmpty else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        guard let cert = loadCertificate(from: certData) else {
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
class XPCClient {
    static let shared = XPCClient()

    private var connection: NSXPCConnection?

    /// Serial queue protecting `connection`.
    ///
    /// Replaces the previous `NSLock`-based approach.  `NSLock` is not
    /// reentrant, so if `conn.resume()` triggered an immediate
    /// invalidation callback while `getConnection()` held the lock the
    /// app would deadlock.  A serial `DispatchQueue` naturally serialises
    /// access and the `async` dispatch in the handlers avoids reentrancy.
    private let connectionQueue = DispatchQueue(label: "com.brianshumate.vmenu.xpc-connection")

    /// Obtain (or create) the XPC connection to the helper.
    private func getConnection() -> NSXPCConnection {
        connectionQueue.sync {
            if let existing = connection {
                return existing
            }

            let conn = NSXPCConnection(
                machServiceName: vmenuHelperMachServiceName,
                options: []
            )
            conn.remoteObjectInterface = NSXPCInterface(with: VmenuHelperProtocol.self)
            conn.invalidationHandler = { [weak self] in
                self?.connectionQueue.async {
                    self?.connection = nil
                }
            }
            conn.interruptionHandler = { [weak self] in
                self?.connectionQueue.async {
                    self?.connection = nil
                }
            }
            conn.resume()
            connection = conn
            return conn
        }
    }

    /// Get a typed proxy to the helper, calling `errorHandler` on XPC failure.
    func proxy(errorHandler: @escaping (Error) -> Void) -> VmenuHelperProtocol? {
        let conn = getConnection()
        return conn.remoteObjectProxyWithErrorHandler(errorHandler) as? VmenuHelperProtocol
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

    // MARK: - Async wrappers

    /// Async wrapper around `findVaultPath`.
    func findVaultPath() async -> String? {
        await withCheckedContinuation { continuation in
            guard let helper = proxy() else {
                continuation.resume(returning: nil)
                return
            }
            helper.findVaultPath { path in
                continuation.resume(returning: path)
            }
        }
    }

    /// Async wrapper around `createOrUpdatePlist`.
    func createOrUpdatePlist() async -> Bool {
        await withCheckedContinuation { continuation in
            guard let helper = proxy() else {
                continuation.resume(returning: false)
                return
            }
            helper.createOrUpdatePlist { success in
                continuation.resume(returning: success)
            }
        }
    }

    /// Async wrapper around `bootstrapService`.
    func bootstrapService() async -> Bool {
        await withCheckedContinuation { continuation in
            guard let helper = proxy() else {
                continuation.resume(returning: false)
                return
            }
            helper.bootstrapService { success in
                continuation.resume(returning: success)
            }
        }
    }

    /// Async wrapper around `bootoutService`.
    func bootoutService() async -> Bool {
        await withCheckedContinuation { continuation in
            guard let helper = proxy() else {
                continuation.resume(returning: false)
                return
            }
            helper.bootoutService { success in
                continuation.resume(returning: success)
            }
        }
    }

    /// Async wrapper around `kickstartService`.
    func kickstartService() async -> Bool {
        await withCheckedContinuation { continuation in
            guard let helper = proxy() else {
                continuation.resume(returning: false)
                return
            }
            helper.kickstartService { success in
                continuation.resume(returning: success)
            }
        }
    }

    /// Async wrapper around `checkServiceStatus`.
    func checkServiceStatus() async -> Bool {
        await withCheckedContinuation { continuation in
            guard let helper = proxy() else {
                continuation.resume(returning: false)
                return
            }
            helper.checkServiceStatus { running in
                continuation.resume(returning: running)
            }
        }
    }

    /// Async wrapper around `readStartupLog`.
    func readStartupLog() async -> String? {
        await withCheckedContinuation { continuation in
            guard let helper = proxy() else {
                continuation.resume(returning: nil)
                return
            }
            helper.readStartupLog { content in
                continuation.resume(returning: content)
            }
        }
    }

    /// Async wrapper around `recreateStartupLog`.
    func recreateStartupLog() async -> Bool {
        await withCheckedContinuation { continuation in
            guard let helper = proxy() else {
                continuation.resume(returning: false)
                return
            }
            helper.recreateStartupLog { success in
                continuation.resume(returning: success)
            }
        }
    }

    /// Async wrapper around `readCACertData`.
    func readCACertData(atPath path: String) async -> Data? {
        await withCheckedContinuation { continuation in
            guard let helper = proxy() else {
                continuation.resume(returning: nil)
                return
            }
            helper.readCACertData(atPath: path) { data in
                continuation.resume(returning: data)
            }
        }
    }

    /// Async wrapper around `removeCACertFile`.
    func removeCACertFile(atPath path: String) async -> Bool {
        await withCheckedContinuation { continuation in
            guard let helper = proxy() else {
                continuation.resume(returning: false)
                return
            }
            helper.removeCACertFile(atPath: path) { success in
                continuation.resume(returning: success)
            }
        }
    }
}

// MARK: - SMAppService helper registration

/// Register the XPC helper agent with `SMAppService` so launchd knows
/// to start it when the main app connects to the Mach service.
///
/// The helper's launchd plist must be embedded in the app bundle at:
///   `Contents/Library/LaunchAgents/com.brianshumate.vmenu.helper.plist`
///
/// `SMAppService.agent(plistName:)` requires macOS 13+, which matches
/// vmenu's deployment target.
func registerHelperAgent() {
    let service = SMAppService.agent(
        plistName: "com.brianshumate.vmenu.helper.plist"
    )
    do {
        try service.register()
    } catch {
        // Already registered is fine (e.g. across relaunches).
        let nsError = error as NSError
        // kSMErrorAlreadyRegistered = 6 (ServiceManagement framework)
        if nsError.domain == "SMAppService" && nsError.code == 1 {
            // Already registered — nothing to do.
        } else {
            logger.error("Failed to register helper agent: \(error.localizedDescription, privacy: .public)")
        }
    }
}

// MARK: - VaultManager

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

    /// XPC client for communicating with the unsandboxed helper agent.
    private let xpc = XPCClient.shared

    /// Window references for status and about panels.
    var statusWindow: NSWindow?
    var aboutWindow: NSWindow?

    /// Is Vault sealed?
    var isSealed: Bool {
        guard let status = parsedStatus else { return true }
        return status.sealed != "false"
    }

    private var hasPerformedInitialCheck = false
    private var pollingTimer: Timer?
    private var statusRefreshTimer: Timer?

    init() {
        // Defer all process work to avoid re-entrant run loop
    }

    func performInitialCheck() {
        guard !hasPerformedInitialCheck else { return }
        hasPerformedInitialCheck = true

        Task {
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

    /// Background timer that periodically checks whether Vault is running.
    func startPolling(interval: TimeInterval = 10) {
        guard pollingTimer == nil else { return }
        pollingTimer = Timer.scheduledTimer(
            withTimeInterval: interval,
            repeats: true
        ) { [weak self] _ in
            guard let self else { return }
            Task { @MainActor in
                let running = await self.xpc.checkServiceStatus()
                if self.isRunning != running {
                    self.isRunning = running
                    if running {
                        await self.parseEnvironmentVariables()
                        self.refreshStatus()
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
            Task { @MainActor in
                guard self.isRunning, self.isVaultAvailable else { return }
                self.refreshStatus()
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
        for window in NSApp.windows {
            guard let button = window.contentView?.findStatusBarButton() else {
                continue
            }
            button.performClick(nil)
            return
        }
    }

    /// Activate the application, bridging the API change between macOS 13 and 14+.
    private func activateApp() {
        if #available(macOS 14.0, *) {
            NSApp.activate()
        } else {
            NSApp.activate(ignoringOtherApps: true)
        }
    }

    func showAboutWindow() {
        if let existing = aboutWindow {
            aboutWindow = nil
            existing.orderOut(nil)
        }

        dismissMenuBarExtra()

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

        // Force layout so the hosting controller can size the window to
        // fit its SwiftUI content *before* we center.  Without this,
        // center() runs against the initial 320×300 contentRect and
        // SwiftUI resizes the window afterwards, pushing it upward
        // against the menu bar.
        window.layoutIfNeeded()
        window.center()
        window.makeKeyAndOrderFront(nil)
        activateApp()

        aboutWindow = window
    }

    func showStatusWindow() {
        if let existing = statusWindow {
            statusWindow = nil
            existing.orderOut(nil)
        }

        dismissMenuBarExtra()

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 540, height: 580),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.title = String(localized: "Vault Server Status", comment: "Title for the status detail window")
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
        if let status = parsedStatus {
            rootView = AnyView(
                StatusPopoverView(
                    status: status, rawOutput: statusOutput, unsealKey: unsealKey)
            )
        } else {
            rootView = AnyView(StatusErrorView(errorMessage: statusOutput))
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

        window.center()
        window.isReleasedWhenClosed = false
        window.level = .floating
        window.makeKeyAndOrderFront(nil)
        activateApp()

        statusWindow = window
    }
}

// MARK: - VaultManager Lifecycle & Status

extension VaultManager {
    func startVault() {
        guard isVaultAvailable else { return }

        Task {
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
            _ = await xpc.kickstartService()

            self.isRunning = true

            // Wait for Vault to finish writing its startup log.
            try? await Task.sleep(nanoseconds: 2_000_000_000)
            let maxAttempts = 5
            for _ in 0..<maxAttempts {
                if let logContent = await xpc.readStartupLog(),
                    logContent.contains("VAULT_ADDR") {
                    break
                }
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }

            await self.parseEnvironmentVariables()
            self.refreshStatus()
        }
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
                logger.warning("Ignoring non-loopback VAULT_ADDR: \(env.vaultAddr, privacy: .private)")
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

// MARK: - Symbol Effect Helpers

/// Applies `.contentTransition(.symbolEffect(.replace))` on macOS 14+ and
/// falls back to a plain view on macOS 13.  Keeps call sites clean while
/// respecting the macOS 13 deployment target.
extension View {
    @ViewBuilder
    func symbolReplaceTransition() -> some View {
        if #available(macOS 14.0, *) {
            self.contentTransition(.symbolEffect(.replace))
        } else {
            self
        }
    }
}

struct MenuRowButton: View {
    let title: String
    let icon: String
    var shortcut: String? = nil
    let action: () -> Void

    @ScaledMetric(relativeTo: .body) private var iconWidth: CGFloat = 20
    @State private var isHovered = false
    @Environment(\.isEnabled) private var isEnabled

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                Image(systemName: icon)
                    .font(.caption)
                    .frame(width: iconWidth)
                    .accessibilityHidden(true)
                Text(title)
                    .font(.body)
                Spacer()
                if let shortcut {
                    Text(shortcut)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .foregroundStyle(
                isHovered && isEnabled
                    ? AnyShapeStyle(Color(nsColor: .selectedMenuItemTextColor))
                    : AnyShapeStyle(.primary)
            )
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

    @ScaledMetric(relativeTo: .body) private var iconWidth: CGFloat = 20
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
                        .font(.caption)
                        .foregroundStyle(
                            isHovered
                                ? AnyShapeStyle(Color(nsColor: .selectedMenuItemTextColor))
                                : AnyShapeStyle(Color.accentColor)
                        )
                        .frame(width: iconWidth)
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(label)
                            .font(.caption)
                            .fontWeight(.medium)
                            .foregroundStyle(
                                isHovered
                                    ? AnyShapeStyle(Color(nsColor: .selectedMenuItemTextColor))
                                    : AnyShapeStyle(.primary))
                        Text(displayValue)
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(
                                isHovered
                                    ? AnyShapeStyle(
                                        Color(nsColor: .selectedMenuItemTextColor).opacity(0.7))
                                    : AnyShapeStyle(.secondary)
                            )
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                    Spacer()
                    if copyFeedback == label {
                        Image(systemName: "checkmark.circle.fill")
                            .font(.caption2)
                            .fontWeight(.bold)
                            .foregroundStyle(
                                isHovered
                                    ? AnyShapeStyle(Color(nsColor: .selectedMenuItemTextColor))
                                    : AnyShapeStyle(Color("CopyConfirmation")))
                            .accessibilityHidden(true)
                    } else {
                        Text("Copy", comment: "Button label to copy a value to the clipboard")
                            .font(.caption2)
                            .foregroundStyle(
                                isHovered
                                    ? AnyShapeStyle(
                                        Color(nsColor: .selectedMenuItemTextColor).opacity(0.7))
                                    : AnyShapeStyle(.secondary))
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
                    Image(systemName: isRevealed ? "eye.slash.fill" : "eye.fill")
                        .font(.caption2)
                        .foregroundStyle(
                            isHovered
                                ? AnyShapeStyle(
                                    Color(nsColor: .selectedMenuItemTextColor).opacity(0.7))
                                : AnyShapeStyle(.secondary))
                        .symbolReplaceTransition()
                }
                .buttonStyle(.borderless)
                .focusable(false)
                .help(isRevealed ? "Hide \(label)" : "Reveal \(label)")
                .accessibilityLabel(isRevealed ? "Hide \(label)" : "Reveal \(label)")
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
        .accessibilityElement(children: .combine)
        .accessibilityLabel(Text("\(label). Double-tap to copy.", comment: "VoiceOver label for an environment variable copy row"))
        .accessibilityValue(isSensitive && !isRevealed ? Text("Hidden", comment: "VoiceOver value when a sensitive field is masked") : Text(value))
    }
}

/// Loading indicator.
///
/// Respects the Reduce Motion accessibility setting: when enabled, all dots
/// are shown at a uniform static opacity instead of animating.
struct DottedLoadingIndicator: View {
    let dotCount: Int
    let dotSize: CGFloat
    let spacing: CGFloat

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    init(dotCount: Int = 5, dotSize: CGFloat = 4, spacing: CGFloat = 6) {
        self.dotCount = dotCount
        self.dotSize = dotSize
        self.spacing = spacing
    }

    var body: some View {
        if reduceMotion {
            // Static representation: all dots at uniform opacity.
            HStack(spacing: spacing) {
                ForEach(0..<dotCount, id: \.self) { _ in
                    Circle()
                        .fill(Color.secondary)
                        .frame(width: dotSize, height: dotSize)
                        .opacity(0.6)
                }
            }
            .accessibilityElement()
            .accessibilityLabel(Text("Loading", comment: "VoiceOver label for the loading indicator"))
        } else {
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
            .accessibilityElement()
            .accessibilityLabel(Text("Loading", comment: "VoiceOver label for the loading indicator"))
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
    @Environment(\.accessibilityDifferentiateWithoutColor) private var differentiateWithoutColor
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @Environment(\.colorSchemeContrast) private var colorSchemeContrast
    @Environment(\.colorScheme) private var colorScheme
    @ScaledMetric(relativeTo: .caption) private var statusDotSize: CGFloat = 8

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if !vaultManager.isVaultAvailable {
                missingVaultView
            } else {
                headerSection
                Divider()
                    .padding(.horizontal, 8)
                controlSection
                if vaultManager.isRunning {
                    Divider()
                        .padding(.horizontal, 8)
                    environmentSection
                }
                Divider()
                    .padding(.horizontal, 8)
                quitSection
            }
        }
        .frame(minWidth: 320, idealWidth: 360)
    }

    private var missingVaultView: some View {
        VStack(spacing: 0) {
            VStack(spacing: 12) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .symbolRenderingMode(.hierarchical)
                    .font(.largeTitle)
                    .foregroundStyle(Color(nsColor: .systemOrange))
                    .accessibilityLabel(Text("Warning", comment: "Accessibility label for the warning icon"))

                Text("Vault Not Found", comment: "Heading when Vault is not installed")
                    .font(.headline)
                    .fontWeight(.bold)

                Text("Vault was not found on this Mac.\nInstall it with Homebrew:", comment: "Explanation when Vault is not installed")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)

                Text("brew install hashicorp/tap/vault")
                    .font(.system(.caption, design: .monospaced))
                    .padding(.horizontal, 10)
                    .padding(.vertical, 4)
                    .background(
                        RoundedRectangle(cornerRadius: 6)
                            // .regularMaterial adapts to Reduce Transparency,
                            // Increase Contrast, and Dark Mode automatically.
                            .fill(reduceTransparency
                                ? AnyShapeStyle(Color(nsColor: .textBackgroundColor))
                                : AnyShapeStyle(.regularMaterial))
                    )

                Button(String(localized: "Download from HashiCorp", comment: "Button to open Vault download page")) {
                    if let url = URL(
                        string:
                            "https://developer.hashicorp.com/vault/tutorials/getting-started/getting-started-install"
                    ) {
                        NSWorkspace.shared.open(url)
                    }
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.small)
            }
            .padding(16)

            Divider()
                .padding(.horizontal, 8)

            VStack(spacing: 2) {
                menuButton(
                    title: String(localized: "Quit vmenu", comment: "Menu button to quit the application"),
                    icon: "xmark.circle.fill",
                    shortcut: "⌘Q"
                ) {
                    NSApplication.shared.terminate(nil)
                }
            }
            .padding(.vertical, 4)
            .padding(.horizontal, 4)
        }
    }

    private var headerSection: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: "lock.shield.fill")
                    .symbolRenderingMode(.hierarchical)
                    .font(.title2)
                    .fontWeight(.semibold)
                    .foregroundStyle(.secondary)
                    .accessibilityHidden(true)

                VStack(alignment: .leading, spacing: 1) {
                    Text("Vault Dev Mode", comment: "Header title for the Vault dev server section")
                        .font(.headline)
                        .foregroundStyle(.primary)
                }

                Spacer()

                statusBadge
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            .background(
                RoundedRectangle(cornerRadius: 8)
                    // .thinMaterial sits one level above the popover surface,
                    // adapts to Reduce Transparency and Increase Contrast, and
                    // allows the system Liquid Glass to show through correctly.
                    .fill(reduceTransparency
                        ? AnyShapeStyle(Color(nsColor: .controlBackgroundColor))
                        : AnyShapeStyle(.thinMaterial))
            )
            .padding(.horizontal, 8)
            .padding(.top, 8)

            if vaultManager.isRunning {
                VStack(spacing: 6) {
                    if let status = vaultManager.parsedStatus {
                        if !vaultManager.vaultAddr.isEmpty {
                            detailRow(
                                label: String(localized: "Address", comment: "Label for the Vault server network address"),
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
                        .fill(reduceTransparency
                            ? AnyShapeStyle(Color(nsColor: .controlBackgroundColor))
                            : AnyShapeStyle(.thinMaterial))
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
        // Use the tuned asset-catalog colors (four variants each: light, dark,
        // light+HC, dark+HC) rather than the generic NSColor.system* values
        // returned by VaultDisplayState.swiftUIColor.
        let stateColor: Color = {
            switch displayState {
            case .stopped: return Color("StatusStopped")
            case .sealed:  return Color("StatusSealed")
            case .running: return Color("StatusRunning")
            }
        }()
        let label: String = {
            switch displayState {
            case .stopped: return String(localized: "Stopped", comment: "Vault server state label — not running")
            case .sealed: return String(localized: "Sealed", comment: "Vault server state label — running but sealed")
            case .running: return String(localized: "Running", comment: "Vault server state label — running and unsealed")
            }
        }()
        // Provide a distinct icon per state so that color is never the sole
        // differentiator, satisfying the accessibilityDifferentiateWithoutColor
        // setting and the HIG requirement for color-independent status indicators.
        let stateIcon: String = {
            switch displayState {
            case .stopped: return "stop.fill"
            case .sealed: return "lock.fill"
            case .running: return "checkmark.circle.fill"
            }
        }()

        return HStack(spacing: 5) {
            if differentiateWithoutColor {
                // Replace the plain dot with a shape-distinct icon so the state
                // is unambiguous without relying on colour.
                Image(systemName: stateIcon)
                    .font(.system(.caption2, weight: .bold))
                    .foregroundStyle(stateColor)
                    .accessibilityHidden(true)
            } else {
                Circle()
                    .fill(stateColor)
                    .frame(width: statusDotSize, height: statusDotSize)
                    // Reduce glow intensity in Dark Mode: a 0.6-opacity colored
                    // shadow bleeds visibly against dark surroundings.
                    .shadow(
                        color: stateColor.opacity(colorScheme == .dark ? 0.35 : 0.55),
                        radius: colorScheme == .dark ? 4 : 3
                    )
            }
            Text(label)
                .font(.caption)
                .fontWeight(.semibold)
        }
        .foregroundStyle(.secondary)
        .padding(.horizontal, 10)
        .padding(.vertical, 5)
        .background(
            Capsule()
                // .ultraThinMaterial is the semantic choice for a small badge
                // floating within the functional layer: it adapts to Reduce
                // Transparency and Increase Contrast automatically.
                .fill(reduceTransparency
                    ? AnyShapeStyle(Color(nsColor: .separatorColor))
                    : AnyShapeStyle(.ultraThinMaterial))
                .overlay(
                    Capsule()
                        .strokeBorder(
                            Color(nsColor: .separatorColor)
                                .opacity(colorSchemeContrast == .increased ? 0.6 : 0.0),
                            lineWidth: colorSchemeContrast == .increased ? 1.0 : 0.0
                        )
                )
        )
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("Vault status: \(label)", comment: "VoiceOver label for the server status badge"))
    }

    private func detailRow(label: String, value: String, icon: String) -> some View {
        HStack(spacing: 6) {
            Image(systemName: icon)
                .font(.caption2)
                .fontWeight(.medium)
                .foregroundStyle(.secondary)
                .frame(width: 14)
                .accessibilityHidden(true)
            Text(label)
                .font(.caption)
                .fontWeight(.medium)
                .foregroundStyle(.secondary)
            Text(value)
                .font(.system(.caption, design: .monospaced))
                .fontWeight(.medium)
                .foregroundStyle(.primary)
                .lineLimit(1)
            Spacer()
        }
    }

    private func detailPill(label: String, icon: String) -> some View {
        HStack(spacing: 3) {
            Image(systemName: icon)
                .font(.caption2)
                .accessibilityHidden(true)
            Text(label)
                .font(.caption2)
                .fontWeight(.medium)
        }
        .foregroundStyle(.secondary)
        .padding(.horizontal, 7)
        .padding(.vertical, 3)
        .background(
            Capsule()
                // .ultraThinMaterial for small informational pills:
                // adapts automatically to all accessibility settings.
                .fill(reduceTransparency
                    ? AnyShapeStyle(Color(nsColor: .separatorColor).opacity(0.4))
                    : AnyShapeStyle(.ultraThinMaterial))
        )
    }

    private func sealStatusPill(sealed: Bool) -> some View {
        HStack(spacing: 3) {
            Image(systemName: sealed ? "lock.fill" : "lock.open.fill")
                .font(.caption2)
                .symbolReplaceTransition()
                .accessibilityHidden(true)
            Text(sealed
                ? String(localized: "Sealed", comment: "Vault seal status — data is locked")
                : String(localized: "Unsealed", comment: "Vault seal status — data is accessible"))
                .font(.caption2)
                .fontWeight(.medium)
        }
        .foregroundStyle(.secondary)
        .padding(.horizontal, 7)
        .padding(.vertical, 3)
        .background(
            Capsule()
                .fill(reduceTransparency
                    ? AnyShapeStyle(Color(nsColor: .separatorColor).opacity(0.4))
                    : AnyShapeStyle(.ultraThinMaterial))
        )
        .help(sealed
            ? String(localized: "Vault is sealed — its data is encrypted and inaccessible until unsealed", comment: "Tooltip explaining sealed state")
            : String(localized: "Vault is unsealed — its data is decrypted and ready for use", comment: "Tooltip explaining unsealed state"))
    }

    private var controlSection: some View {
        VStack(spacing: 2) {
            menuButton(
                title: vaultManager.isRunning
                    ? String(localized: "Stop Server", comment: "Menu button to stop the Vault server")
                    : String(localized: "Start Server", comment: "Menu button to start the Vault server"),
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

            menuButton(
                title: String(localized: "Restart Server", comment: "Menu button to restart the Vault server"),
                icon: "arrow.clockwise.circle.fill",
                shortcut: "⌘R"
            ) {
                vaultManager.restartVault()
            }
            .disabled(!vaultManager.isVaultAvailable || !vaultManager.isRunning)

            menuButton(
                title: String(
                    localized: "Display Server Status",
                    comment: "Menu button to open the status window"
                ),
                icon: "chart.bar.doc.horizontal.fill",
                shortcut: "⌘I"
            ) {
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
                    .help(String(localized: "The network address where Vault is listening", comment: "Tooltip for VAULT_ADDR"))
            }
            if !vaultManager.vaultCACert.isEmpty {
                envCopyRow(label: "VAULT_CACERT", value: vaultManager.vaultCACert)
                    .help(String(localized: "Path to the certificate authority file used for TLS verification", comment: "Tooltip for VAULT_CACERT"))
            }
            if !vaultManager.vaultToken.isEmpty {
                envCopyRow(label: "VAULT_TOKEN", value: vaultManager.vaultToken, isSensitive: true)
                    .help(String(localized: "The authentication token used to access Vault", comment: "Tooltip for VAULT_TOKEN"))
            }
        }
        .padding(.vertical, 4)
        .padding(.horizontal, 4)
    }

    private func envCopyRow(label: String, value: String, isSensitive: Bool = false) -> some View {
        EnvCopyRowButton(
            label: label, value: value, isSensitive: isSensitive, copyFeedback: $copyFeedback
        ) {
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
            menuButton(title: String(localized: "About vmenu", comment: "Menu button to open the About window"), icon: "info.circle.fill") {
                VaultManager.shared.showAboutWindow()
            }
            menuButton(
                title: String(localized: "Quit vmenu", comment: "Menu button to quit the application"),
                icon: "xmark.circle.fill",
                shortcut: "⌘Q"
            ) {
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

}

struct AboutView: View {
    private let appVersion: String = {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.16"
    }()

    private let buildNumber: String = {
        Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "1.16"
    }()

    @ScaledMetric(relativeTo: .title2) private var appIconSize: CGFloat = 64

    var body: some View {
        VStack(spacing: 16) {
            Image(nsImage: NSApp.applicationIconImage)
                .resizable()
                .aspectRatio(contentMode: .fit)
                .frame(width: appIconSize, height: appIconSize)
                .accessibilityLabel(Text("vmenu app icon", comment: "Accessibility label for the application icon"))

            VStack(spacing: 4) {
                Text("vmenu")
                    .font(.title2)
                    .fontWeight(.bold)
                Text(
                    "Version \(appVersion)" + (buildNumber != appVersion ? " (\(buildNumber))" : "")
                )
                .font(.caption)
                .foregroundStyle(.secondary)
            }

            Text("A macOS menu bar app for Vault.", comment: "Short app description in the About window")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .lineSpacing(2)

            Divider()
                .padding(.horizontal, 40)

            VStack(spacing: 4) {
                Text("Made with ❤️ and 🤖 by [Brian Shumate](https://brianshumate.com/)")
                    .font(.caption)
                    .fontWeight(.medium)
                    .foregroundStyle(.primary)
                    .tint(.blue)

                Button(String(localized: "GitHub Repository", comment: "Link to the project's GitHub page")) {
                    if let url = URL(string: "https://github.com/brianshumate/vmenu") {
                        NSWorkspace.shared.open(url)
                    }
                }
                .buttonStyle(.link)
                .font(.caption)
                .tint(.blue)
            }

        }
        .padding(24)
        .frame(minWidth: 280, idealWidth: 320)
    }
}

/// Dynamic menu bar image (red: stopped, orange: sealed, green: running).
///
/// The triangle outline is drawn using `NSColor.labelColor` which adapts
/// to light/dark menu bar automatically.  The colored status dot is drawn
/// with the state's semantic color (red/orange/green) and the image is
/// marked non-template so AppKit preserves those colors rather than
/// re-tinting everything to a single monochrome value.
private func makeVaultMenuBarImage(state: VaultDisplayState = .stopped) -> NSImage {
    let size = NSSize(width: 20, height: 18)

    func trianglePath(in rect: NSRect) -> NSBezierPath {
        let inset: CGFloat = 3.0
        let path = NSBezierPath()
        path.move(to: NSPoint(x: inset, y: rect.maxY - inset))
        path.line(to: NSPoint(x: rect.maxX - inset, y: rect.maxY - inset))
        path.line(to: NSPoint(x: rect.midX, y: inset))
        path.close()
        path.lineWidth = 1.5
        path.lineJoinStyle = .round
        return path
    }

    // isTemplate = false so AppKit renders the image with its actual drawn
    // colors.  NSColor.labelColor resolves to the correct foreground color
    // for the current menu bar appearance (black on light, white on dark)
    // without needing template mode.  The dot uses the state's semantic
    // color (red / orange / green) which would be stripped to monochrome
    // if isTemplate were true.
    let composite = NSImage(size: size, flipped: false) { rect in
        let path = trianglePath(in: rect)
        NSColor.labelColor.setStroke()
        path.stroke()

        // Filled dot at the triangle's visual centroid — color-coded by state:
        //   stopped → red   sealed → orange   running → green
        let dotRadius: CGFloat = 2.0
        let inset: CGFloat = 3.0
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
    // Keep isTemplate = false so the state-colored dot is rendered as-is.
    // AppKit template mode strips all color to a single tint, which would
    // make the dot white/black regardless of Vault's actual state.
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

    private func findStatusBarWindowVisible() -> Bool {
        for window in NSApp.windows {
            guard window.contentView?.findStatusBarButton() != nil else { continue }

            guard window.isVisible, window.occlusionState.contains(.visible) else {
                return false
            }

            let frame = window.frame
            if frame.width < 1 || frame.height < 1 {
                return false
            }

            let onAnyScreen = NSScreen.screens.contains { screen in
                screen.frame.intersects(frame)
            }
            return onAnyScreen
        }

        return true
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

        let content = UNMutableNotificationContent()
        content.title = String(localized: "vmenu Icon Hidden", comment: "Notification title when menu bar icon is obscured by other icons")
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

        center.add(request) { error in
            if let error {
                logger.error(
                    "Failed to deliver menu bar visibility notification: \(error.localizedDescription, privacy: .public)"
                )
            }
        }
    }

    func requestNotificationPermission() {
        guard let center = Self.notificationCenter() else { return }

        center.requestAuthorization(options: [.alert, .sound]) { granted, error in
            if let error {
                logger.error("Notification permission error: \(error.localizedDescription, privacy: .public)")
            }
            if !granted {
                logger.info("Notification permission not granted — menu bar visibility alerts will be silent")
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
        XPCClient.shared.invalidate()
    }

    private func ensureSingleInstance() -> Bool {
        guard let bundleID = Bundle.main.bundleIdentifier else { return true }

        let runningInstances = NSRunningApplication.runningApplications(
            withBundleIdentifier: bundleID
        )

        if runningInstances.count > 1 {
            let alert = NSAlert()
            alert.messageText = String(localized: "vmenu is already running", comment: "Alert title when a second instance is launched")
            alert.informativeText = String(
                localized: "Another instance of vmenu is active in the menu bar. Only one instance can run at a time.",
                comment: "Alert body explaining only one instance is allowed"
            )
            alert.alertStyle = .warning
            alert.addButton(withTitle: String(localized: "OK", comment: "Dismiss button for the duplicate-instance alert"))
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

    /// Accessibility label for the menu bar icon so VoiceOver users can
    /// identify the app and its current state without seeing the icon.
    private var menuBarAccessibilityLabel: Text {
        switch displayState {
        case .stopped:
            return Text("vmenu — Vault stopped", comment: "Menu bar icon accessibility label when Vault is stopped")
        case .sealed:
            return Text("vmenu — Vault sealed", comment: "Menu bar icon accessibility label when Vault is sealed")
        case .running:
            return Text("vmenu — Vault running", comment: "Menu bar icon accessibility label when Vault is running")
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
