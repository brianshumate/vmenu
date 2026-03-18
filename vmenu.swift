import AppKit
import SwiftUI

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
            guard let separatorRange = trimmed.range(of: "\\s{2,}", options: .regularExpression) else {
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
    private var plistURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/com.hashicorp.vault.plist")
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
        pollingTimer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
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

    /* Periodically refresh `vault status` to keep seal state and other details
     * current. Uses a longer interval (30s) than the launchctl check since it
     * spawns a process and makes an HTTP request to the Vault server.
     */
    private func startStatusRefreshPolling(interval: TimeInterval = 30) {
        guard statusRefreshTimer == nil else { return }
        statusRefreshTimer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
            guard let self else { return }
            guard self.isRunning, self.isVaultAvailable else { return }
            self.refreshStatus()
        }
    }

    private var hasPerformedInitialCheck = false
    private var pollingTimer: Timer?
    private var statusRefreshTimer: Timer?

    // Synchronously check vault availability (safe to call from main thread)
    private func checkVaultAvailabilitySync() -> Bool {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/which")
        task.arguments = ["vault"]

        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = pipe

        do {
            try task.run()
            task.waitUntilExit()
            return task.terminationStatus == 0
        } catch {
            return false
        }
    }

    // Synchronously check vault launchctl status
    private func checkVaultStatusSync() -> Bool {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        task.arguments = ["list", plistLabel]

        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = pipe

        do {
            try task.run()
            task.waitUntilExit()
            return task.terminationStatus == 0
        } catch {
            return false
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
    private func expectedPlistContent() -> String {
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

    private func createOrUpdatePlist() {
        let plistContent = expectedPlistContent()

        let launchAgentsDir = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents")
        try? FileManager.default.createDirectory(at: launchAgentsDir, withIntermediateDirectories: true)

        if FileManager.default.fileExists(atPath: plistURL.path) {
            if let existing = try? String(contentsOf: plistURL, encoding: .utf8),
               existing == plistContent {
                return  // plist is already up to date
            }
            let unloadTask = Process()
            unloadTask.executableURL = URL(fileURLWithPath: "/bin/launchctl")
            unloadTask.arguments = ["unload", plistURL.path]
            try? unloadTask.run()
            unloadTask.waitUntilExit()
        }

        try? plistContent.write(to: plistURL, atomically: true, encoding: .utf8)
    }

    private func findVaultPath() -> String? {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/which")
        task.arguments = ["vault"]

        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = pipe

        do {
            try task.run()
            task.waitUntilExit()
            if task.terminationStatus == 0 {
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                let path = String(data: data, encoding: .utf8)?
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                return path
            }
        } catch {
            return nil
        }
        return nil
    }

    func startVault() {
        guard isVaultAvailable else { return }

        let plistPath = plistURL.path
        let label = plistLabel

        DispatchQueue.global(qos: .userInitiated).async {
            self.createOrUpdatePlist()

            let unloadTask = Process()
            unloadTask.executableURL = URL(fileURLWithPath: "/bin/launchctl")
            unloadTask.arguments = ["unload", plistPath]
            try? unloadTask.run()
            unloadTask.waitUntilExit()

            // Truncate startup log to avoid stale values from previous runs
            try? "".write(toFile: "/tmp/vault.startup.log", atomically: true, encoding: .utf8)

            let loadTask = Process()
            loadTask.executableURL = URL(fileURLWithPath: "/bin/launchctl")
            loadTask.arguments = ["load", plistPath]

            do {
                try loadTask.run()
                loadTask.waitUntilExit()
            } catch {
                print("Failed to load plist: \(error)")
            }

            let startTask = Process()
            startTask.executableURL = URL(fileURLWithPath: "/bin/launchctl")
            startTask.arguments = ["start", label]

            do {
                try startTask.run()
                DispatchQueue.main.async {
                    self.isRunning = true
                }

                /*
                * Wait for Vault to finish writing its startup log
                * If the log is still empty after the initial delay,
                * retry a few times before giving up.
                */
                DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 2) {
                    var attempts = 0
                    let maxAttempts = 5
                    while attempts < maxAttempts {
                        let logContent = (try? String(contentsOfFile: "/tmp/vault.startup.log", encoding: .utf8)) ?? ""
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
            } catch {
                print("Failed to start Vault: \(error)")
            }
        }
    }

    func stopVault() {
        let plistPath = plistURL.path

        DispatchQueue.global(qos: .userInitiated).async {
            let unloadTask = Process()
            unloadTask.executableURL = URL(fileURLWithPath: "/bin/launchctl")
            unloadTask.arguments = ["unload", plistPath]

            do {
                try unloadTask.run()
                unloadTask.waitUntilExit()
                DispatchQueue.main.async {
                    self.isRunning = false
                    self.vaultAddr = ""
                    self.vaultCACert = ""
                    self.parsedStatus = nil
                }
            } catch {
                print("Failed to stop Vault: \(error)")
            }
        }
    }

    func restartVault() {
        let plistPath = plistURL.path

        DispatchQueue.global(qos: .userInitiated).async {
            let unloadTask = Process()
            unloadTask.executableURL = URL(fileURLWithPath: "/bin/launchctl")
            unloadTask.arguments = ["unload", plistPath]

            do {
                try unloadTask.run()
                unloadTask.waitUntilExit()
                DispatchQueue.main.async {
                    self.isRunning = false
                    self.vaultAddr = ""
                    self.vaultCACert = ""
                    self.parsedStatus = nil
                }
            } catch {
                print("Failed to stop Vault: \(error)")
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

        /* Iterate in reverse so we always pick up the values from the most
         * recent Vault launch (operational log is appended to across restarts)
        */
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

    // Run `vault status` off the main thread and return
    private func runVaultStatus() -> (String, VaultStatus?) {
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
        if !vaultAddr.isEmpty { env["VAULT_ADDR"] = vaultAddr }
        if !vaultCACert.isEmpty { env["VAULT_CACERT"] = vaultCACert }
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
        DispatchQueue.global(qos: .userInitiated).async {
            let (output, parsed) = self.runVaultStatus()
            DispatchQueue.main.async {
                self.statusOutput = output
                self.parsedStatus = parsed
                self.isRefreshing = false
            }
        }
    }

    func fetchStatus() {
        guard isVaultAvailable else { return }

        DispatchQueue.global(qos: .userInitiated).async {
            let (output, parsed) = self.runVaultStatus()
            DispatchQueue.main.async {
                self.statusOutput = output
                self.parsedStatus = parsed
                self.showStatusWindow()
            }
        }
    }

    private var statusWindow: NSWindow?

    func showStatusWindow() {
        // Close existing status window if open
        if let existing = statusWindow {
            existing.close()
        }

        // Dismiss MenuBarExtra popover so it doesn't cover the status window
        for window in NSApp.windows where type(of: window) != NSWindow.self {
            if window.isVisible,
               window.level.rawValue > NSWindow.Level.normal.rawValue,
               window.className.contains("StatusBar") || window.className.contains("MenuBar") {
                window.orderOut(nil)
            }
        }

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
        NSApp.activate(ignoringOtherApps: true)

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
                    Text("Vault Dev Mode")
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
                            detailRow(label: "Address", value: vaultManager.vaultAddr, icon: "network")
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
        menuButton(title: "Quit vmenu", icon: "power", shortcut: "⌘Q") {
            NSApplication.shared.terminate(nil)
        }
        .padding(.vertical, 4)
        .padding(.horizontal, 4)
    }

    // MARK: - Helpers

    private func menuButton(title: String, icon: String, shortcut: String? = nil, action: @escaping () -> Void) -> some View {
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
                StatusItemView(label: "Storage", value: status.storageType, icon: "internaldrive")
                StatusItemView(label: "Seal Type", value: status.sealType, icon: "lock.shield")
                StatusItemView(label: "HA Enabled", value: status.haEnabled, icon: "heart.fill")
            }

            HStack(spacing: 16) {
                StatusItemView(label: "Initialized", value: status.initialized.capitalized, icon: "checkmark.circle")
                StatusItemView(label: "Key Shares", value: status.totalShares, icon: "number")
                StatusItemView(label: "Key Threshold", value: status.threshold, icon: "slider.horizontal.3")
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

// Represents the three visual states of the menu bar icon
enum VaultDisplayState {
    case stopped
    case sealed
    case running

    var dotColor: NSColor {
        switch self {
        case .stopped: return .systemRed
        case .sealed:  return .systemOrange
        case .running: return .systemGreen
        }
    }

    var swiftUIColor: Color {
        switch self {
        case .stopped: return .red
        case .sealed:  return .orange
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

    // Menu bar icon color.
    let composite = NSImage(size: size, flipped: false) { rect in
        let path = trianglePath(in: rect)
        NSColor.white.setStroke()
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

class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        VaultManager.shared.performInitialCheck()
        VaultManager.shared.startPolling()
    }
}

@main
struct vmenuApp: App {
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
