import AppKit
import SwiftUI
import VmenuCore

// MARK: - Symbol Effect Helpers

/// Applies `.contentTransition(.symbolEffect(.replace))` for animated
/// SF Symbol transitions.
extension View {
  func symbolReplaceTransition() -> some View {
    self.contentTransition(.symbolEffect(.replace))
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
                  : AnyShapeStyle(Color("CopyConfirmation"))
              )
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
                : AnyShapeStyle(.secondary)
            )
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
    .accessibilityLabel(
      Text(
        "\(label). Double-tap to copy.",
        comment: "VoiceOver label for an environment variable copy row")
    )
    .accessibilityValue(
      isSensitive && !isRevealed
        ? Text("Hidden", comment: "VoiceOver value when a sensitive field is masked")
        : Text(value))
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
      .accessibilityLabel(
        Text("Loading", comment: "VoiceOver label for the loading indicator"))
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
      .accessibilityLabel(
        Text("Loading", comment: "VoiceOver label for the loading indicator"))
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
  private var vaultManager = VaultManager.shared
  @State private var copyFeedback: String?
  @Environment(\.accessibilityDifferentiateWithoutColor) private var differentiateWithoutColor
  @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
  @Environment(\.colorSchemeContrast) private var colorSchemeContrast
  @Environment(\.colorScheme) private var colorScheme
  @ScaledMetric(relativeTo: .caption) private var statusDotSize: CGFloat = 8

  var body: some View {
    VStack(alignment: .leading, spacing: 0) {
      if vaultManager.isHelperUnavailable {
        helperUnavailableView
      } else if !vaultManager.isVaultAvailable {
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

  /// View shown when the XPC helper is unavailable.
  ///
  /// Provides clear explanation of the problem and recovery options.
  private var helperUnavailableView: some View {
    VStack(spacing: 0) {
      VStack(spacing: 12) {
        Image(systemName: "exclamationmark.shield.fill")
          .symbolRenderingMode(.hierarchical)
          .font(.largeTitle)
          .foregroundStyle(Color(nsColor: .systemRed))
          .accessibilityLabel(
            Text("Error", comment: "Accessibility label for the error icon"))

        Text("Helper Unavailable", comment: "Heading when the XPC helper cannot be reached")
          .font(.headline)
          .fontWeight(.bold)

        Text(vaultManager.helperUnavailableReason)
          .font(.caption)
          .foregroundStyle(.secondary)
          .multilineTextAlignment(.center)
          .fixedSize(horizontal: false, vertical: true)
          .padding(.horizontal, 8)

        VStack(spacing: 8) {
          Button(
            String(
              localized: "Try Recovery",
              comment: "Button to attempt helper recovery")
          ) {
            vaultManager.attemptHelperRecovery()
          }
          .buttonStyle(.borderedProminent)
          .controlSize(.small)

          Button(
            String(
              localized: "Open Login Items Settings",
              comment: "Button to open System Settings Login Items")
          ) {
            vaultManager.openHelperSettings()
          }
          .buttonStyle(.bordered)
          .controlSize(.small)
        }
      }
      .padding(16)

      Divider()
        .padding(.horizontal, 8)

      VStack(spacing: 2) {
        menuButton(
          title: String(
            localized: "About vmenu", comment: "Menu button to open the About window"),
          icon: "info.circle.fill"
        ) {
          VaultManager.shared.showAboutWindow()
        }
        menuButton(
          title: String(
            localized: "Quit vmenu", comment: "Menu button to quit the application"),
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

  private var missingVaultView: some View {
    VStack(spacing: 0) {
      VStack(spacing: 12) {
        Image(systemName: "exclamationmark.triangle.fill")
          .symbolRenderingMode(.hierarchical)
          .font(.largeTitle)
          .foregroundStyle(Color(nsColor: .systemOrange))
          .accessibilityLabel(
            Text("Warning", comment: "Accessibility label for the warning icon"))

        Text("Vault Not Found", comment: "Heading when Vault is not installed")
          .font(.headline)
          .fontWeight(.bold)

        Text(
          "Vault was not found on this Mac.\nInstall it with Homebrew:",
          comment: "Explanation when Vault is not installed"
        )
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
              .fill(
                reduceTransparency
                  ? AnyShapeStyle(Color(nsColor: .textBackgroundColor))
                  : AnyShapeStyle(.regularMaterial))
          )

        Button(
          String(
            localized: "Download from HashiCorp",
            comment: "Button to open Vault download page")
        ) {
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
          title: String(
            localized: "Quit vmenu", comment: "Menu button to quit the application"),
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
          .fill(
            reduceTransparency
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
                label: String(
                  localized: "Address",
                  comment: "Label for the Vault server network address"),
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
            .fill(
              reduceTransparency
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
      case .sealed: return Color("StatusSealed")
      case .running: return Color("StatusRunning")
      }
    }()
    let label: String = {
      switch displayState {
      case .stopped:
        return String(
          localized: "Stopped", comment: "Vault server state label — not running")
      case .sealed:
        return String(
          localized: "Sealed", comment: "Vault server state label — running but sealed")
      case .running:
        return String(
          localized: "Running", comment: "Vault server state label — running and unsealed"
        )
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
        .fill(
          reduceTransparency
            ? AnyShapeStyle(Color(nsColor: .separatorColor))
            : AnyShapeStyle(.ultraThinMaterial)
        )
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
    .accessibilityLabel(
      Text("Vault status: \(label)", comment: "VoiceOver label for the server status badge"))
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
        .fill(
          reduceTransparency
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
      Text(
        sealed
          ? String(localized: "Sealed", comment: "Vault seal status — data is locked")
          : String(
            localized: "Unsealed", comment: "Vault seal status — data is accessible")
      )
      .font(.caption2)
      .fontWeight(.medium)
    }
    .foregroundStyle(.secondary)
    .padding(.horizontal, 7)
    .padding(.vertical, 3)
    .background(
      Capsule()
        .fill(
          reduceTransparency
            ? AnyShapeStyle(Color(nsColor: .separatorColor).opacity(0.4))
            : AnyShapeStyle(.ultraThinMaterial))
    )
    .help(
      sealed
        ? String(
          localized:
            "Vault is sealed — its data is encrypted and inaccessible until unsealed",
          comment: "Tooltip explaining sealed state")
        : String(
          localized: "Vault is unsealed — its data is decrypted and ready for use",
          comment: "Tooltip explaining unsealed state"))
  }

  private var controlSection: some View {
    VStack(spacing: 2) {
      menuButton(
        title: vaultManager.isRunning
          ? String(
            localized: "Stop Server", comment: "Menu button to stop the Vault server")
          : String(
            localized: "Start Server", comment: "Menu button to start the Vault server"),
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
        title: String(
          localized: "Restart Server", comment: "Menu button to restart the Vault server"),
        icon: "arrow.clockwise.circle.fill",
        shortcut: "⌘R"
      ) {
        vaultManager.restartVault()
      }
      .disabled(!vaultManager.isVaultAvailable || !vaultManager.isRunning)

      menuButton(
        title: String(
          localized: "Show Server Details",
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
          .help(
            String(
              localized: "The network address where Vault is listening",
              comment: "Tooltip for VAULT_ADDR"))
      }
      if !vaultManager.vaultCACert.isEmpty {
        envCopyRow(label: "VAULT_CACERT", value: vaultManager.vaultCACert)
          .help(
            String(
              localized:
                "Path to the certificate authority file used for TLS verification",
              comment: "Tooltip for VAULT_CACERT"))
      }
      if !vaultManager.vaultToken.isEmpty {
        envCopyRow(label: "VAULT_TOKEN", value: vaultManager.vaultToken, isSensitive: true)
          .help(
            String(
              localized: "The authentication token used to access Vault",
              comment: "Tooltip for VAULT_TOKEN"))
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
      menuButton(
        title: String(
          localized: "About vmenu", comment: "Menu button to open the About window"),
        icon: "info.circle.fill"
      ) {
        VaultManager.shared.showAboutWindow()
      }
      menuButton(
        title: String(
          localized: "Quit vmenu", comment: "Menu button to quit the application"),
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
    Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.22"
  }()

  private let buildNumber: String = {
    Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "1.22"
  }()

  @ScaledMetric(relativeTo: .title2) private var appIconSize: CGFloat = 64

  var body: some View {
    VStack(spacing: 16) {
      Image(nsImage: NSApp.applicationIconImage)
        .resizable()
        .aspectRatio(contentMode: .fit)
        .frame(width: appIconSize, height: appIconSize)
        .accessibilityLabel(
          Text("vmenu app icon", comment: "Accessibility label for the application icon"))

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

      Text(
        "A macOS menu bar app for Vault.",
        comment: "Short app description in the About window"
      )
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
          .tint(Color(nsColor: .linkColor))

        Button(
          String(
            localized: "GitHub Repository", comment: "Link to the project's GitHub page"
          )
        ) {
          if let url = URL(string: "https://github.com/brianshumate/vmenu") {
            NSWorkspace.shared.open(url)
          }
        }
        .buttonStyle(.link)
        .font(.caption)
        .tint(Color(nsColor: .linkColor))
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
func makeVaultMenuBarImage(state: VaultDisplayState = .stopped) -> NSImage {
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
