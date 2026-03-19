import SwiftUI
import VmenuCore

// MARK: - StatusPopoverView

struct StatusPopoverView: View {
  let status: VaultStatus
  let rawOutput: String
  let unsealKey: String

  @State private var showRawOutput = false
  @State private var showUnsealKey = false
  @State private var unsealKeyCopied = false
  @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
  @Environment(\.colorSchemeContrast) private var colorSchemeContrast
  @ScaledMetric(relativeTo: .headline) private var heroIconCircleSize: CGFloat = 44
  @ScaledMetric(relativeTo: .caption) private var eyeButtonSize: CGFloat = 24

  private var isSealed: Bool {
    status.sealed != "false"
  }

  var body: some View {
    VStack(spacing: 0) {
      heroHeader
      ScrollView {
        VStack(spacing: 16) {
          serverInfoCard
          sealAndKeysCard
          clusterCard
          if !unsealKey.isEmpty {
            unsealKeyCard
          }
          rawOutputCard
        }
        .padding(20)
        .padding(.bottom, 4)
      }
    }
    .frame(minWidth: 400, idealWidth: 520, minHeight: 400, idealHeight: 560)
    // No explicit background — the NSVisualEffectView (.windowBackground,
    // .behindWindow) set up in showStatusWindow() provides the surface.
  }

  // MARK: - Hero Header

  private var heroHeader: some View {
    HStack(spacing: 14) {
      // Icon
      ZStack {
        Circle()
          .fill(Color(nsColor: .separatorColor).opacity(0.12))
          .frame(width: heroIconCircleSize, height: heroIconCircleSize)
        Image(systemName: "server.rack")
          .symbolRenderingMode(.hierarchical)
          .font(.title3)
          .fontWeight(.medium)
          .foregroundStyle(.secondary)
          .accessibilityHidden(true)
      }

      VStack(alignment: .leading, spacing: 3) {
        Text("Vault Server Status")
          .font(.headline)
        HStack(spacing: 6) {
          Text("v\(status.version)")
            .font(.system(.caption, design: .monospaced))
            .fontWeight(.medium)
            .foregroundStyle(.secondary)
          if status.buildDate != "-" {
            Text("·")
              .foregroundStyle(.quaternary)
            Text(formatBuildDate(status.buildDate))
              .font(.caption)
              .foregroundStyle(.secondary)
          }
        }
      }

      Spacer()

      sealStatusBadge
    }
    .padding(.horizontal, 18)
    .padding(.vertical, 14)
    .frame(minHeight: 72)
    // .ultraThinMaterial is visible in both Light and Dark Mode and adapts
    // to Reduce Transparency and Increase Contrast automatically.
    // Replaces the bespoke LinearGradient that was invisible in Dark Mode.
    .background(reduceTransparency
      ? AnyShapeStyle(Color(nsColor: .windowBackgroundColor))
      : AnyShapeStyle(.ultraThinMaterial))
  }

  private var sealStatusBadge: some View {
    let label = isSealed ? "Sealed" : "Unsealed"
    let icon = isSealed ? "lock.fill" : "lock.open.fill"
    // Use the tuned asset-catalog status colors so the badge communicates
    // seal state semantically and maintains contrast in both appearances.
    let tint: Color = isSealed ? Color("StatusSealed") : Color("StatusRunning")

    return HStack(spacing: 6) {
      Image(systemName: icon)
        .font(.caption2)
        .fontWeight(.semibold)
        .symbolReplaceTransition()
        .accessibilityHidden(true)
      Text(label)
        .font(.caption)
        .fontWeight(.semibold)
    }
    .foregroundStyle(tint)
    .padding(.horizontal, 12)
    .padding(.vertical, 7)
    .background(
      Capsule()
        .fill(tint.opacity(0.12))
        .overlay(
          Capsule()
            .strokeBorder(tint.opacity(0.25), lineWidth: 0.5)
        )
    )
  }

  // MARK: - Server Information Card

  private var serverInfoCard: some View {
    CardView(title: "Server", icon: "info.circle.fill") {
      LazyVGrid(columns: [
        GridItem(.flexible(), spacing: 10),
        GridItem(.flexible(), spacing: 10)
      ], spacing: 10) {
        MetricTile(
          label: "Version",
          value: status.version,
          icon: "tag.fill"
        )
        MetricTile(
          label: "Storage",
          value: status.storageType.capitalized,
          icon: "internaldrive.fill"
        )
        MetricTile(
          label: "Seal Type",
          value: status.sealType.capitalized,
          icon: "lock.shield.fill"
        )
        MetricTile(
          label: "HA Enabled",
          value: status.haEnabled.capitalized,
          icon: "arrow.triangle.2.circlepath"
        )
      }
    }
  }

  // MARK: - Seal & Keys Card

  private var sealAndKeysCard: some View {
    CardView(title: "Seal & Keys", icon: "key.fill") {
      HStack(spacing: 10) {
        MetricTile(
          label: "Initialized",
          value: status.initialized.capitalized,
          icon: "checkmark.seal.fill"
        )
        MetricTile(
          label: "Key Shares",
          value: status.totalShares,
          icon: "person.3.fill"
        )
        MetricTile(
          label: "Threshold",
          value: status.threshold,
          icon: "number.square.fill"
        )
      }
    }
  }

  // MARK: - Cluster Card

  private var clusterCard: some View {
    CardView(title: "Cluster", icon: "network") {
      VStack(spacing: 0) {
        if status.clusterName != "-" {
          ClusterDetailRow(
            label: "Name",
            value: status.clusterName,
            icon: "tag",
            isLast: status.clusterId == "-"
          )
        }
        if status.clusterId != "-" {
          ClusterDetailRow(
            label: "ID",
            value: status.clusterId,
            icon: "number",
            isMonospaced: true,
            isLast: true
          )
        }
        if status.clusterName == "-" && status.clusterId == "-" {
          HStack {
            Image(systemName: "info.circle")
              .font(.caption)
              .foregroundStyle(.tertiary)
              .accessibilityHidden(true)
            Text("No cluster details available")
              .font(.caption)
              .foregroundStyle(.tertiary)
            Spacer()
          }
          .padding(.vertical, 6)
        }
      }
    }
  }

  // MARK: - Unseal Key Card

  private var unsealKeyCard: some View {
    CardView(title: "Unseal Key", icon: "key.horizontal.fill") {
      HStack(spacing: 10) {
        Image(systemName: "key.fill")
          .font(.caption)
          .foregroundStyle(.secondary)
          .frame(width: 18)
          .accessibilityHidden(true)

        Group {
          if showUnsealKey {
            Text(unsealKey)
              .font(.system(.caption, design: .monospaced))
              .lineLimit(1)
              .truncationMode(.middle)
          } else {
            Text(String(repeating: "•", count: 32))
              .font(.system(.caption, design: .monospaced))
              .foregroundStyle(.tertiary)
          }
        }
        .textSelection(.enabled)

        Spacer(minLength: 4)

        HStack(spacing: 4) {
          Button {
            showUnsealKey.toggle()
          } label: {
            Image(systemName: showUnsealKey ? "eye.slash.fill" : "eye.fill")
              .font(.caption)
              .foregroundStyle(.secondary)
              .symbolReplaceTransition()
              .frame(width: eyeButtonSize, height: eyeButtonSize)
              .contentShape(Rectangle())
          }
          .buttonStyle(.borderless)
          .help(showUnsealKey ? "Hide unseal key" : "Reveal unseal key")
          .accessibilityLabel(showUnsealKey ? "Hide unseal key" : "Reveal unseal key")

          Button {
            copyToClipboard(unsealKey, autoExpire: true)
            unsealKeyCopied = true
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
              unsealKeyCopied = false
            }
          } label: {
            HStack(spacing: 3) {
              Image(systemName: unsealKeyCopied ? "checkmark.circle.fill" : "doc.on.clipboard")
                .font(.caption2)
                .symbolReplaceTransition()
                .accessibilityLabel(unsealKeyCopied ? "Copied" : "Copy to clipboard")
              Text(unsealKeyCopied ? "Copied" : "Copy")
                .font(.caption2)
                .fontWeight(.medium)
            }
            .foregroundStyle(unsealKeyCopied ? AnyShapeStyle(Color("CopyConfirmation")) : AnyShapeStyle(.secondary))
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(
              RoundedRectangle(cornerRadius: 5)
                // .ultraThinMaterial for small button chips on a material surface.
                .fill(reduceTransparency
                  ? AnyShapeStyle(Color(nsColor: .separatorColor).opacity(0.25))
                  : AnyShapeStyle(.ultraThinMaterial))
            )
          }
          .buttonStyle(.borderless)
        }
      }
      .padding(10)
      .background(
        RoundedRectangle(cornerRadius: 8)
          // .thinMaterial elevates this content block one step above the card
          // surface; adapts automatically to all system appearance settings.
          .fill(reduceTransparency
            ? AnyShapeStyle(Color(nsColor: .textBackgroundColor))
            : AnyShapeStyle(.thinMaterial))
          .overlay(
            RoundedRectangle(cornerRadius: 8)
              .strokeBorder(
                Color(nsColor: .separatorColor)
                  .opacity(colorSchemeContrast == .increased ? 0.5 : 0.2),
                lineWidth: colorSchemeContrast == .increased ? 1.0 : 0.5
              )
          )
      )
    }
  }

  // MARK: - Raw Output Card

  private var rawOutputCard: some View {
    CardView(
      title: "Raw Output",
      icon: "terminal.fill",
      isCollapsible: true,
      isExpanded: $showRawOutput
    ) {
      VStack(alignment: .leading, spacing: 8) {
        HStack {
          Spacer()
          Button {
            copyToClipboard(rawOutput)
          } label: {
            HStack(spacing: 3) {
              Image(systemName: "doc.on.clipboard")
                .font(.caption2)
                .accessibilityHidden(true)
              Text("Copy")
                .font(.caption2)
                .fontWeight(.medium)
            }
            .foregroundStyle(.secondary)
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(
              RoundedRectangle(cornerRadius: 5)
                .fill(reduceTransparency
                  ? AnyShapeStyle(Color(nsColor: .separatorColor).opacity(0.25))
                  : AnyShapeStyle(.ultraThinMaterial))
            )
          }
          .buttonStyle(.borderless)
        }

        Text(rawOutput)
          .font(.system(.caption, design: .monospaced))
          .foregroundStyle(.secondary)
          .textSelection(.enabled)
          .padding(12)
          .frame(maxWidth: .infinity, alignment: .leading)
          .background(
            RoundedRectangle(cornerRadius: 8)
              .fill(reduceTransparency
                ? AnyShapeStyle(Color(nsColor: .textBackgroundColor))
                : AnyShapeStyle(.thinMaterial))
              .overlay(
                RoundedRectangle(cornerRadius: 8)
                  .strokeBorder(
                    Color(nsColor: .separatorColor)
                      .opacity(colorSchemeContrast == .increased ? 0.5 : 0.15),
                    lineWidth: colorSchemeContrast == .increased ? 1.0 : 0.5
                  )
              )
          )
      }
    }
  }

  // MARK: - Helpers

  private func formatBuildDate(_ dateString: String) -> String {
    let isoFormatter = ISO8601DateFormatter()
    isoFormatter.formatOptions = [.withInternetDateTime]
    guard let date = isoFormatter.date(from: dateString) else {
      return dateString
    }
    let displayFormatter = DateFormatter()
    displayFormatter.dateStyle = .medium
    displayFormatter.timeStyle = .none
    return displayFormatter.string(from: date)
  }

}

// MARK: - CardView

/// A reusable island card container with a section header, optional collapse, and
/// inset content on a subtle elevated background.
private struct CardView<Content: View>: View {
  let title: String
  let icon: String
  var isCollapsible: Bool = false
  var isExpanded: Binding<Bool>?
  @ViewBuilder let content: () -> Content

  @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
  @Environment(\.accessibilityReduceMotion) private var reduceMotion
  @Environment(\.colorSchemeContrast) private var colorSchemeContrast
  @Environment(\.colorScheme) private var colorScheme

  var body: some View {
    VStack(alignment: .leading, spacing: 0) {
      // Section header
      sectionHeader
        .padding(.horizontal, 14)
        .padding(.top, 12)
        .padding(.bottom, 10)

      if isCollapsible {
        if isExpanded?.wrappedValue == true {
          contentBody
            .padding(.horizontal, 14)
            .padding(.bottom, 14)
        }
      } else {
        contentBody
          .padding(.horizontal, 14)
          .padding(.bottom, 14)
      }
    }
    .background(
      RoundedRectangle(cornerRadius: 12)
        // .regularMaterial is the semantic choice for content-layer cards:
        // adapts to Reduce Transparency, Increase Contrast, and Dark Mode.
        .fill(reduceTransparency
          ? AnyShapeStyle(Color(nsColor: .controlBackgroundColor))
          : AnyShapeStyle(.regularMaterial))
        // Shadow: suppress in Dark Mode where any shadow adds visual noise,
        // and strengthen slightly in Light Mode for card lift perception.
        .shadow(
          color: Color(nsColor: .shadowColor)
            .opacity(colorScheme == .dark ? 0.0 : 0.18),
          radius: 3,
          y: 1
        )
        .overlay(
          RoundedRectangle(cornerRadius: 12)
            .strokeBorder(
              Color(nsColor: .separatorColor)
                .opacity(colorSchemeContrast == .increased ? 0.6 : 0.3),
              lineWidth: colorSchemeContrast == .increased ? 1.0 : 0.5
            )
        )
    )
  }

  private var sectionHeader: some View {
    Group {
      if isCollapsible, let binding = isExpanded {
        Button {
          withAnimation(reduceMotion ? nil : .easeInOut(duration: 0.2)) {
            binding.wrappedValue.toggle()
          }
        } label: {
          headerContent(expanded: binding.wrappedValue)
        }
        .buttonStyle(.plain)
      } else {
        headerContent(expanded: nil)
      }
    }
  }

  private func headerContent(expanded: Bool?) -> some View {
    HStack(spacing: 7) {
      Image(systemName: icon)
        .font(.caption)
        .fontWeight(.semibold)
        .foregroundStyle(.secondary)
        .accessibilityHidden(true)
      Text(title)
        .font(.caption)
        .fontWeight(.semibold)
        .foregroundStyle(.secondary)
      Spacer()
      if let expanded {
        Image(systemName: "chevron.right")
          .font(.caption2)
          .fontWeight(.bold)
          .foregroundStyle(.tertiary)
          .rotationEffect(.degrees(expanded ? 90 : 0))
          .animation(reduceMotion ? nil : .easeInOut(duration: 0.2), value: expanded)
          .accessibilityHidden(true)
      }
    }
  }

  @ViewBuilder
  private var contentBody: some View {
    content()
  }
}

// MARK: - MetricTile

/// A compact, lozenge-shaped tile that shows a single metric with an icon,
/// label, and value — used in grid layouts inside cards.
private struct MetricTile: View {
  let label: String
  let value: String
  let icon: String

  @ScaledMetric(relativeTo: .caption2) private var iconBoxSize: CGFloat = 28
  @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
  @Environment(\.colorSchemeContrast) private var colorSchemeContrast

  var body: some View {
    HStack(spacing: 8) {
      ZStack {
        RoundedRectangle(cornerRadius: 6)
          // .ultraThinMaterial for the icon box so it separates from the tile
          // background while still adapting to all system appearance settings.
          .fill(reduceTransparency
            ? AnyShapeStyle(Color(nsColor: .separatorColor).opacity(0.18))
            : AnyShapeStyle(.ultraThinMaterial))
          .frame(width: iconBoxSize, height: iconBoxSize)
        Image(systemName: icon)
          .symbolRenderingMode(.hierarchical)
          .font(.caption)
          .fontWeight(.medium)
          .foregroundStyle(.secondary)
          .accessibilityHidden(true)
      }

      VStack(alignment: .leading, spacing: 1) {
        Text(label)
          .font(.caption2)
          .foregroundStyle(.tertiary)
          .lineLimit(1)
        Text(value)
          .font(.body)
          .fontWeight(.semibold)
          .foregroundStyle(.primary)
          .lineLimit(1)
      }

      Spacer(minLength: 0)
    }
    .padding(8)
    .background(
      RoundedRectangle(cornerRadius: 8)
        // .thinMaterial elevates the tile above the card's .regularMaterial,
        // creating the intended two-level depth hierarchy within the content
        // layer. Adapts automatically to Reduce Transparency and Increase Contrast.
        .fill(reduceTransparency
          ? AnyShapeStyle(Color(nsColor: .textBackgroundColor))
          : AnyShapeStyle(.thinMaterial))
        .overlay(
          RoundedRectangle(cornerRadius: 8)
            .strokeBorder(
              Color(nsColor: .separatorColor)
                .opacity(colorSchemeContrast == .increased ? 0.4 : 0.12),
              lineWidth: colorSchemeContrast == .increased ? 1.0 : 0.5
            )
        )
    )
  }
}

// MARK: - ClusterDetailRow

/// A single key-value row used in the cluster details section, with a subtle
/// separator between rows.
private struct ClusterDetailRow: View {
  let label: String
  let value: String
  let icon: String
  var isMonospaced: Bool = false
  var isLast: Bool = false

  var body: some View {
    VStack(spacing: 0) {
      HStack(spacing: 8) {
        Image(systemName: icon)
          .font(.caption2)
          .fontWeight(.medium)
          .foregroundStyle(.tertiary)
          .frame(width: 16)
          .accessibilityHidden(true)
        Text(label)
          .font(.caption)
          .foregroundStyle(.secondary)
          .frame(minWidth: 40, alignment: .leading)
        Text(value)
          .font(
            isMonospaced
              ? .system(.caption, design: .monospaced)
              : .caption
          )
          .fontWeight(isMonospaced ? .regular : .medium)
          .foregroundStyle(.primary)
          .lineLimit(1)
          .truncationMode(.middle)
          .textSelection(.enabled)
        Spacer()
      }
      .padding(.vertical, 8)

      if !isLast {
        Divider()
          .padding(.leading, 24)
      }
    }
  }
}

// MARK: - StatusRowView (kept for backward compatibility)

struct StatusRowView: View {
  let label: String
  let value: String

  var body: some View {
    HStack {
      Text(label)
        .font(.caption)
        .foregroundStyle(.secondary)
        .lineLimit(1)
      Spacer()
      Text(value)
        .font(.system(.caption, design: .monospaced))
        .lineLimit(1)
    }
  }
}

// MARK: - StatusItemView (kept for backward compatibility)

struct StatusItemView: View {
  let label: String
  let value: String
  let icon: String

  var body: some View {
    HStack(spacing: 8) {
      Image(systemName: icon)
        .font(.caption)
        .foregroundStyle(.secondary)
        .frame(width: 16)
        .accessibilityHidden(true)

      VStack(alignment: .leading, spacing: 2) {
        Text(label)
          .font(.caption2)
          .foregroundStyle(.secondary)
          .lineLimit(1)
        Text(value)
          .font(.subheadline)
          .fontWeight(.medium)
          .lineLimit(1)
      }

      Spacer()
    }
    .padding(10)
    .background(
      RoundedRectangle(cornerRadius: 8)
        .fill(.regularMaterial)
    )
  }
}

// MARK: - StatusErrorView

struct StatusErrorView: View {
  let errorMessage: String

  @ScaledMetric(relativeTo: .title) private var iconCircleSize: CGFloat = 80

  var body: some View {
    VStack(spacing: 20) {
      Spacer(minLength: 24)

      ZStack {
        Circle()
          // .ultraThinMaterial for the icon backdrop: visible in all
          // appearances and adapts to Reduce Transparency automatically.
          .fill(.ultraThinMaterial)
          .frame(width: iconCircleSize, height: iconCircleSize)
        Image(systemName: "exclamationmark.triangle.fill")
          .symbolRenderingMode(.hierarchical)
          .font(.title)
          .foregroundStyle(Color(nsColor: .systemOrange))
          .accessibilityLabel("Error")
      }

      VStack(spacing: 6) {
        Text("Unable to Reach Vault")
          .font(.headline)

        Text(errorMessage)
          .font(.caption)
          .foregroundStyle(.secondary)
          .multilineTextAlignment(.center)
          .lineSpacing(2)
          .padding(.horizontal, 24)
      }

      Button {
        NSApp.keyWindow?.close()
      } label: {
        Text("Dismiss")
          .font(.body)
          .fontWeight(.medium)
          .padding(.horizontal, 24)
          .padding(.vertical, 8)
      }
      .buttonStyle(.borderedProminent)
      .keyboardShortcut(.return, modifiers: [])

      Spacer(minLength: 48)
    }
    .padding(30)
    .frame(minWidth: 340, idealWidth: 340, minHeight: 280)
    // No explicit background — the NSVisualEffectView (.windowBackground,
    // .behindWindow) set up in showStatusWindow() provides the surface.
  }
}
