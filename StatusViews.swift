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
    .frame(width: 520, height: 560)
    .background(Color(nsColor: .windowBackgroundColor))
  }

  // MARK: - Hero Header

  private var heroHeader: some View {
    ZStack {
      // Subtle backdrop
      LinearGradient(
        colors: [Color(nsColor: .separatorColor).opacity(0.08), Color(nsColor: .separatorColor).opacity(0.02)],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
      )

      HStack(spacing: 14) {
        // Icon
        ZStack {
          Circle()
            .fill(Color(nsColor: .separatorColor).opacity(0.12))
            .frame(width: 44, height: 44)
          Image(systemName: "server.rack")
            .font(.system(size: 20, weight: .medium))
            .foregroundStyle(.secondary)
        }

        VStack(alignment: .leading, spacing: 3) {
          Text("Vault Server Status")
            .font(.system(size: 15, weight: .semibold))
          HStack(spacing: 6) {
            Text("v\(status.version)")
              .font(.system(size: 11, weight: .medium, design: .monospaced))
              .foregroundStyle(.secondary)
            if status.buildDate != "-" {
              Text("·")
                .foregroundStyle(.quaternary)
              Text(formatBuildDate(status.buildDate))
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
            }
          }
        }

        Spacer()

        sealStatusBadge
      }
      .padding(.horizontal, 18)
      .padding(.vertical, 14)
    }
    .frame(height: 72)
  }

  private var sealStatusBadge: some View {
    let label = isSealed ? "Sealed" : "Unsealed"
    let icon = isSealed ? "lock.fill" : "lock.open.fill"

    return HStack(spacing: 6) {
      Image(systemName: icon)
        .font(.system(size: 10, weight: .semibold))
      Text(label)
        .font(.system(size: 12, weight: .semibold))
    }
    .foregroundStyle(.secondary)
    .padding(.horizontal, 12)
    .padding(.vertical, 7)
    .background(
      Capsule()
        .fill(Color(nsColor: .separatorColor).opacity(0.12))
        .overlay(
          Capsule()
            .strokeBorder(Color(nsColor: .separatorColor).opacity(0.20), lineWidth: 0.5)
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
          icon: "square.grid.3x3.fill"
        )
        MetricTile(
          label: "Threshold",
          value: status.threshold,
          icon: "slider.horizontal.3"
        )
      }
    }
  }

  // MARK: - Cluster Card

  private var clusterCard: some View {
    CardView(title: "Cluster", icon: "circle.hexagongrid.fill") {
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
            Image(systemName: "minus.circle")
              .font(.caption)
              .foregroundStyle(.tertiary)
            Text("No cluster details available")
              .font(.system(size: 12))
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
          .font(.system(size: 11))
          .foregroundStyle(.secondary)
          .frame(width: 18)

        Group {
          if showUnsealKey {
            Text(unsealKey)
              .font(.system(size: 11, design: .monospaced))
              .lineLimit(1)
              .truncationMode(.middle)
          } else {
            Text(String(repeating: "•", count: 32))
              .font(.system(size: 11, design: .monospaced))
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
              .font(.system(size: 11))
              .foregroundStyle(.secondary)
              .frame(width: 24, height: 24)
              .contentShape(Rectangle())
          }
          .buttonStyle(.borderless)
          .help(showUnsealKey ? "Hide unseal key" : "Reveal unseal key")

          Button {
            copyToClipboard(unsealKey, autoExpire: true)
            unsealKeyCopied = true
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
              unsealKeyCopied = false
            }
          } label: {
            HStack(spacing: 3) {
              Image(systemName: unsealKeyCopied ? "checkmark" : "doc.on.clipboard")
                .font(.system(size: 10))
              Text(unsealKeyCopied ? "Copied" : "Copy")
                .font(.system(size: 10, weight: .medium))
            }
            .foregroundStyle(unsealKeyCopied ? .green : .secondary)
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(
              RoundedRectangle(cornerRadius: 5)
                .fill(Color(nsColor: .separatorColor).opacity(0.15))
            )
          }
          .buttonStyle(.borderless)
        }
      }
      .padding(10)
      .background(
        RoundedRectangle(cornerRadius: 8)
          .fill(Color(nsColor: .textBackgroundColor).opacity(0.5))
          .overlay(
            RoundedRectangle(cornerRadius: 8)
              .strokeBorder(Color(nsColor: .separatorColor).opacity(0.2), lineWidth: 0.5)
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
                .font(.system(size: 10))
              Text("Copy")
                .font(.system(size: 10, weight: .medium))
            }
            .foregroundStyle(.secondary)
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(
              RoundedRectangle(cornerRadius: 5)
                .fill(Color(nsColor: .separatorColor).opacity(0.15))
            )
          }
          .buttonStyle(.borderless)
        }

        Text(rawOutput)
          .font(.system(size: 11, design: .monospaced))
          .foregroundStyle(.secondary)
          .textSelection(.enabled)
          .fixedSize(horizontal: true, vertical: false)
          .padding(12)
          .frame(maxWidth: .infinity, alignment: .leading)
          .background(
            RoundedRectangle(cornerRadius: 8)
              .fill(Color(nsColor: .textBackgroundColor).opacity(0.5))
              .overlay(
                RoundedRectangle(cornerRadius: 8)
                  .strokeBorder(Color(nsColor: .separatorColor).opacity(0.15), lineWidth: 0.5)
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

  /// Copy text to the system clipboard.
  ///
  /// When `autoExpire` is `true` the clipboard is automatically cleared
  /// after 30 seconds if it still contains the copied value.
  private func copyToClipboard(_ text: String, autoExpire: Bool = false) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(text, forType: .string)

    if autoExpire {
      let changeCount = NSPasteboard.general.changeCount
      DispatchQueue.main.asyncAfter(deadline: .now() + 30) {
        if NSPasteboard.general.changeCount == changeCount {
          NSPasteboard.general.clearContents()
        }
      }
    }
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
        .fill(Color(nsColor: .controlBackgroundColor))
        .shadow(color: .black.opacity(0.04), radius: 2, y: 1)
        .overlay(
          RoundedRectangle(cornerRadius: 12)
            .strokeBorder(Color(nsColor: .separatorColor).opacity(0.3), lineWidth: 0.5)
        )
    )
  }

  private var sectionHeader: some View {
    Group {
      if isCollapsible, let binding = isExpanded {
        Button {
          withAnimation(.easeInOut(duration: 0.2)) {
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
        .font(.system(size: 11, weight: .semibold))
        .foregroundStyle(.secondary)
      Text(title)
        .font(.system(size: 12, weight: .semibold))
        .foregroundStyle(.secondary)
      Spacer()
      if let expanded {
        Image(systemName: "chevron.right")
          .font(.system(size: 9, weight: .bold))
          .foregroundStyle(.tertiary)
          .rotationEffect(.degrees(expanded ? 90 : 0))
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

  var body: some View {
    HStack(spacing: 8) {
      ZStack {
        RoundedRectangle(cornerRadius: 6)
          .fill(Color(nsColor: .separatorColor).opacity(0.10))
          .frame(width: 28, height: 28)
        Image(systemName: icon)
          .font(.system(size: 12, weight: .medium))
          .foregroundStyle(.secondary)
      }

      VStack(alignment: .leading, spacing: 1) {
        Text(label)
          .font(.system(size: 10))
          .foregroundStyle(.tertiary)
          .fixedSize(horizontal: true, vertical: false)
        Text(value)
          .font(.system(size: 13, weight: .semibold))
          .foregroundStyle(.primary)
          .fixedSize(horizontal: true, vertical: false)
      }

      Spacer(minLength: 0)
    }
    .padding(8)
    .background(
      RoundedRectangle(cornerRadius: 8)
        .fill(Color(nsColor: .textBackgroundColor).opacity(0.4))
        .overlay(
          RoundedRectangle(cornerRadius: 8)
            .strokeBorder(Color(nsColor: .separatorColor).opacity(0.12), lineWidth: 0.5)
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
          .font(.system(size: 10, weight: .medium))
          .foregroundStyle(.tertiary)
          .frame(width: 16)
        Text(label)
          .font(.system(size: 12))
          .foregroundStyle(.secondary)
          .frame(width: 40, alignment: .leading)
        Text(value)
          .font(
            isMonospaced
              ? .system(size: 12, design: .monospaced)
              : .system(size: 12, weight: .medium)
          )
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
        .fixedSize(horizontal: true, vertical: false)
      Spacer()
      Text(value)
        .font(.system(.caption, design: .monospaced))
        .fixedSize(horizontal: true, vertical: false)
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

      VStack(alignment: .leading, spacing: 2) {
        Text(label)
          .font(.caption2)
          .foregroundStyle(.secondary)
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

// MARK: - StatusErrorView

struct StatusErrorView: View {
  let errorMessage: String

  var body: some View {
    VStack(spacing: 20) {
      Spacer()

      ZStack {
        Circle()
          .fill(Color(nsColor: .separatorColor).opacity(0.10))
          .frame(width: 80, height: 80)
        Image(systemName: "exclamationmark.triangle.fill")
          .font(.system(size: 36))
          .foregroundStyle(.secondary)
      }

      VStack(spacing: 6) {
        Text("Unable to Reach Vault")
          .font(.system(size: 16, weight: .semibold))

        Text(errorMessage)
          .font(.system(size: 12))
          .foregroundStyle(.secondary)
          .multilineTextAlignment(.center)
          .lineSpacing(2)
          .padding(.horizontal, 24)
      }

      Button {
        NSApp.keyWindow?.close()
      } label: {
        Text("Dismiss")
          .font(.system(size: 13, weight: .medium))
          .padding(.horizontal, 24)
          .padding(.vertical, 8)
      }
      .buttonStyle(.borderedProminent)
      .keyboardShortcut(.return, modifiers: [])

      Spacer()
    }
    .padding(30)
    .frame(width: 340, height: 280)
    .background(Color(nsColor: .windowBackgroundColor))
  }
}
