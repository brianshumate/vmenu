import SwiftUI

struct StatusPopoverView: View {
  let status: VaultStatus
  let rawOutput: String
  let unsealKey: String

  @State private var showRawOutput = false
  @State private var showUnsealKey = false
  @State private var unsealKeyCopied = false

  var body: some View {
    VStack(spacing: 0) {
      headerView
      Divider()
      ScrollView {
        VStack(alignment: .leading, spacing: 16) {
          statusSection
          clusterSection
          if !unsealKey.isEmpty {
            unsealKeySection
          }
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
        Text("Vault server status")
          .font(.headline)
        Text("Dev mode server")
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

  private var unsealKeySection: some View {
    VStack(alignment: .leading, spacing: 12) {
      Text("Unseal Key")
        .font(.subheadline)
        .fontWeight(.semibold)
        .foregroundColor(.secondary)

      VStack(spacing: 8) {
        HStack(spacing: 8) {
          Image(systemName: "key.fill")
            .font(.caption)
            .foregroundColor(.accentColor)
            .frame(width: 16)

          if showUnsealKey {
            Text(unsealKey)
              .font(.system(.caption, design: .monospaced))
              .lineLimit(1)
              .truncationMode(.middle)
          } else {
            Text(String(repeating: "•", count: 32))
              .font(.system(.caption, design: .monospaced))
              .foregroundColor(.secondary)
          }

          Spacer()

          Button {
            showUnsealKey.toggle()
          } label: {
            Image(systemName: showUnsealKey ? "eye.slash" : "eye")
              .font(.caption)
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
            Label(
              unsealKeyCopied ? "Copied" : "Copy",
              systemImage: unsealKeyCopied ? "checkmark" : "doc.on.clipboard"
            )
            .font(.caption)
          }
          .buttonStyle(.borderless)
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
