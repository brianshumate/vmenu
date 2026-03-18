import AppKit
import SwiftUI

/// Represents the three visual states of the menu bar icon.
public enum VaultDisplayState {
    case stopped
    case sealed
    case running

    public var dotColor: NSColor {
        switch self {
        case .stopped: return .systemRed
        case .sealed:  return .systemOrange
        case .running: return .systemGreen
        }
    }

    public var swiftUIColor: Color {
        switch self {
        case .stopped: return .red
        case .sealed:  return .orange
        case .running: return .green
        }
    }

    /// Derive the display state from running and seal status.
    public static func from(isRunning: Bool, isSealed: Bool) -> VaultDisplayState {
        guard isRunning else { return .stopped }
        return isSealed ? .sealed : .running
    }
}
