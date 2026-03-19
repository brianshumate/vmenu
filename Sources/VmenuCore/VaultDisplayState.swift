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
    case .sealed: return .systemOrange
    case .running: return .systemGreen
    }
  }

  public var swiftUIColor: Color {
    // Use NSColor.system* so the color adapts between light and dark
    // appearances — matching the behaviour of dotColor above — rather
    // than resolving to a fixed sRGB value as Color.red/.orange/.green do.
    //
    // The app target additionally defines named asset-catalog colors
    // (StatusStopped / StatusSealed / StatusRunning) with four variants
    // each (light, dark, light-high-contrast, dark-high-contrast).
    // Those are loaded by the UI layer via Color("StatusRunning") etc.
    // Here we use the NSColor dynamic equivalents so this model type
    // remains independent of the app bundle's asset catalog.
    switch self {
    case .stopped: return Color(nsColor: .systemRed)
    case .sealed:  return Color(nsColor: .systemOrange)
    case .running: return Color(nsColor: .systemGreen)
    }
  }

  /// Derive the display state from running and seal status.
  public static func from(isRunning: Bool, isSealed: Bool) -> VaultDisplayState {
    guard isRunning else { return .stopped }
    return isSealed ? .sealed : .running
  }
}
