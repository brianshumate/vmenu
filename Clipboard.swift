import AppKit

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
  func findStatusBarButton() -> NSStatusBarButton? {
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

  /// Pin this view and all of its descendant `NSVisualEffectView`s to the
  /// `.active` state.
  ///
  /// A `behindWindow` effect view in the `.inactive` state stops compositing
  /// vibrancy and renders fully transparent.  AppKit flips the popover's own
  /// effect view to `.inactive` once it resigns key, which is what lets the
  /// desktop bleed through the menu.  Re-asserting `.active` keeps every region
  /// opaque.  See `MenuPopoverWindowFixer`.
  func pinVisualEffectStatesActive() {
    if let effectView = self as? NSVisualEffectView {
      effectView.state = .active
    }
    for subview in subviews {
      subview.pinVisualEffectStatesActive()
    }
  }

  /// The outermost `NSHostingView` ancestor of this view, i.e. the SwiftUI
  /// content host for the enclosing window.
  ///
  /// Walks the superview chain and returns the last hosting view found, which
  /// is the root host whose `fittingSize` reflects the whole SwiftUI tree.
  /// Matched by class name because `NSHostingView` is generic and has no
  /// non-generic base class to test against.
  func enclosingHostingView() -> NSView? {
    var result: NSView?
    var view: NSView? = self
    while let current = view {
      if String(describing: type(of: current)).contains("HostingView") {
        result = current
      }
      view = current.superview
    }
    return result
  }
}
