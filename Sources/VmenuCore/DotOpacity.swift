import Foundation

/// Compute the opacity for a loading indicator dot based on its distance from
/// the currently active dot. Matches the logic in `DottedLoadingIndicator`.
public func dotOpacity(index: Int, active: Int, dotCount: Int) -> Double {
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
