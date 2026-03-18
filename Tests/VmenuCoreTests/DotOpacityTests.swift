@testable import VmenuCore
import XCTest

final class DotOpacityTests: XCTestCase {

    func testActiveDotIsFullOpacity() {
        XCTAssertEqual(dotOpacity(index: 2, active: 2, dotCount: 5), 1.0)
    }

    func testFirstDotActiveIsFullOpacity() {
        XCTAssertEqual(dotOpacity(index: 0, active: 0, dotCount: 5), 1.0)
    }

    func testLastDotActiveIsFullOpacity() {
        XCTAssertEqual(dotOpacity(index: 4, active: 4, dotCount: 5), 1.0)
    }

    func testAdjacentDotIsHalfOpacity() {
        XCTAssertEqual(dotOpacity(index: 1, active: 2, dotCount: 5), 0.5)
        XCTAssertEqual(dotOpacity(index: 3, active: 2, dotCount: 5), 0.5)
    }

    func testDistantDotIsMinOpacity() {
        XCTAssertEqual(dotOpacity(index: 0, active: 3, dotCount: 5), 0.15)
    }

    func testWrapAroundAdjacent() {
        // Index 0 and active 4 in a 5-dot ring: distance = min(4, 1) = 1
        XCTAssertEqual(dotOpacity(index: 0, active: 4, dotCount: 5), 0.5)
    }

    func testWrapAroundAdjacentReverse() {
        // Index 4 and active 0 in a 5-dot ring: distance = min(4, 1) = 1
        XCTAssertEqual(dotOpacity(index: 4, active: 0, dotCount: 5), 0.5)
    }

    func testWrapAroundDistant() {
        // Index 0 and active 2 in a 5-dot ring: distance = min(2, 3) = 2
        XCTAssertEqual(dotOpacity(index: 0, active: 2, dotCount: 5), 0.15)
    }

    func testTwoDotsActive() {
        // With 2 dots: index 0, active 1 → distance = min(1, 1) = 1
        XCTAssertEqual(dotOpacity(index: 0, active: 1, dotCount: 2), 0.5)
    }

    func testThreeDotsOpposites() {
        // With 3 dots: index 0, active 2 → distance = min(2, 1) = 1
        XCTAssertEqual(dotOpacity(index: 0, active: 2, dotCount: 3), 0.5)
    }

    func testSingleDot() {
        // A single dot is always active
        XCTAssertEqual(dotOpacity(index: 0, active: 0, dotCount: 1), 1.0)
    }

    func testAllPositionsWithActiveDot2() {
        let expected: [Double] = [0.15, 0.5, 1.0, 0.5, 0.15]
        for idx in 0..<5 {
            XCTAssertEqual(
                dotOpacity(index: idx, active: 2, dotCount: 5),
                expected[idx],
                "Dot \(idx) opacity should be \(expected[idx])"
            )
        }
    }

    func testAllPositionsWithActiveDot0() {
        // Active=0: [1.0, 0.5, 0.15, 0.15, 0.5]
        let expected: [Double] = [1.0, 0.5, 0.15, 0.15, 0.5]
        for idx in 0..<5 {
            XCTAssertEqual(
                dotOpacity(index: idx, active: 0, dotCount: 5),
                expected[idx],
                "Dot \(idx) opacity should be \(expected[idx])"
            )
        }
    }
}
