import AppKit
import SwiftUI
import XCTest

@testable import VmenuCore

final class VaultDisplayStateTests: XCTestCase {

  func testStoppedWhenNotRunning() {
    let state = VaultDisplayState.from(isRunning: false, isSealed: false)
    XCTAssertEqual(state, .stopped)
  }

  func testStoppedWhenNotRunningAndSealed() {
    let state = VaultDisplayState.from(isRunning: false, isSealed: true)
    XCTAssertEqual(state, .stopped)
  }

  func testSealedWhenRunningAndSealed() {
    let state = VaultDisplayState.from(isRunning: true, isSealed: true)
    XCTAssertEqual(state, .sealed)
  }

  func testRunningWhenRunningAndUnsealed() {
    let state = VaultDisplayState.from(isRunning: true, isSealed: false)
    XCTAssertEqual(state, .running)
  }

  func testStoppedDotColorIsRed() {
    XCTAssertEqual(VaultDisplayState.stopped.dotColor, .systemRed)
  }

  func testSealedDotColorIsOrange() {
    XCTAssertEqual(VaultDisplayState.sealed.dotColor, .systemOrange)
  }

  func testRunningDotColorIsGreen() {
    XCTAssertEqual(VaultDisplayState.running.dotColor, .systemGreen)
  }

  func testStoppedSwiftUIColorIsRed() {
    XCTAssertEqual(VaultDisplayState.stopped.swiftUIColor, Color(nsColor: .systemRed))
  }

  func testSealedSwiftUIColorIsOrange() {
    XCTAssertEqual(VaultDisplayState.sealed.swiftUIColor, Color(nsColor: .systemOrange))
  }

  func testRunningSwiftUIColorIsGreen() {
    XCTAssertEqual(VaultDisplayState.running.swiftUIColor, Color(nsColor: .systemGreen))
  }
}
