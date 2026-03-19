import Foundation
import XCTest

@testable import VmenuCore

final class CACertPathValidatorTests: XCTestCase {

  // MARK: - Helpers

  // swiftlint:disable:next implicitly_unwrapped_optional
  private var tempDir: URL!

  override func setUp() {
    super.setUp()
    // Create a temporary directory under the user's home (not /tmp) so the
    // test files are in a location that passes the unsafe-directory check.
    let home = FileManager.default.homeDirectoryForCurrentUser
    tempDir = home
      .appendingPathComponent(".vmenu-test-\(UUID().uuidString)")
    try? FileManager.default.createDirectory(
      at: tempDir, withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700])
  }

  override func tearDown() {
    if let tempDir {
      try? FileManager.default.removeItem(at: tempDir)
    }
    super.tearDown()
  }

  /// Create a regular file at the given path with the specified permissions.
  private func createFile(
    named name: String,
    permissions: Int = 0o600
  ) -> String {
    let url = tempDir.appendingPathComponent(name)
    FileManager.default.createFile(atPath: url.path, contents: Data("test".utf8))
    try? FileManager.default.setAttributes(
      [.posixPermissions: permissions],
      ofItemAtPath: url.path)
    return url.path
  }

  /// Create a symbolic link at `linkName` pointing to `target`.
  private func createSymlink(named linkName: String, target: String) -> String {
    let linkPath = tempDir.appendingPathComponent(linkName).path
    try? FileManager.default.createSymbolicLink(
      atPath: linkPath, withDestinationPath: target)
    return linkPath
  }

  // MARK: - Tests: Valid paths

  func testValidRegularFileAccepted() {
    let path = createFile(named: "ca.pem")
    XCTAssertTrue(validateCACertPath(path))
  }

  func testValidFileWithReadOnlyPermissions() {
    let path = createFile(named: "ca.pem", permissions: 0o400)
    XCTAssertTrue(validateCACertPath(path))
  }

  func testValidFileWithOwnerReadWritePermissions() {
    let path = createFile(named: "ca.pem", permissions: 0o600)
    XCTAssertTrue(validateCACertPath(path))
  }

  // MARK: - Tests: Relative paths rejected

  func testRelativePathRejected() {
    XCTAssertFalse(validateCACertPath("relative/path/ca.pem"))
  }

  func testEmptyPathRejected() {
    // Note: empty paths are handled by the caller (caCertPath.isEmpty check),
    // but the validator should also reject them.
    XCTAssertFalse(validateCACertPath(""))
  }

  func testDotRelativePathRejected() {
    XCTAssertFalse(validateCACertPath("./ca.pem"))
  }

  // MARK: - Tests: Unsafe directories rejected

  func testTmpPathRejected() {
    // We don't create the file — the prefix check happens first.
    // But to be safe, create a real file in /tmp for the test.
    let tmpPath = "/tmp/vmenu-test-\(UUID().uuidString).pem"
    FileManager.default.createFile(atPath: tmpPath, contents: Data("test".utf8))
    defer { try? FileManager.default.removeItem(atPath: tmpPath) }

    XCTAssertFalse(validateCACertPath(tmpPath))
  }

  func testVarTmpPathRejected() {
    XCTAssertFalse(validateCACertPath("/var/tmp/ca.pem"))
  }

  func testPrivateTmpPathRejected() {
    // /tmp is actually /private/tmp on macOS
    XCTAssertFalse(validateCACertPath("/private/tmp/ca.pem"))
  }

  func testPrivateVarTmpPathRejected() {
    XCTAssertFalse(validateCACertPath("/private/var/tmp/ca.pem"))
  }

  func testTmpSubdirectoryRejected() {
    XCTAssertFalse(validateCACertPath("/tmp/subdir/ca.pem"))
  }

  // MARK: - Tests: Symlinks rejected

  func testSymlinkRejected() {
    let realPath = createFile(named: "real-ca.pem")
    let linkPath = createSymlink(named: "link-ca.pem", target: realPath)
    XCTAssertFalse(validateCACertPath(linkPath))
  }

  // MARK: - Tests: Non-regular files rejected

  func testDirectoryRejected() {
    let dirPath = tempDir.appendingPathComponent("subdir").path
    try? FileManager.default.createDirectory(
      atPath: dirPath, withIntermediateDirectories: true)
    XCTAssertFalse(validateCACertPath(dirPath))
  }

  // MARK: - Tests: Unsafe permissions rejected

  func testGroupWritableRejected() {
    let path = createFile(named: "ca.pem", permissions: 0o620)
    XCTAssertFalse(validateCACertPath(path))
  }

  func testWorldWritableRejected() {
    let path = createFile(named: "ca.pem", permissions: 0o602)
    XCTAssertFalse(validateCACertPath(path))
  }

  func testGroupAndWorldWritableRejected() {
    let path = createFile(named: "ca.pem", permissions: 0o622)
    XCTAssertFalse(validateCACertPath(path))
  }

  func testWorldReadableButNotWritableAccepted() {
    // 0o644 = owner rw, group r, other r — not writable, so acceptable
    let path = createFile(named: "ca.pem", permissions: 0o644)
    XCTAssertTrue(validateCACertPath(path))
  }

  // MARK: - Tests: Nonexistent file rejected

  func testNonexistentFileRejected() {
    let path = tempDir.appendingPathComponent("nonexistent.pem").path
    XCTAssertFalse(validateCACertPath(path))
  }
}
