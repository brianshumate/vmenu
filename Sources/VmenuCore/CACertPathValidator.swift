import Foundation

/// Directories considered unsafe for CA certificate storage because they
/// are world-writable or commonly targeted by symlink attacks.
private let unsafeDirectoryPrefixes: [String] = [
  "/tmp",
  "/var/tmp",
  "/private/tmp",
  "/private/var/tmp"
]

/// Maximum CA certificate file size (1 MiB).
///
/// PEM-encoded CA bundles are typically under 10 KiB.  A generous upper
/// bound prevents reading unexpectedly large files that could indicate
/// a replaced or injected path.
private let maxCACertFileSize: off_t = 1_024 * 1_024

/// Validate that `path` is safe to read as a CA certificate file.
///
/// Checks performed:
/// 1. The path is absolute.
/// 2. The path does not reside in a world-writable directory (e.g.
///    `/tmp`, `/var/tmp`).
/// 3. The file is not a symbolic link (checked via `lstat` to avoid
///    TOCTOU through the link itself).
/// 4. The file is a regular file.
/// 5. The file is owned by the current user (or root).
/// 6. The file is not group- or world-writable.
///
/// Returns `true` if the path passes all checks.
///
/// - Note: This function is suitable for pre-flight validation (e.g.
///   UI display or logging).  For reading file contents, prefer
///   ``safeReadCACertData(_:)`` which performs validation and reading
///   on the same file descriptor to eliminate TOCTOU races.
public func validateCACertPath(_ path: String) -> Bool {
  // 1. Require absolute path.
  guard path.hasPrefix("/") else {
    return false
  }

  // Resolve to a canonical path for prefix checks so that paths like
  // /private/tmp/../tmp/cert.pem are caught.  The lstat below still
  // operates on the original path to detect symlinks.
  let resolvedPath = (path as NSString).resolvingSymlinksInPath

  // 2. Reject paths in world-writable directories.
  for prefix in unsafeDirectoryPrefixes {
    if resolvedPath == prefix || resolvedPath.hasPrefix(prefix + "/") {
      return false
    }
  }

  // 3 & 4. lstat the original path (not resolved) to detect symlinks.
  var statBuf = stat()
  guard lstat(path, &statBuf) == 0 else {
    return false
  }

  let fileType = statBuf.st_mode & S_IFMT

  // 3. Reject symbolic links.
  if fileType == S_IFLNK {
    return false
  }

  // 4. Must be a regular file.
  guard fileType == S_IFREG else {
    return false
  }

  // 5. Must be owned by the current user or root.
  let currentUID = getuid()
  guard statBuf.st_uid == currentUID || statBuf.st_uid == 0 else {
    return false
  }

  // 6. Must not be group-writable or world-writable.
  let groupWritable = (statBuf.st_mode & S_IWGRP) != 0
  let worldWritable = (statBuf.st_mode & S_IWOTH) != 0
  if groupWritable || worldWritable {
    return false
  }

  return true
}

/// Validate the file descriptor's metadata matches the security policy.
///
/// Performs the same ownership and permission checks as
/// ``validateCACertPath(_:)`` steps 4–6, but operates on an already-open
/// file descriptor via `fstat()` to eliminate TOCTOU races.
///
/// Returns `true` if the descriptor passes all checks.
private func validateFileDescriptor(_ fd: Int32) -> Bool {
  var statBuf = stat()
  guard fstat(fd, &statBuf) == 0 else {
    return false
  }

  // Must be a regular file (catches /dev/ nodes, FIFOs, etc.).
  guard (statBuf.st_mode & S_IFMT) == S_IFREG else {
    return false
  }

  // Must be owned by the current user or root.
  let currentUID = getuid()
  guard statBuf.st_uid == currentUID || statBuf.st_uid == 0 else {
    return false
  }

  // Must not be group-writable or world-writable.
  let groupWritable = (statBuf.st_mode & S_IWGRP) != 0
  let worldWritable = (statBuf.st_mode & S_IWOTH) != 0
  if groupWritable || worldWritable {
    return false
  }

  // Must not exceed the size limit.
  guard statBuf.st_size >= 0, statBuf.st_size <= maxCACertFileSize else {
    return false
  }

  return true
}

/// Safely read the contents of a CA certificate file, eliminating TOCTOU
/// races between validation and reading.
///
/// Performs the following steps on a single file descriptor:
/// 1. Pre-flight path checks (absolute path, not in an unsafe directory).
/// 2. Open the file with `O_RDONLY | O_NOFOLLOW` — this fails atomically
///    if the path is a symbolic link, preventing a race between `lstat`
///    and `open`.
/// 3. `fstat()` the open descriptor to verify ownership and permissions
///    on the *actual* file that was opened.
/// 4. Read the file contents from the validated descriptor.
///
/// Returns the file data on success, or `nil` if any check fails.
public func safeReadCACertData(_ path: String) -> Data? {
  // 1. Pre-flight path checks (cheap string checks before any syscall).
  guard path.hasPrefix("/") else {
    return nil
  }

  let resolvedPath = (path as NSString).resolvingSymlinksInPath
  for prefix in unsafeDirectoryPrefixes {
    if resolvedPath == prefix || resolvedPath.hasPrefix(prefix + "/") {
      return nil
    }
  }

  // 2. Open with O_NOFOLLOW — fails with ELOOP if path is a symlink,
  //    closing the TOCTOU window between lstat and open.
  let fd = open(path, O_RDONLY | O_NOFOLLOW)
  guard fd >= 0 else {
    return nil
  }
  defer { close(fd) }

  // 3. Validate ownership and permissions on the open descriptor.
  guard validateFileDescriptor(fd) else {
    return nil
  }

  // 4. Read from the validated descriptor.
  //    Use fstat to get the size, then read in one call.
  var statBuf = stat()
  guard fstat(fd, &statBuf) == 0 else {
    return nil
  }
  let fileSize = Int(statBuf.st_size)
  guard fileSize > 0 else {
    return nil
  }

  var buffer = Data(count: fileSize)
  let bytesRead = buffer.withUnsafeMutableBytes { rawBuffer -> Int in
    guard let baseAddress = rawBuffer.baseAddress else { return 0 }
    return read(fd, baseAddress, fileSize)
  }

  guard bytesRead == fileSize else {
    return nil
  }

  return buffer
}
