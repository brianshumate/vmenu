import Foundation

/// Directories considered unsafe for CA certificate storage because they
/// are world-writable or commonly targeted by symlink attacks.
private let unsafeDirectoryPrefixes: [String] = [
  "/tmp",
  "/var/tmp",
  "/private/tmp",
  "/private/var/tmp"
]

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
