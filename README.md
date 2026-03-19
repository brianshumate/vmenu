<p align="center">
  <img src="share/screenshot-vmenu-running-alt.png" alt="vmenu running in the macOS menu bar" width="580">
</p>

<h1 align="center">vmenu</h1>

<p align="center">
  <strong>A native macOS menu bar app for managing HashiCorp Vault dev servers</strong>
</p>

<p align="center">
  <a href="https://github.com/brianshumate/vmenu/actions/workflows/swift.yml"><img src="https://github.com/brianshumate/vmenu/actions/workflows/swift.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/brianshumate/vmenu/releases/latest"><img src="https://img.shields.io/github/v/release/brianshumate/vmenu?label=release&color=blue" alt="Latest Release"></a>
  <img src="https://img.shields.io/badge/platform-macOS%2013%2B-lightgrey?logo=apple" alt="macOS 13+">
  <img src="https://img.shields.io/badge/Swift-5.9-F05138?logo=swift&logoColor=white" alt="Swift 5.9">
  <a href="LICENSE"><img src="https://img.shields.io/github/license/brianshumate/vmenu" alt="License"></a>
</p>

---

**vmenu** lives in your menu bar and gives you one-click control over a [Vault](https://www.vaultproject.io/) dev mode server. Start, stop, restart, check status, and copy environment variables — without ever opening a terminal.

## Screenshots

<table>
  <tr>
    <td align="center"><strong>Running</strong></td>
    <td align="center"><strong>Stopped</strong></td>
  </tr>
  <tr>
    <td><img src="share/screenshot-vmenu-running.png" alt="vmenu with Vault running" width="400"></td>
    <td><img src="share/screenshot-vmenu-stopped.png" alt="vmenu with Vault stopped" width="400"></td>
  </tr>
</table>

## Features

- **Start/stop/restart** a Vault dev server with a click or keyboard shortcut.
- **Server readiness indicator** — green (unsealed), orange (sealed), red (stopped).
- **One-click copy** of `VAULT_ADDR`, `VAULT_CACERT`, and `VAULT_TOKEN` export commands for Terminal session or other use.
- **Server status at a glance** — version, seal status, storage backend, address.
- **macOS-native** — pure SwiftUI, lightweight, no Electron, no runtime dependencies.
- **Fully sandboxed** — the main app runs inside the App Sandbox; privileged operations are delegated to a sandboxed XPC helper via `SMAppService`.
- **launchd integration** — manages Vault through a proper LaunchAgent.
- **Keyboard shortcuts** for every action (⌘S, ⌘R, ⌘I, ⌘Q).

### Menu bar icon

The menu bar icon reflects the current server state:

| Icon color | State |
|---|---|
| 🟢 Green | Vault is unsealed and ready |
| 🟠 Orange | Vault is sealed |
| 🔴 Red | Vault is stopped |

## Prerequisites

vmenu needs the `vault` binary installed and available in your `PATH`.

If you do not have Vault, you can install with Homebrew:

```shell
brew install hashicorp/tap/vault
```

If you do not use Homebrew, consider downloading a binary directly from [releases.hashicorp.com/vault](https://releases.hashicorp.com/vault), and installing in your PATH using your preferred method.

> [!TIP]
> vmenu requires **macOS 13 (Ventura) or later** through macOS 26 (Tahoe).

## Install

### Download a release (recommended)

Grab the latest DMG or zip from [**Releases**](https://github.com/brianshumate/vmenu/releases/latest), open the DMG, and drag `vmenu.app` into `/Applications`.

> [!NOTE]
> Release builds from GitHub Actions are signed and notarized.
> If macOS still shows a Gatekeeper warning, right-click the app and choose **Open**, or go to **System Settings → Privacy & Security** and click **Open Anyway**.

### Build from source

Build both the main app and XPC helper

```shell
swift build -c release
```

Build and ad-hoc sign a full .app bundle (includes the XPC helper)

```shell
./build-app.sh release
```

Copy app to `/Applications` folder.

```shell
cp -r vmenu.app /Applications/
```

> [!NOTE]
> The XPC helper agent (`com.brianshumate.vmenu.helper`) requires a properly assembled `.app` bundle so that `SMAppService` can find its LaunchAgent plist at `Contents/Library/LaunchAgents/`. Use `./build-app.sh` to produce a complete bundle.

## Run tests

vmenu ships with a full test suite; here's how to run the tests:

```shell
swift test
```

<details>
<summary><strong>Developer ID signing (for distribution)</strong></summary>

```shell
# Uses the first "Developer ID Application" identity in your keychain
./build-app.sh release sign

# Or specify an identity explicitly
CODESIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)" ./build-app.sh release sign
```

The build script signs both the XPC helper and the main binary with the same identity. The helper is signed first (inner component before outer bundle) with its own entitlements (`vmenuhelper/vmenuhelper.entitlements`).

The build script reads the latest git tag (e.g. `v1.5`) and stamps it into `CFBundleShortVersionString` and `CFBundleVersion`. If no tag exists, the version defaults to the value already in `vmenu/Info.plist`.

</details>

## How it works

vmenu is a menu bar–only app (`LSUIElement = true`) — no Dock icon, no main window.

### Architecture

The app uses a two-process architecture for separation of concerns and defense in depth.

| Component | Binary | Sandbox | Role |
|---|---|---|---|
| **Main app** | vmenu | Sandboxed | UI, Vault HTTP API polling, clipboard |
| **XPC helper** | com.brianshumate.vmenu.helper | Unsandboxed | launchctl, plist/log file I/O, vault binary discovery |

The main app registers the helper agent via [`SMAppService.agent(plistName:)`](https://developer.apple.com/documentation/servicemanagement/smappservice) at launch. launchd starts the helper on demand when the main app connects to its Mach service over XPC. The helper manages the Vault dev server through a LaunchAgent plist at `~/Library/LaunchAgents/com.hashicorp.vault.plist`, using `launchctl bootstrap`/`bootout`/`kickstart` subcommands.

The helper's launchd plist is embedded in the app bundle at `Contents/Library/LaunchAgents/com.brianshumate.vmenu.helper.plist`.

The main app communicates with the Vault server directly over HTTPS for status polling (`/v1/sys/seal-status`, `/v1/sys/leader`) without spawning any processes.

### XPC protocol

All operations that the App Sandbox forbids are exposed through the `VmenuHelperProtocol` XPC interface.

| Method | Operation |
|---|---|
| `findVaultPath` | Locate the `vault` binary on the system |
| `createOrUpdatePlist` | Write/update the Vault LaunchAgent plist |
| `bootstrapService` / `bootoutService` / `kickstartService` | launchctl lifecycle management |
| `checkServiceStatus` | Check if the Vault LaunchAgent is loaded |
| `readStartupLog` / `recreateStartupLog` | Read/reset log files for environment variable parsing |
| `readCACertData` | Read CA certificate bytes for TLS trust evaluation |
| `removeCACertFile` | Clean up stale dev-mode CA certificates |

## Security model

The main vmenu app runs inside the **App Sandbox**. Operations that the sandbox forbids — process spawning (`launchctl`), file I/O outside the container (`~/Library/LaunchAgents/`, `~/Library/Logs/vmenu/`, CA cert files) — are delegated to a dedicated XPC helper agent. The entitlements for each component are documented in [`vmenu/vmenu.entitlements`](vmenu/vmenu.entitlements) and [`vmenuhelper/vmenuhelper.entitlements`](vmenuhelper/vmenuhelper.entitlements).

| Component | Sandbox | Entitlements |
|---|---|---|
| Main app | Enabled | `network.client` (outbound HTTPS to `127.0.0.1:8200`) |
| XPC helper | Disabled | Hardened runtime only (no sandbox) |

Defense-in-depth measures:

- **App Sandbox** on the main app restricts filesystem, process, and network access.
- **Hardened Runtime** enabled for both the main app and the XPC helper.
- **Explicitly disabled unsigned executable memory** and **library validation bypass** in both components.
- **Ephemeral `URLSession`** use, so no credentials get cached to disk.
- **CA certificate path validation** in the helper rejects symlinks, traversal, world-writable directories, and files with unsafe ownership or permissions.
- **Log file safety** — the helper uses `O_CREAT | O_EXCL` for atomic file creation and validates files are regular (not symlinks) before reading or writing.
- **XPC isolation** — the helper is registered via `SMAppService.agent` and its Mach service is scoped to the app bundle. The main app invalidates the XPC connection on termination.

## AI use disclaimer

This codebase has been built with the support of coding agents.

## License

[BSD 2-Clause](LICENSE)
