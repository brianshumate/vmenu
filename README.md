# vmenu

![CI](https://github.com/brianshumate/vmenu/actions/workflows/swift.yml/badge.svg)

A macOS menu bar application for managing a Vault dev mode server.

Requires **macOS 13 (Ventura)** or later — compatible through macOS 26 (Tahoe).

## Features

- Start / Stop / Restart Vault dev server via launchd
- Live status polling with sealed/unsealed/stopped indicator in the menu bar
- Copy `VAULT_ADDR` and `VAULT_CACERT` values to clipboard
- View parsed `vault status` output
- Notification when macOS hides the menu bar icon due to crowding
- Single-instance enforcement — launching a second copy shows an alert and exits

## Prerequisites

- [Vault](https://www.vaultproject.io/) binary installed and in your PATH

### Install Vault

```shell
brew install hashicorp/tap/vault
```

## Install from release

Download the latest DMG or zip from
[Releases](https://github.com/brianshumate/vmenu/releases), then drag
`vmenu.app` into `/Applications`.

> **Gatekeeper note:** Release builds from GitHub Actions are ad-hoc signed.
> On first launch macOS may show "vmenu can't be opened because Apple cannot
> check it for malicious software." Right-click the app and choose **Open**,
> or go to **System Settings → Privacy & Security** and click **Open Anyway**.

## Build from source

### Quick run (debug)

```shell
swift run
```

### Build a release binary

```shell
swift build -c release
```

The binary is written to the path shown by `swift build --show-bin-path -c release`.

### Build the .app bundle

The `build-app.sh` script compiles the binary, assembles a complete
`.app` bundle with icon and Info.plist, stamps the version from the
latest git tag, and code-signs the result.

```shell
# Ad-hoc signed — good for local use
./build-app.sh release

# Install
cp -r vmenu.app /Applications/
```

To produce a build signed with your Developer ID (required for
notarization and Gatekeeper-friendly distribution):

```shell
# Uses the first "Developer ID Application" identity in your keychain
./build-app.sh release sign

# Or specify an identity explicitly
CODESIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)" ./build-app.sh release sign
```

### Version stamping

The build script reads the latest git tag (e.g. `v1.2`) and writes it
into the bundle's `CFBundleShortVersionString` and `CFBundleVersion`.
If no tag exists the version defaults to the value in `vmenu/Info.plist`.

## How it works

vmenu is a menu bar–only app (`LSUIElement = true`) — it has no Dock icon
and no main window. It manages the Vault dev server through a launchd
LaunchAgent plist at `~/Library/LaunchAgents/com.hashicorp.vault.plist`,
using modern `launchctl bootstrap`/`bootout`/`kickstart` subcommands on
macOS 13+.

Click the menu bar icon to access server controls. The icon color reflects
the current state:

| Color  | Meaning             |
|--------|---------------------|
| Green  | Vault is unsealed   |
| Orange | Vault is sealed     |
| Red    | Vault is stopped    |

## Running tests

```shell
swift test
```

## License

[BSD 2-Clause](LICENSE)
