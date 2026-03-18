# vmenu

![example workflow](https://github.com/brianshumate/vmenu/actions/workflows/swift.yml/badge.svg)

A macOS menu bar application for managing a Vault dev mode server.

Requires **macOS 13 (Ventura)** or later — compatible through macOS 26 (Tahoe).

## Features

- Start/Stop/Restart Vault dev server
- Copy `VAULT_ADDR` and `VAULT_CACERT` values to clipboard
- View `vault status` output

## Prerequisites

- [Vault](https://www.vaultproject.io/) binary installed and in your PATH

### Install Vault

Install Vault with Homebrew.

```shell
brew install hashicorp/tap/vault
```

## Build the app

Build a production release, and display the path to the binary folder.

```shell
swift build --show-bin-path -c release
```

### Build the .app bundle

Build a `vmenu.app` bundle with the proper icon and Info.plist for use in
`/Applications` or the Menu Bar pane in System Preferences.

```shell
./build-app.sh release
cp -r vmenu.app /Applications/
```

## Run the app

```shell
swift run
```

The app will appear in your menu bar as an inverted triangle outline with a status indicator color.

Click the icon to access Vault dev mode server controls.
