# vmenu

![example workflow](https://github.com/brianshumate/vmenu/actions/workflows/swift.yml/badge.svg)

A macOS menu bar application for managing a Vault dev mode server.

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

```shell
swift build
```

## Run the app

```shell
swift run
```

The app will appear in your menu bar as an inverted triangle outline with a status indicator color.

Click the icon to access Vault dev mode server controls.
