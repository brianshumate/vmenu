// swift-tools-version: 6.0
import PackageDescription

let package = Package(
  name: "vmenu",
  platforms: [
    .macOS(.v13)
  ],
  targets: [
    .target(
      name: "VmenuCore",
      dependencies: [],
      path: "Sources/VmenuCore"
    ),
    .target(
      name: "VmenuXPCProtocol",
      dependencies: [],
      path: "Sources/VmenuXPCProtocol"
    ),
    .executableTarget(
      name: "vmenu",
      dependencies: ["VmenuCore", "VmenuXPCProtocol"],
      path: ".",
      exclude: [
        "LICENSE",
        "README.md",
        "prek.toml",
        "share",
        "vmenu/Info.plist",
        "vmenu/AppIcon.icns",
        "vmenu/Assets.xcassets",
        "vmenu/icon-layers",
        "vmenu/vmenu.entitlements",
        "vmenuhelper/Info.plist",
        "vmenuhelper/vmenuhelper.entitlements",
        "vmenuhelper/com.brianshumate.vmenu.helper.plist",
        "Sources",
        "Tests",
        "build-app.sh",
        "scripts"
      ],
      sources: ["vmenu.swift", "StatusViews.swift"]
    ),
    .executableTarget(
      name: "vmenu-helper",
      dependencies: ["VmenuCore", "VmenuXPCProtocol"],
      path: "Sources/VmenuHelper"
    ),
    .testTarget(
      name: "VmenuCoreTests",
      dependencies: ["VmenuCore"],
      path: "Tests/VmenuCoreTests"
    )
  ]
)
