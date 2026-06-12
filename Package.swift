// swift-tools-version: 6.0
import PackageDescription

let package = Package(
  name: "vmenu",
  platforms: [
    .macOS(.v14)
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
        "scripts",
        "version.txt",
        "AGENTS.md",
        "F-IMPROVE.md",
        ".claude"
      ],
      sources: ["vmenu.swift", "StatusViews.swift", "VmenuViews.swift", "HelperDiagnostics.swift"]
    ),
    .executableTarget(
      name: "vmenu-helper",
      dependencies: ["VmenuCore", "VmenuXPCProtocol"],
      path: "Sources/VmenuHelper",
      swiftSettings: [
        .define("DEBUG", .when(configuration: .debug))
      ]
    ),
    .testTarget(
      name: "VmenuCoreTests",
      dependencies: ["VmenuCore"],
      path: "Tests/VmenuCoreTests"
    )
  ]
)
