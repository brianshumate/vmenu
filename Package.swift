// swift-tools-version: 6.0
import Foundation
import PackageDescription

// Developer-only files that are gitignored and therefore present in local
// checkouts but absent in CI. Excluding a path that does not exist emits an
// "Invalid Exclude" warning, so only exclude them when they actually exist.
let optionalExcludes = ["AGENTS.md", "F-IMPROVE.md", ".claude"].filter {
  FileManager.default.fileExists(atPath: $0)
}

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
        "vmenuhelper/launch-constraint-parent.plist",
        "vmenuhelper/launch-constraint-self.plist",
        "Sources",
        "Tests",
        "scripts",
        "version.txt"
      ] + optionalExcludes,
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
