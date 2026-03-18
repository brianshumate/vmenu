// swift-tools-version: 5.9
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
        .executableTarget(
            name: "vmenu",
            dependencies: [],
            path: ".",
            exclude: [
                "LICENSE",
                "README.md",
                "prek.toml",
                "vmenu/Info.plist",
                "Sources",
                "Tests"
            ],
            sources: ["vmenu.swift"]
        ),
        .testTarget(
            name: "VmenuCoreTests",
            dependencies: ["VmenuCore"],
            path: "Tests/VmenuCoreTests"
        )
    ]
)
