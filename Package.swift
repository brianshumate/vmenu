// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "vmenu",
    platforms: [
        .macOS(.v13)
    ],
    targets: [
        .executableTarget(
            name: "vmenu",
            dependencies: [],
            path: ".",
            exclude: [
                "LICENSE",
                "README.md",
                "prek.toml",
                "vmenu/Info.plist"
            ],
            sources: ["vmenu.swift"]
        )
    ]
)
