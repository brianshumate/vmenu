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
            sources: ["vmenu.swift"]
        )
    ]
)
