// swift-tools-version:5.9

import PackageDescription

let package = Package(
    name: "test",
    platforms: [
        .macOS(.v10_15),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-algorithms", from: "1.2.0"),
        .package(url: "https://github.com/apple/swift-nio-http2", "1.0.0"..<"1.19.1"),
        .package(url: "https://github.com/apple/swift-http-types", exact: "1.0.2")
    ]
)
