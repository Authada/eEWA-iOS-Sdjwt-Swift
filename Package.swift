// swift-tools-version: 5.8.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "eudi-lib-sdjwt-swift",
    platforms: [
        .iOS(.v14),
        .tvOS(.v12),
        .watchOS(.v5),
        .macOS(.v12)

    ],
    products: [
        .library(
            name: "eudi-lib-sdjwt-swift",
            targets: ["eudi-lib-sdjwt-swift"])
    ],
    dependencies: [
        .package(
          url: "https://github.com/SwiftyJSON/SwiftyJSON.git",
          from: "4.0.0"
        ),
        .package(
          url: "https://github.com/Authada/eEWA-iOS-Jose-Swift.git",
          branch: "main"
        )
    ],
    targets: [
        .target(
            name: "eudi-lib-sdjwt-swift",
            dependencies: [
                .product(name: "jose-swift", package: "eewa-ios-jose-swift"),
                .product(name: "SwiftyJSON", package: "swiftyjson")
            ],
            path: "Sources",
            plugins: [
            ]
        ),
        .testTarget(
            name: "eudi-lib-sdjwt-swiftTests",
            dependencies: ["eudi-lib-sdjwt-swift"],
            path: "Tests")

    ]
)
