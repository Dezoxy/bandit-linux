// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "BanditHelper",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "bandit-helper", targets: ["BanditHelperCLI"]),
        .executable(name: "bandit-test", targets: ["BanditTest"])
    ],
    dependencies: [
        .package(url: "https://github.com/LebJe/TOMLKit.git", from: "0.6.0")
    ],
    targets: [
        .target(
            name: "BanditCore",
            dependencies: ["TOMLKit"],
            path: "Sources/BanditCore"
        ),
        .executableTarget(
            name: "BanditHelperCLI",
            dependencies: ["BanditCore"],
            path: "Sources/BanditHelperCLI"
        ),
        .executableTarget(
            name: "BanditTest",
            dependencies: ["BanditCore", "TOMLKit"],
            path: "Sources/BanditTest"
        )
    ]
)
