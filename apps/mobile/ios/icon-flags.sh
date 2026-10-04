#!/bin/sh
# Prints the xcodebuild settings that leave the app icon out of a build, or
# nothing: Xcode's asset compiler needs a simulator runtime of the iOS SDK's
# exact version, even to build for iPhones, and prints these settings only
# when this Mac lacks it (`xcodebuild -downloadPlatform iOS` installs it).
xcrun simctl runtime match list -j | node -e '
    let s = ""; process.stdin.on("data", d => s += d).on("end", () => {
        const sdk = Object.entries(JSON.parse(s)).find(([name]) => name.startsWith("iphoneos"))?.[1];
        const installed = require("child_process").execSync("xcrun simctl runtime list -j").toString();
        const builds = Object.values(JSON.parse(installed)).map(r => r.build);
        if (!sdk || !builds.includes(sdk.chosenRuntimeBuild)) {
            console.log("EXCLUDED_SOURCE_FILE_NAMES=Assets.xcassets ASSETCATALOG_COMPILER_APPICON_NAME=");
        }
    });'
