// The Android side of the phone app. For now it holds the module that
// wraps the shared code's interface, and its tests on an emulator or a
// device; see scripts/test-mobile-bindings.sh.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "open-secret-manager"
include(":vault")
