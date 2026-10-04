// The Android app: `app`, its screens, and `vault`, the module that wraps
// the shared code's interface; `loginfixture` is a stand-in for another app,
// for the autofill tests. See apps/mobile/README.md.
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
include(":app")
include(":loginfixture")
