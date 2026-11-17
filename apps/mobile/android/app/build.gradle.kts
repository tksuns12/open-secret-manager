// The phone app for Android: its screens over the `vault` module.
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "org.opensecretmanager.app"
    compileSdk = 36

    defaultConfig {
        applicationId = "org.opensecretmanager.app"
        minSdk = 28
        targetSdk = 36
        versionCode = 2
        versionName = "0.1.1"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        // The shared code is built for arm64 only: a phone of another kind
        // refuses to install the app rather than failing to open the vault.
        ndk {
            abiFilters += "arm64-v8a"
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    // A release is built unsigned: scripts/release-android.sh signs it with
    // the owner's key after building it in a container. See
    // docs/release.md.

    buildTypes {
        debug {
            // `-Posm.screenshots=true` makes a debug build whose screens can
            // be captured, for reviewing them. Every other build keeps them
            // out of screenshots.
            buildConfigField("boolean", "ALLOW_SCREENSHOTS", (project.findProperty("osm.screenshots") ?: "false").toString())
        }
        release {
            buildConfigField("boolean", "ALLOW_SCREENSHOTS", "false")
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        jniLibs {
            // The shared code's library is loaded from the APK as it is.
            useLegacyPackaging = false
            // Every library goes in as it comes (prepare.sh strips the
            // shared code's): stripped here, it would depend on which NDK
            // the machine that builds has, and a build elsewhere would
            // differ.
            keepDebugSymbols += "**/*.so"
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    implementation(project(":vault"))
    implementation("androidx.core:core-ktx:1.18.0")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.fragment:fragment-ktx:1.8.9")
    implementation("androidx.lifecycle:lifecycle-process:2.9.4")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.9.4")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.9.4")
    implementation("androidx.compose.ui:ui:1.10.5")
    implementation("androidx.compose.foundation:foundation:1.10.5")
    implementation("androidx.compose.material3:material3:1.4.0")
    implementation("androidx.biometric:biometric:1.1.0")
    // The entries of a fill in the keyboard's strip (autofill/Presentation.kt).
    implementation("androidx.autofill:autofill:1.3.0")
    // Passkeys for Android's Credential Manager (passkey/), Apache-2.0: the
    // library alone, never its Google Play services part.
    implementation("androidx.credentials:credentials:1.6.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    implementation("androidx.work:work-runtime-ktx:2.12.0")
    // Scanning the QR code of an invitation (ScanInvitation.kt): the camera
    // through CameraX, the code read by ZXing, both Apache-2.0.
    implementation("androidx.camera:camera-camera2:1.6.2")
    implementation("androidx.camera:camera-lifecycle:1.6.2")
    implementation("androidx.camera:camera-view:1.6.2")
    implementation("com.google.zxing:core:3.5.4")

    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4:1.10.5")
    androidTestImplementation("androidx.test.uiautomator:uiautomator:2.3.0")
    androidTestImplementation("androidx.work:work-testing:2.12.0")
    debugImplementation("androidx.compose.ui:ui-test-manifest:1.10.5")
}

// The autofill tests fill the forms of a stand-in for another app, typed
// on keyboards of their own.
tasks.matching { it.name == "connectedDebugAndroidTest" }.configureEach {
    dependsOn(":loginfixture:installDebug", ":testkeyboard:installDebug")
}
