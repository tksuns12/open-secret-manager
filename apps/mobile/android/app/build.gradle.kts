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
        versionCode = 1
        versionName = "0.1.0"
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

    // A release is signed with the owner's key when OSM_ANDROID_KEYSTORE
    // names its keystore (with OSM_ANDROID_KEYSTORE_PASSWORD,
    // OSM_ANDROID_KEY_ALIAS, and OSM_ANDROID_KEY_PASSWORD); without it the
    // release is left unsigned. See docs/release.md.
    val keystore = System.getenv("OSM_ANDROID_KEYSTORE")
    if (keystore != null) {
        signingConfigs.create("release") {
            storeFile = file(keystore)
            storePassword = System.getenv("OSM_ANDROID_KEYSTORE_PASSWORD")
            keyAlias = System.getenv("OSM_ANDROID_KEY_ALIAS")
            keyPassword = System.getenv("OSM_ANDROID_KEY_PASSWORD")
        }
    }

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
            signingConfig = signingConfigs.findByName("release")
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
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    implementation("androidx.work:work-runtime-ktx:2.12.0")

    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4:1.10.5")
    androidTestImplementation("androidx.test.uiautomator:uiautomator:2.3.0")
    androidTestImplementation("androidx.work:work-testing:2.12.0")
    debugImplementation("androidx.compose.ui:ui-test-manifest:1.10.5")
}

// The autofill tests fill the forms of a stand-in for another app.
tasks.matching { it.name == "connectedDebugAndroidTest" }.configureEach {
    dependsOn(":loginfixture:installDebug")
}
