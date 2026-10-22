// A stand-in for another app with login forms, for the autofill tests
// (app/src/androidTest/.../AutofillTest.kt): a form of its own, and a page
// in a web view; and an app that asks for passkeys (PasskeyTest). Never
// shipped.
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "org.opensecretmanager.loginfixture"
    compileSdk = 36

    defaultConfig {
        applicationId = "org.opensecretmanager.loginfixture"
        minSdk = 28
        targetSdk = 36
        versionCode = 1
        versionName = "1"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    implementation("androidx.credentials:credentials:1.6.0")
}
