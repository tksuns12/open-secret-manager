// Keyboards for the autofill tests (app/src/androidTest/.../Keyboard.kt),
// in an app of their own: Android drops a keyboard whose app is stopped,
// and the tests stop the stand-in app (`loginfixture`) before each form.
// Never shipped.
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "org.opensecretmanager.testkeyboard"
    compileSdk = 36

    defaultConfig {
        applicationId = "org.opensecretmanager.testkeyboard"
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
    // The strip of the keyboard that asks for a fill's entries.
    implementation("androidx.autofill:autofill:1.3.0")
}
