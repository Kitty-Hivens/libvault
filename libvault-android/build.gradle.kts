import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    // AGP compiles the Kotlin sources itself (built-in Kotlin), with the Kotlin
    // Gradle plugin the root build puts on the classpath.
    alias(libs.plugins.android.library)
    alias(libs.plugins.mavenPublish)
    signing
}

android {
    namespace = "dev.hivens.libvault.android"
    compileSdk = libs.versions.androidCompileSdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.androidMinSdk.get().toInt()
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.toVersion(libs.versions.javaCoreTarget.get())
        targetCompatibility = JavaVersion.toVersion(libs.versions.javaCoreTarget.get())
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.fromTarget(libs.versions.javaCoreTarget.get()))
        freeCompilerArgs.addAll(
            "-jvm-default=enable",
            // The backend builds on core's shared plumbing, which is what the
            // marker fences off from everybody else.
            "-opt-in=dev.hivens.libvault.internal.InternalLibvaultApi",
        )
    }
    // Explicit API mode: every public symbol must declare its visibility and
    // carry an explicit return type. Keeps the published surface deliberate.
    explicitApi()
}

dependencies {
    api(project(":libvault-core"))

    // The Keystore exists only on a device, so the backend is tested there.
    // `./gradlew :libvault-android:connectedAndroidTest` with a device or an
    // emulator attached.
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.junit)
}

mavenPublishing {
    coordinates("dev.hivens", "libvault-android", project.version.toString())
    pom {
        name.set("libvault-android")
        description.set(
            "libvault on Android: secrets encrypted under a non-exportable Android Keystore key, " +
                "with the same API and the same encrypted-file fallback as the desktop library.",
        )
    }
}
