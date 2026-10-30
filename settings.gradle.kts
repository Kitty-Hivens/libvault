pluginManagement {
    repositories {
        // The Android Gradle Plugin is published here and nowhere else. The
        // filter keeps every other plugin resolving from the portal.
        google {
            content {
                includeGroupByRegex("com\\.android(\\..*)?")
                includeGroupByRegex("com\\.google\\.(android|testing)(\\..*)?")
                includeGroupByRegex("androidx(\\..*)?")
            }
        }
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        // AGP's own build-time dependencies and androidx.test, for the Android
        // module. Filtered the same way, so nothing else drifts onto it.
        google {
            content {
                includeGroupByRegex("com\\.android(\\..*)?")
                includeGroupByRegex("com\\.google\\.(android|testing)(\\..*)?")
                includeGroupByRegex("androidx(\\..*)?")
            }
        }
        mavenCentral()
    }
}

rootProject.name = "libvault"

// Split so each runtime gets only what it can load. Core is the API, the
// encrypted file and the selection logic, built for Java 17 with no Panama in
// it. The desktop module adds the Panama keyrings and keeps the `libvault`
// artifact name, so existing consumers see no change. The Android module adds
// the Android Keystore.
include(":libvault-core")
include(":libvault-desktop")
include(":libvault-android")
