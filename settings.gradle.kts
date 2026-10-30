pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        mavenCentral()
    }
}

rootProject.name = "libvault"

// Split so each runtime gets only what it can load. Core is the API, the
// encrypted file and the selection logic, built for Java 17 with no Panama in
// it. The desktop module adds the Panama keyrings and keeps the `libvault`
// artifact name, so existing consumers see no change.
include(":libvault-core")
include(":libvault-desktop")
