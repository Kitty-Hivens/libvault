import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.jvm)
    `java-library`
    alias(libs.plugins.animalSniffer)
    alias(libs.plugins.mavenPublish)
    signing
}

java {
    // Deliberately below the desktop module's 22. Nothing here touches
    // java.lang.foreign, and Android takes Java 17 bytecode. If this ever needs
    // raising, the reason has to be written down: drifting up by inertia
    // breaks the Android module.
    sourceCompatibility = JavaVersion.toVersion(libs.versions.javaCoreTarget.get())
    targetCompatibility = JavaVersion.toVersion(libs.versions.javaCoreTarget.get())
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.fromTarget(libs.versions.javaCoreTarget.get()))
        freeCompilerArgs.addAll(
            "-jvm-default=enable", // Generate Java 8+ default methods for interface APIs.
            // Its own marker, opted into here for the same reason a module can
            // use its own internals: the fence is aimed outward.
            "-opt-in=dev.hivens.libvault.internal.InternalLibvaultApi",
        )
    }
    // Explicit API mode: every public symbol must declare its visibility and
    // carry an explicit return type. Keeps the published surface deliberate.
    explicitApi()
}

dependencies {
    // SLF4J -- consumers wire their own backend. The library logs at
    // DEBUG/INFO/WARN; nothing fires at ERROR in normal operation (failures
    // degrade by returning null/false, not by throwing).
    api(libs.slf4j.api)

    // Argon2id for the Passphrase key-derivation tier only. `implementation`,
    // not `api`: BouncyCastle never appears in libvault's public surface, so
    // consumers don't inherit it on their compile classpath.
    implementation(libs.bouncycastle)

    testImplementation(platform("org.junit:junit-bom:${libs.versions.junit.get()}"))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
    testRuntimeOnly(libs.slf4j.simple)
    testImplementation(libs.kotest.assertions)

    // The Android API at minSdk, as Animal Sniffer reads it. See the catalog.
    signature(variantOf(libs.android.api.signature) { artifactType("signature") })
}

animalsniffer {
    // Main only: the tests run on a desktop JVM and may use anything.
    sourceSets = listOf(project.sourceSets.main.get())
}

mavenPublishing {
    coordinates("dev.hivens", "libvault-core", project.version.toString())
    pom {
        name.set("libvault-core")
        description.set(
            "The libvault API, its encrypted-file fallback and its backend selection. " +
                "No platform code: use libvault (desktop) or libvault-android.",
        )
    }
}
