import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.jvm)
    `java-library`
    // vanniktech: applies maven-publish + signing, targets the new Central
    // Portal. Shared configuration lives in the root build.
    alias(libs.plugins.mavenPublish)
    signing
}

// Dedicated configuration so the smoke harness can pull in an SLF4J binding
// (slf4j-simple) without polluting the published library artifact. The library
// API exposes slf4j-api only; consumers bring their own binding.
val smokeRuntime: Configuration = configurations.create("smokeRuntime") {
    extendsFrom(configurations.runtimeClasspath.get())
}

dependencies {
    smokeRuntime(libs.slf4j.simple)
}

tasks.register<JavaExec>("runSmoke") {
    group = "verification"
    description = "Store/retrieve/delete a secret against the live OS keyring and print the chosen tier. Ctrl-C to exit."
    classpath = sourceSets.main.get().runtimeClasspath + smokeRuntime
    mainClass.set("dev.hivens.libvault.desktop.SmokeMainKt")
    jvmArgs("--enable-native-access=ALL-UNNAMED")
    // Surface backend diagnostics (selected tier, D-Bus session path, keyring
    // lock state). Default slf4j-simple level is INFO already, but the system
    // property makes the intent explicit and future-proofs against the default
    // flipping in a newer release.
    systemProperty("org.slf4j.simpleLogger.defaultLogLevel", "info")
    systemProperty("org.slf4j.simpleLogger.showDateTime", "true")
    systemProperty("org.slf4j.simpleLogger.dateTimeFormat", "HH:mm:ss.SSS")
    standardInput = System.`in`
    isIgnoreExitValue = true
}

java {
    // Source / target Java 22 -- Project Panama (java.lang.foreign) finalized
    // as JEP 454. Compiles with any JDK >= 22 in the build environment.
    sourceCompatibility = JavaVersion.toVersion(libs.versions.javaTarget.get())
    targetCompatibility = JavaVersion.toVersion(libs.versions.javaTarget.get())
    // No withSourcesJar()/withJavadocJar() here -- the vanniktech plugin builds
    // and publishes the sources + javadoc jars itself; declaring them again
    // would double-register the artifacts.
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.fromTarget(libs.versions.javaTarget.get()))
        freeCompilerArgs.addAll(
            "-jvm-default=enable", // Generate Java 8+ default methods for interface APIs.
            // The backends build on core's shared plumbing, which is what the
            // marker fences off from everybody else.
            "-opt-in=dev.hivens.libvault.internal.InternalLibvaultApi",
        )
    }
    // Explicit API mode: every public symbol must declare its visibility and
    // carry an explicit return type. Keeps the published surface deliberate.
    explicitApi()
}

dependencies {
    // `api`: every type a consumer compiles against (SecretVault, VaultConfig,
    // the capabilities) lives in core, so it has to reach their classpath.
    api(project(":libvault-core"))

    testImplementation(platform("org.junit:junit-bom:${libs.versions.junit.get()}"))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
    testRuntimeOnly(libs.slf4j.simple)
    testImplementation(libs.kotest.assertions)
}

tasks.test {
    // The OS-keyring backends reach Panama; the file/memory/selection tests
    // don't, but the flag is harmless on those.
    jvmArgs("--enable-native-access=ALL-UNNAMED")
}

tasks.withType<Jar>().configureEach {
    // The artifact is `libvault`, whatever the directory is called.
    manifest { attributes("Implementation-Title" to "libvault") }
}

mavenPublishing {
    // The coordinate consumers already depend on. The directory is named for
    // what is in it, the artifact keeps its name.
    coordinates("dev.hivens", "libvault", project.version.toString())
    pom {
        name.set("libvault")
        description.set("Cross-platform secret storage -- OS keyring with an encrypted-file fallback -- for JVM 22+ via Project Panama.")
    }
}
