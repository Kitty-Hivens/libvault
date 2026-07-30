plugins {
    alias(libs.plugins.kotlin.jvm)
    `java-library`
    // vanniktech: applies maven-publish + signing, targets the new Central
    // Portal. Replaces the bare `maven-publish` + hand-rolled publishing block.
    alias(libs.plugins.mavenPublish)
    // Declared so the `signing { }` type-safe accessor + useGpgCmd() resolve
    // (vanniktech applies signing transitively, but that doesn't generate the
    // Kotlin DSL accessor for this script). Idempotent.
    `signing`
}

// Dedicated configuration so the smoke harness can pull in an SLF4J binding
// (slf4j-simple) without polluting the published library artifact. The library
// API exposes slf4j-api only; consumers bring their own binding.
val smokeRuntime: Configuration by configurations.creating {
    extendsFrom(configurations.runtimeClasspath.get())
}

dependencies {
    "smokeRuntime"(libs.slf4j.simple)
}

tasks.register<JavaExec>("runSmoke") {
    group = "verification"
    description = "Store/retrieve/delete a secret against the live OS keyring and print the chosen tier. Ctrl-C to exit."
    classpath = sourceSets.main.get().runtimeClasspath + smokeRuntime
    mainClass.set("dev.hivens.libvault.SmokeMainKt")
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

group = "dev.hivens"
// Version comes from the git tag at CI time via `-PappVersion=<tag>`; falls
// back to `git describe` for local development. Mirrors the libtray/libnotify
// pattern so a shared developer mental model.
version = providers.gradleProperty("appVersion")
    .orElse(providers.exec {
        commandLine("git", "describe", "--tags", "--always", "--dirty")
        isIgnoreExitValue = true
    }.standardOutput.asText.map { it.trim().ifEmpty { "0.0.0-SNAPSHOT" } })
    .getOrElse("0.0.0-SNAPSHOT")

java {
    // Source / target Java 22 -- Project Panama (java.lang.foreign) finalized
    // as JEP 454. Compiles with any JDK >= 22 in the build environment.
    sourceCompatibility = JavaVersion.VERSION_22
    targetCompatibility = JavaVersion.VERSION_22
    // No withSourcesJar()/withJavadocJar() here -- the vanniktech plugin builds
    // and publishes the sources + javadoc jars itself; declaring them again
    // would double-register the artifacts.
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_22)
        freeCompilerArgs.addAll(
            "-jvm-default=enable",  // Generate Java 8+ default methods for interface APIs.
        )
        // Every warning is an error. Warnings pile up unseen behind the build
        // cache (a cached compile replays without re-emitting them); as errors
        // they fail the compile, so none caches green.
        allWarningsAsErrors.set(true)
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
}

tasks.test {
    useJUnitPlatform()
    // The OS-keyring backends reach Panama; the file/memory/selection tests
    // don't, but the flag is harmless on those.
    jvmArgs("--enable-native-access=ALL-UNNAMED")
}

tasks.withType<Jar>().configureEach {
    manifest {
        attributes(
            "Implementation-Title" to "libvault",
            "Implementation-Version" to project.version,
            "Implementation-Vendor" to "Kitty-Hivens",
        )
    }
}

// Maven Central publishing via the vanniktech plugin (new Central Portal,
// central.sonatype.com). It builds the sources + javadoc jars, signs every
// artifact, assembles the deployment bundle, and uploads it to the Central
// Portal Publisher API.
//
// Secrets come from ~/.gradle/gradle.properties or env -- NEVER commit them:
//   mavenCentralUsername / mavenCentralPassword : Central Portal user token
//       (Central Portal -> Account -> Generate User Token), NOT the login.
//   signingInMemoryKey / signingInMemoryKeyPassword (+ optional ...KeyId) :
//       the ASCII-armored GPG private key + its passphrase.
//
// Publish: push a vX.Y.Z tag and .github/workflows/publish.yml does the rest,
// passing the tag as -PappVersion and signing with the key CI holds. From a
// workstation the same release is `./gradlew publishToMavenCentral
// -PappVersion=X.Y.Z --no-configuration-cache`, signing through the keyring.
// Pass the version either way: gradle.properties pins appVersion to a
// SNAPSHOT, so the git-describe fallback above never gets to run.
// automaticRelease then carries the deployment all the way through instead of
// leaving it VALIDATED in the portal waiting for a manual Publish click.
mavenPublishing {
    publishToMavenCentral(automaticRelease = true)
    signAllPublications()
    coordinates("dev.hivens", "libvault", project.version.toString())
    pom {
        name.set("libvault")
        description.set("Cross-platform secret storage -- OS keyring with an encrypted-file fallback -- for JVM 22+ via Project Panama.")
        url.set("https://github.com/Kitty-Hivens/libvault")
        licenses {
            license {
                name.set("Apache-2.0")
                url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
            }
        }
        developers {
            developer {
                id.set("kitty-hivens")
                name.set("Kitty-Hivens")
            }
        }
        scm {
            url.set("https://github.com/Kitty-Hivens/libvault")
            connection.set("scm:git:https://github.com/Kitty-Hivens/libvault.git")
        }
    }
}

signing {
    // Local release signs through the gpg keyring: BouncyCastle's in-memory
    // reader chokes on modern GnuPG secret-key exports ("checksum mismatch"),
    // so we hand signing to the gpg command. CI can still inject an in-memory
    // key via signingInMemoryKey (vanniktech handles that), in which case we
    // leave signing to it and skip useGpgCmd.
    if (!providers.gradleProperty("signingInMemoryKey").isPresent &&
        System.getenv("ORG_GRADLE_PROJECT_signingInMemoryKey") == null
    ) {
        useGpgCmd()
    }
}
