import com.vanniktech.maven.publish.MavenPublishBaseExtension
import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.gradle.plugins.signing.SigningExtension
import org.jetbrains.kotlin.gradle.tasks.KotlinCompilationTask

plugins {
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.mavenPublish) apply false
}

// Version comes from the git tag at CI time via `-PappVersion=<tag>`; falls
// back to `git describe` for local development. Mirrors the libtray/libnotify
// pattern so a shared developer mental model.
val appVersion: String = providers.gradleProperty("appVersion")
    .orElse(
        providers.exec {
            commandLine("git", "describe", "--tags", "--always", "--dirty")
            isIgnoreExitValue = true
        }.standardOutput.asText.map { it.trim().ifEmpty { "0.0.0-SNAPSHOT" } },
    )
    .getOrElse("0.0.0-SNAPSHOT")

// Present only where the key cannot come from a keyring, see the signing block.
val inMemoryKey = providers.gradleProperty("signingInMemoryKey")
    .orElse(providers.environmentVariable("ORG_GRADLE_PROJECT_signingInMemoryKey"))

allprojects {
    group = "dev.hivens"
    version = appVersion
}

subprojects {
    tasks.withType<Test>().configureEach {
        useJUnitPlatform()
        // CI logs carry only the console, and without the message a failed
        // assertion is a bare file:line.
        testLogging {
            events("failed")
            exceptionFormat = TestExceptionFormat.FULL
        }
    }

    // Every warning is an error. Warnings pile up unseen behind the build
    // cache (a cached compile replays without re-emitting them). As errors
    // they fail the compile, so none caches green.
    tasks.withType<KotlinCompilationTask<*>>().configureEach {
        compilerOptions.allWarningsAsErrors.set(true)
    }

    tasks.withType<Jar>().configureEach {
        manifest {
            attributes(
                "Implementation-Title" to project.name,
                "Implementation-Version" to project.version,
                "Implementation-Vendor" to "Kitty-Hivens",
            )
        }
    }

    // Maven Central publishing via the vanniktech plugin (new Central Portal,
    // central.sonatype.com). It builds the sources + javadoc jars, signs every
    // artifact, assembles the deployment bundle, and uploads it to the Central
    // Portal Publisher API. Each module adds its coordinates and description.
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
    // placeholder, so the git-describe fallback above never gets to run.
    // automaticRelease then carries the deployment all the way through instead of
    // leaving it VALIDATED in the portal waiting for a manual Publish click.
    plugins.withId("com.vanniktech.maven.publish") {
        configure<MavenPublishBaseExtension> {
            publishToMavenCentral(automaticRelease = true)
            signAllPublications()
            pom {
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
    }

    // Central takes 9.9.9-TEST like any release, and a version there can never
    // be withdrawn. So the placeholder is refused by the task that would send
    // it to the Central repository, before anything is sent.
    tasks.withType<PublishToMavenRepository>().configureEach {
        val version = appVersion
        doFirst {
            if ((this as PublishToMavenRepository).repository.name == "mavenCentral" && version.endsWith("-TEST")) {
                throw GradleException("appVersion $version is the local placeholder. Publish a release with -PappVersion=X.Y.Z")
            }
        }
    }

    plugins.withId("signing") {
        // Local release signs through the gpg keyring: BouncyCastle's in-memory
        // reader chokes on modern GnuPG secret-key exports ("checksum mismatch"),
        // so we hand signing to the gpg command. CI injects an in-memory key via
        // signingInMemoryKey (vanniktech handles that), in which case signing is
        // left to it and useGpgCmd is skipped.
        if (!inMemoryKey.isPresent) {
            configure<SigningExtension> {
                useGpgCmd()
            }
        }
    }
}
