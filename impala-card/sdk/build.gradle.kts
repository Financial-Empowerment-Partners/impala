plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidLibrary)
    alias(libs.plugins.mavenPublish)
}

kotlin {
    jvmToolchain(17)

    jvm()

    listOf(
        iosX64(),
        iosArm64(),
        iosSimulatorArm64()
    ).forEach {iosTarget ->
        iosTarget.binaries.framework {
            baseName = "impala-sdk"
            isStatic = true
        }
    }

    sourceSets {
        commonMain.dependencies {
            implementation(libs.okio) // for ByteString, Buffer, etc (instead of java libs)
            implementation(libs.kotlinx.datetime) // for Clock.System.now() (instead of platform-specific Instant from threeten)
            implementation(libs.uuid) // for Uuid (instead of java libs)
            implementation(libs.datatypes) // ASN.1 encoding/decoding (it wraps bouncy castle for its android implementation)
            implementation(libs.bignum) // BigInteger (instead of platform-specific from bouncy castle)
        }

        jvmTest.dependencies {
            implementation(libs.kotlin.test)
            implementation(libs.javacard.simulator)
            // implementation(files("../build/applet.jar"))
            implementation(project(":applet"))
        }
    }

    jvm {
        testRuns["test"].executionTask.configure {
            testLogging {
                showExceptions = true
                showStandardStreams = true

                events("passed", "skipped", "failed")
            }
        }
    }

    androidTarget {
        publishLibraryVariants("release", "debug")
    }
}

android {
    // this is the namespace of the shared library in android (note that it differs from the android app's namespace: com.impala.android)
    namespace = "com.impala.sdk"
    compileSdk = libs.versions.android.compileSdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.android.minSdk.get().toInt()
    }
}

publishing {
    repositories {
        maven {
            name = "githubPackages"
            url = uri("https://maven.pkg.github.com/Financial-Empowerment-Partners/impala/impala-card")
            credentials(PasswordCredentials::class)
        }
    }
}
