plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidKmpLibrary)
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
            // Removed 2026-06: at.asitplus.crypto:datatypes (+ its kotlinx-datetime
            // 0.8.0-0.6.x-compat pin) — zero at.asitplus/kotlinx.datetime imports in
            // any source set. The Signum successor (at.asitplus.signum:indispensable)
            // was evaluated and is unnecessary: the SDK passes DER signature bytes
            // through opaquely (see ImpalaSDK.kt doc comments); ASN.1 handling is
            // applet/bridge behaviour. If SDK-side ASN.1 parsing is ever needed,
            // adopt at.asitplus.signum:indispensable + plain kotlinx-datetime then.
            implementation(libs.okio) // for ByteString, Buffer, etc (instead of java libs)
            implementation(libs.uuid) // for Uuid (instead of java libs)
            implementation(libs.bignum) // BigInteger (instead of platform-specific from bouncy castle)
        }

        jvmTest.dependencies {
            implementation(libs.kotlin.test)
            implementation(libs.javacard.simulator)
            // Direct org.bouncycastle.* imports in Scp03CounterIcvTest (CMac reference
            // impl) — previously a hidden transitive of the removed datatypes dep.
            implementation(libs.bouncycastle)
            // implementation(files("../build/applet.jar"))
            implementation(project(":applet"))
        }

        // iosMain (shared by iosX64/iosArm64/iosSimulatorArm64 via the default
        // hierarchy template) holds the CoreNFC transport: CoreNfcBibo + the
        // optional CoreNfcSessionDriver. CoreNFC/Foundation/darwin are built-in
        // platform.* interop libraries — no extra dependencies, no cinterop .def.
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

    // AGP 9 Android target: com.android.kotlin.multiplatform.library replaces
    // com.android.library + androidTarget(). The plugin publishes a single
    // Android variant, so the old publishLibraryVariants("release", "debug")
    // configuration no longer exists; consumers (impala-lib via composite
    // build) resolve the unified variant.
    androidLibrary {
        // this is the namespace of the shared library in android (note that it
        // differs from the android app's namespace: com.impala.android)
        namespace = "com.impala.sdk"
        compileSdk = libs.versions.android.compileSdk.get().toInt()
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
