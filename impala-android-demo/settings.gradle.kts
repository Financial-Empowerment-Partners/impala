pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "impala-android-demo"

plugins {
    // Auto-provisioning JVM toolchains (same convention as ../impala-card):
    // unit tests need a Java 21 runtime (Robolectric's SDK-36 sandbox) that
    // isn't guaranteed to be installed locally.
    id("org.gradle.toolchains.foojay-resolver-convention") version ("1.0.0")
}

// Composite builds: the demo consumes the card SDK and the Android card module
// from source (no publishing step). All three builds pin AGP 9.2.1 — composite
// builds share one plugin version. com.impala:simulator (jcardsim + the applet
// + a JCA test issuer) is a test-only dependency.
includeBuild("../impala-card") {
    dependencySubstitution {
        substitute(module("com.impala:sdk")).using(project(":sdk"))
        substitute(module("com.impala:simulator")).using(project(":simulator"))
        // The issuance ceremony as a library, for the T1 e2e lane (src/e2e).
        substitute(module("com.impala:issue")).using(project(":tools:issue"))
    }
}
includeBuild("../impala-lib") {
    dependencySubstitution {
        substitute(module("com.payala:impala-lib")).using(project(":"))
    }
}

include(":app")
