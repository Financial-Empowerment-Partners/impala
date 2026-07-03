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

rootProject.name = "impala-lib"

plugins {
    // Auto-provisioning JVM toolchains (same convention as ../impala-card):
    // unit tests need a Java 21 runtime (Robolectric's SDK-36 sandbox) that
    // isn't guaranteed to be installed locally.
    id("org.gradle.toolchains.foojay-resolver-convention") version ("1.0.0")
}

// Composite build: resolves com.impala:sdk to the ../impala-card :sdk project
// so impala-lib can consume the SDK from source without needing it published.
includeBuild("../impala-card") {
    dependencySubstitution {
        substitute(module("com.impala:sdk")).using(project(":sdk"))
    }
}
