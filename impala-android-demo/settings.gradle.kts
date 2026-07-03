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

include(":app")
