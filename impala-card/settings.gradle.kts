enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

pluginManagement {
    repositories {
        google()
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()

        // // intermediate fix until new versions of BigNum and kotlinx.serialization are released. according to https://github.com/a-sit-plus/kmp-crypto?tab=readme-ov-file#using-it-in-your-projects
        // maven(uri("https://raw.githubusercontent.com/a-sit-plus/kotlinx.serialization/mvn/repo"))
        // maven {
        //     url = uri("https://oss.sonatype.org/content/repositories/snapshots")
        //     name = "bigNum"
        // }
    }
}

rootProject.name = "ImpalaApplet"

plugins {
    // Auto-provisioning JVM toolchains
    id("org.gradle.toolchains.foojay-resolver-convention") version("0.10.0")
}

include(":sdk")
include(":applet")
