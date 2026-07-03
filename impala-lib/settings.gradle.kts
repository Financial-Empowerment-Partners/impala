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
    }
}

rootProject.name = "impala-lib"

// impala-card is a sibling Gradle build. Consume its :sdk (Kotlin
// Multiplatform, Android library variants) via composite-build dependency
// substitution rather than merging its projects into this build: merging
// would let `./gradlew build`/`test` task-name-match into :sdk's iOS
// framework linking (Xcode requirement) and :applet, and would force this
// build to replicate impala-card's version catalog and gradle.properties.
// With substitution, only the tasks producing :sdk's Android variant
// artifacts run here.
includeBuild("../impala-card") {
    dependencySubstitution {
        substitute(module("com.impala:sdk")).using(project(":sdk"))
    }
}
