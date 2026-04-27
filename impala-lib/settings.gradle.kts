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

// Composite build: resolves com.impala:sdk to the ../impala-card :sdk project
// so impala-lib can consume the SDK from source without needing it published.
includeBuild("../impala-card") {
    dependencySubstitution {
        substitute(module("com.impala:sdk")).using(project(":sdk"))
    }
}
