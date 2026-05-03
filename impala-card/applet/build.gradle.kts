plugins {
    alias(libs.plugins.kotlinMultiplatform)
}

ant.importBuild("build.xml")
ant.properties.set("debug", false)

// Forward selected Gradle project properties (-Papplet.aid=..., etc.) to Ant so
// CI can override the AID + issuer key per network without editing build.xml.
listOf("applet.aid", "applet.aid.app", "applet.issuerkey").forEach { key ->
    project.findProperty(key)?.let { ant.properties.set(key, it.toString()) }
}

// we want to get the output of the ant-tasks from gradle.
ant.lifecycleLogLevel = AntBuilder.AntMessagePriority.INFO

tasks.withType<AntTarget>().configureEach {
    group = "applet"
}

kotlin {
    jvmToolchain(17)

    jvm(){
    }

    sourceSets {
        jvmMain.dependencies {
            implementation(libs.javacard.simulator)
        }

        jvmTest.dependencies {
            implementation(libs.kotlin.test)
            implementation(libs.okio)
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
}
