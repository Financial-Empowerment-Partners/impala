plugins {
    alias(libs.plugins.kotlinMultiplatform)
}

ant.importBuild("build.xml")
ant.properties.set("debug", false)

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
