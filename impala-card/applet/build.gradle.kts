plugins {
    alias(libs.plugins.kotlinMultiplatform)
}

ant.importBuild("build.xml")
ant.properties.set("debug", false)

// Forward selected Gradle project properties (-Papplet.aid=..., etc.) to Ant so
// CI can override the AID + issuer key per network without editing build.xml.
// applet.ed25519 = soft | native | none picks the Ed25519 engine of the CAP (see
// build.xml, stageSources); it has no effect on the JVM classes built here.
listOf("applet.aid", "applet.aid.app", "applet.issuerkey", "applet.installparams", "applet.ed25519").forEach { key ->
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
            // jcardsim plus the JavaCard 3.1 EdDSA classes Ed25519Native compiles against.
            implementation(project(":jcardsim-jc31"))
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
