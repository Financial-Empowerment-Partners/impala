// com.impala:simulator — the jcardsim-backed card and a JCA test issuer, as a
// JVM library so impala-lib and the Android demo can use them in their *test*
// source sets (composite build substitution, see their settings.gradle.kts).
// Never a runtime dependency of an app: it bundles jcardsim and the applet.
plugins {
    alias(libs.plugins.kotlinMultiplatform)
}

group = "com.impala"
version = "0.0.1-HEAD"

kotlin {
    jvmToolchain(17)

    jvm()

    sourceSets {
        jvmMain.dependencies {
            api(project(":sdk"))
            api(project(":applet"))
            api(libs.javacard.simulator)
            implementation(libs.okio)
        }

        jvmTest.dependencies {
            implementation(libs.kotlin.test)
        }
    }

    jvm {
        testRuns["test"].executionTask.configure {
            testLogging {
                showExceptions = true
                events("passed", "skipped", "failed")
            }
        }
    }
}

// Host-side APDU server for the Android emulator lane (T2): jcardsim behind a
// length-prefixed TCP socket, reached from the emulator via `adb reverse`.
//   ./gradlew :simulator:serve --args="--port 9443"
tasks.register<JavaExec>("serve") {
    group = "simulator"
    description = "Serve a jcardsim ImpalaApplet over TCP for the emulator test lane"
    val jvm = kotlin.jvm()
    val main = jvm.compilations.getByName("main")
    classpath = files(main.output.allOutputs, main.runtimeDependencyFiles)
    mainClass.set("com.impala.simulator.SimulatorApduServerKt")
    dependsOn(main.compileTaskProvider)
}

// vpcd server for scardutil (--sim / --sim-cfg / fleet targets): hosts the real
// ImpalaApplet on jcardsim over the vsmartcard protocol. scardutil launches it
// through scripts/vpcd-sim.sh, which reads the classpath this task writes.
//   ./gradlew :simulator:vpcdClasspath && scripts/vpcd-sim.sh <jcardsim.cfg>
tasks.register("vpcdClasspath") {
    group = "simulator"
    description = "Write the runtime classpath for scripts/vpcd-sim.sh"
    val jvm = kotlin.jvm()
    val main = jvm.compilations.getByName("main")
    val out = layout.buildDirectory.file("vpcd-classpath.txt")
    dependsOn(main.compileTaskProvider)
    inputs.files(main.output.allOutputs, main.runtimeDependencyFiles)
    outputs.file(out)
    doLast {
        val cp = (main.output.allOutputs.files + main.runtimeDependencyFiles.files).joinToString(File.pathSeparator) { it.absolutePath }
        out.get().asFile.writeText(cp)
    }
}
