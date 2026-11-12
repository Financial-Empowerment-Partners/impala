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
            // jcardsim, repackaged with the JavaCard 3.1 EdDSA classes (:jcardsim-jc31).
            api(project(":jcardsim-jc31"))
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
            // CardHardwareSimulatorTest compares the CAP files with CapVariant
            // when :applet:buildJavacard has left any (it never builds them).
            val capDir = rootProject.file("applet/build")
            systemProperty("impala.cap.dir", capDir.absolutePath)
            inputs.files(fileTree(capDir) { include("*.cap") }).withPropertyName("capFiles").optional()
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

// The CAP load matrix: reads the CAP files of the three Ed25519 variants and
// checks what each imports, and so which simulated hardware levels load it
// (CardPlatform.Level), against CapVariant. CI runs it on the CAPs it has just
// built: a build change that moves a CAP to another JavaCard level fails here.
//   ./gradlew :applet:buildJavacard && ./gradlew :applet:buildJavacard -Papplet.ed25519=native \
//     && ./gradlew :applet:buildJavacard -Papplet.ed25519=none && ./gradlew :simulator:capMatrix
tasks.register<JavaExec>("capMatrix") {
    group = "simulator"
    description = "Check which simulated hardware levels load each CAP variant (applet/build/*.cap)"
    val jvm = kotlin.jvm()
    val main = jvm.compilations.getByName("main")
    classpath = files(main.output.allOutputs, main.runtimeDependencyFiles)
    mainClass.set("com.impala.simulator.CapVariantKt")
    dependsOn(main.compileTaskProvider)
    val capDir = rootProject.file("applet/build")
    if (!project.hasProperty("args")) args(capDir.absolutePath)
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
