// The card issuance ceremony (docs/transfer-protocol.md §5) as a JVM CLI and a
// library: `./gradlew :tools:issue:run --args="--help"`, `installDist` for a
// standalone launcher. The library API (IssuanceCeremony) is what the T1
// end-to-end lane uses to issue a jcardsim card against a live bridge.
plugins {
    alias(libs.plugins.kotlinJvm)
    application
}

group = "com.impala"
version = "0.0.1-HEAD"

kotlin {
    jvmToolchain(17)
    compilerOptions { freeCompilerArgs.add("-Xadd-modules=java.smartcardio") }
}

dependencies {
    implementation(project(":sdk"))
    // jcardsim transport (--transport simulator / tcp:) and the JCA test issuer.
    implementation(project(":simulator"))
    implementation(libs.gson)
    implementation(libs.okio)

    testImplementation(libs.kotlin.test)
    testImplementation(libs.mockwebserver)
}

application {
    applicationName = "impala-issue"
    mainClass.set("com.impala.tools.issue.MainKt")
}

tasks.named<JavaExec>("run") {
    // Prompts (no-echo PIN entry) need the terminal.
    standardInput = System.`in`
}

tasks.test {
    testLogging { events("passed", "skipped", "failed"); showExceptions = true }
}
