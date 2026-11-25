// The capability probe (README.md): a diagnostic applet that asks a card for
// each primitive the applet's Ed25519 engine needs, and the host program that
// reads its answers.
//   ./gradlew :tools:probe:buildProbeCap                 the CAP (build/ImpalaProbe.cap)
//   ./gradlew :tools:probe:run [--args="<reader name>"]  probe the card in a PC/SC reader
//   ./gradlew :tools:probe:test                          the probe on simulated hardware
plugins {
    alias(libs.plugins.kotlinJvm)
    application
}

group = "com.impala"
version = "0.0.1-HEAD"

ant.importBuild("build.xml")
ant.lifecycleLogLevel = AntBuilder.AntMessagePriority.INFO

kotlin {
    jvmToolchain(17)
    compilerOptions { freeCompilerArgs.add("-Xadd-modules=java.smartcardio") }
}

dependencies {
    // The JavaCard API the applet compiles against in the JVM, and the
    // simulated card models the test runs it on.
    implementation(project(":jcardsim-jc31"))

    testImplementation(libs.kotlin.test)
}

application {
    applicationName = "impala-probe"
    mainClass.set("com.impala.probe.MainKt")
}

tasks.test {
    testLogging { events("passed", "skipped", "failed"); showExceptions = true; showStandardStreams = true }
}
