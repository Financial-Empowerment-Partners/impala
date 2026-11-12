// com.impala:jcardsim-jc31: jcardsim 3.0.6.0 (a JavaCard 3.0.5 simulator) with
// the slice of the JavaCard 3.1 API that Ed25519 needs: NamedParameterSpec,
// XECKey / XECPublicKey / XECPrivateKey, KeyBuilder.buildXECKey, KeyPair over
// XEC keys and Signature.SIG_CIPHER_EDDSA, backed by the JDK's own Ed25519.
//
// Why it exists: the applet's JavaCard 3.1 engine (Ed25519Native) can then be
// compiled and RUN in the JVM test lanes, next to the JavaCard 3.0.5 one. No
// published jcardsim has these classes, and its API classes are generated at
// its build time, so they cannot be overridden from source. See README.md.
//
// How: `patchJcardsim` unpacks the jcardsim jar and patches three classes with
// ASM (src/patcher); the sources in src/main are compiled against the result;
// the jar holds both. This module REPLACES the com.klinec:jcardsim dependency:
// never put both on one classpath (the same class names, different bytes).
plugins {
    `java-library`
}

group = "com.impala"
version = "0.0.1-HEAD"

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

// The unmodified jcardsim jar: an input of the patch task, never a dependency
// that reaches a consumer.
val jcardsimJar: Configuration by configurations.creating {
    isCanBeConsumed = false
    isCanBeResolved = true
    isTransitive = false
}

val patcher: SourceSet by sourceSets.creating

dependencies {
    jcardsimJar(libs.javacard.simulator)
    "patcherImplementation"(libs.asm)
}

val patchedDir = layout.buildDirectory.dir("jcardsim-patched")

val patchJcardsim by tasks.registering(JavaExec::class) {
    group = "build"
    description = "Unpack jcardsim and add the JavaCard 3.1 hooks to KeyBuilder and Signature"
    classpath = patcher.runtimeClasspath
    mainClass.set("com.impala.jcardsim.patcher.Jc31Patcher")
    javaLauncher.set(javaToolchains.launcherFor(java.toolchain))
    inputs.files(jcardsimJar).withNormalizer(ClasspathNormalizer::class)
    outputs.dir(patchedDir)
    outputs.cacheIf { true }
    doFirst {
        // Stale classes from an older jcardsim must not survive a version bump.
        delete(patchedDir)
    }
    argumentProviders.add(CommandLineArgumentProvider {
        listOf(jcardsimJar.singleFile.absolutePath, patchedDir.get().asFile.absolutePath)
    })
}

dependencies {
    // The patched classes: on this module's own compile classpath as a directory,
    // and inside its jar (below) for everyone else. The layer is tested where it
    // is used, on the simulator: applet/src/jvmTest (Jc31LayerTest and the
    // native-engine applet tests).
    compileOnly(files(patchJcardsim))
}

tasks.jar {
    from(patchJcardsim)
    // jcardsim ships a LICENSE and a NOTICE under META-INF; keep them, once.
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}

// The patched jcardsim classes exist only in the jar. Without this, a consumer
// in the same build would be handed the bare classes directory of src/main
// (Gradle's "classes" variant) and miss all of jcardsim.
listOf("apiElements", "runtimeElements").forEach { name ->
    configurations.named(name) { outgoing.variants.clear() }
}
