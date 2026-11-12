package com.impala.simulator

import com.impala.jcardsim.jc31.CardPlatform
import java.io.File
import java.util.zip.ZipFile

/**
 * The CAP files the build makes (`-Papplet.ed25519=soft|native|none`) and what
 * each needs a card to have before it will even load: the versions of the
 * three API packages it imports. A card loads a CAP only if it exports every
 * imported package at that version or a later one, which is what makes
 * `native` a JavaCard 3.1+ CAP and the other two JavaCard 3.0.5 CAPs.
 *
 * jcardsim runs class files, not CAPs, so nothing would stop a test from
 * "installing" the JavaCard 3.1 engine on simulated JavaCard 3.0.5 hardware.
 * [SimulatorBibo] asks [loadsOn] first and refuses the way a card's loader
 * does ([CapNotLoadableException]).
 *
 * The numbers are a contract with the build, not a second source of truth:
 * [CapFile] reads them out of a real CAP, `CapVariantContractTest` and
 * `:simulator:capMatrix` compare the two, and CI runs the latter on the CAPs
 * it has just built.
 */
enum class CapVariant(
    /** The value of `-Papplet.ed25519` and of `impala.ed25519`. */
    val id: String,
    /** The file `:applet:buildJavacard` writes under `applet/build/`. */
    val fileName: String,
    /** Minor version of `javacard.framework` the CAP imports (1.x). */
    val frameworkMinor: Int,
    /** Minor version of `javacard.security` the CAP imports (1.x). */
    val securityMinor: Int,
    /** Minor version of `javacardx.crypto` the CAP imports (1.x). */
    val cryptoMinor: Int,
    /** CAP file format the converter writes for that target. */
    val capFormat: String
) {
    /** The default CAP: the software Ed25519 engine, converted for JavaCard 3.0.5. */
    SOFT("soft", "ImpalaApplet.cap", 6, 6, 6, "2.1"),

    /** The platform's own EdDSA, converted for JavaCard 3.1 (and loadable on 3.2). */
    NATIVE("native", "ImpalaApplet-native.cap", 8, 7, 7, "2.3"),

    /** No Stellar key: the legacy card, converted for JavaCard 3.0.5. */
    NONE("none", "ImpalaApplet-none.cap", 6, 6, 6, "2.1");

    /** The lowest JavaCard level whose cards load this CAP. */
    val minimumLevel: CardPlatform.Level
        get() = CardPlatform.Level.values().first { it.exports(frameworkMinor, securityMinor, cryptoMinor) }

    /** Whether a card of [platform] loads this CAP. */
    fun loadsOn(platform: CardPlatform): Boolean = platform.level().exports(frameworkMinor, securityMinor, cryptoMinor)

    companion object {
        /** The variant `-Papplet.ed25519=`[id] builds. */
        fun byId(id: String): CapVariant = values().firstOrNull { it.id == id }
            ?: throw IllegalArgumentException("ed25519 must be soft, native or none, not $id")

        /** The CAP an operator would load on a card of [platform]: its own EdDSA where it has one, the software engine otherwise. */
        fun preferredFor(platform: CardPlatform): CapVariant =
            if (platform.level().atLeast(CardPlatform.Level.JC31) && platform.edDsaOffered()) NATIVE else SOFT

        /** The hardware a CAP is simulated on when none is named: the lowest level that loads it, with all of its optional algorithms. */
        fun defaultPlatformFor(variant: CapVariant): CardPlatform =
            if (variant == NATIVE) CardPlatform.JC31 else CardPlatform.JC305
    }
}

/** A card refused to load a CAP: it lacks an API package version the CAP imports. */
class CapNotLoadableException(val variant: CapVariant, val platform: CardPlatform) : IllegalStateException(
    "${variant.fileName} does not load on a JavaCard ${platform.level().label()} card (${platform.name()}): it imports " +
        "javacard.framework 1.${variant.frameworkMinor}, javacard.security 1.${variant.securityMinor} and " +
        "javacardx.crypto 1.${variant.cryptoMinor}, and the card has 1.${platform.level().frameworkMinor()}, " +
        "1.${platform.level().securityMinor()} and 1.${platform.level().cryptoMinor()}. " +
        "Load the ${CapVariant.values().first { it != CapVariant.NONE && it.loadsOn(platform) }.id} CAP on this hardware."
)

/**
 * What a CAP file says about itself: its format version, its package and the
 * API packages it imports with their versions (the Header and Import
 * components, JCVM specification chapter 6). Enough to say which cards load it.
 */
class CapFile(val file: File) {
    /** One imported package. */
    data class Import(val aidHex: String, val major: Int, val minor: Int) {
        /** `javacard.framework` and friends for the AIDs this applet imports; the AID itself otherwise. */
        val packageName: String get() = KNOWN_PACKAGES[aidHex] ?: aidHex
    }

    /** `2.1` for a JavaCard 3.0.5 target, `2.3` for 3.1 and 3.2. */
    val format: String
    val packageAidHex: String
    val packageVersion: String
    val imports: List<Import>

    init {
        val components = ZipFile(file).use { zip ->
            zip.entries().asSequence().filter { !it.isDirectory }
                .associate { it.name.substringAfterLast('/') to zip.getInputStream(it).use { s -> s.readBytes() } }
        }
        val header = components["Header.cap"] ?: throw IllegalArgumentException("${file.name}: no Header component")
        require(header.size > 13 && header[0].toInt() == 1 && header.copyOfRange(3, 7).contentEquals(MAGIC)) {
            "${file.name}: not a CAP header"
        }
        format = "${header[8].toInt() and 0xFF}.${header[7].toInt() and 0xFF}"
        packageVersion = "${header[11].toInt() and 0xFF}.${header[10].toInt() and 0xFF}"
        val aidLength = header[12].toInt() and 0xFF
        packageAidHex = header.copyOfRange(13, 13 + aidLength).toHex()

        val import = components["Import.cap"] ?: throw IllegalArgumentException("${file.name}: no Import component")
        require(import.size >= 4 && import[0].toInt() == 4) { "${file.name}: not a CAP import component" }
        val list = ArrayList<Import>()
        var p = 4
        repeat(import[3].toInt() and 0xFF) {
            val minor = import[p].toInt() and 0xFF
            val major = import[p + 1].toInt() and 0xFF
            val length = import[p + 2].toInt() and 0xFF
            list += Import(import.copyOfRange(p + 3, p + 3 + length).toHex(), major, minor)
            p += 3 + length
        }
        imports = list
    }

    /** The minor version at which this CAP imports the package [aidHex], or null if it does not import it. */
    fun importedMinor(aidHex: String): Int? = imports.firstOrNull { it.aidHex == aidHex }?.minor

    /** Whether a card of [level] has every package this CAP imports. Packages outside the three API ones are never there. */
    fun loadsOn(level: CardPlatform.Level): Boolean = imports.all { import ->
        when (import.aidHex) {
            AID_LANG -> import.major == 1 && import.minor == 0
            AID_FRAMEWORK -> import.major == 1 && import.minor <= level.frameworkMinor()
            AID_SECURITY -> import.major == 1 && import.minor <= level.securityMinor()
            AID_CRYPTO -> import.major == 1 && import.minor <= level.cryptoMinor()
            else -> false
        }
    }

    /** What is different between this file and what [variant] says its CAP imports; empty when they agree. */
    fun differencesFrom(variant: CapVariant): List<String> {
        val out = ArrayList<String>()
        fun check(what: String, aid: String, expected: Int) {
            val actual = importedMinor(aid)
            if (actual != expected) out += "$what: the CAP imports ${actual?.let { "1.$it" } ?: "nothing"}, CapVariant.${variant.name} says 1.$expected"
        }
        check("javacard.framework", AID_FRAMEWORK, variant.frameworkMinor)
        check("javacard.security", AID_SECURITY, variant.securityMinor)
        check("javacardx.crypto", AID_CRYPTO, variant.cryptoMinor)
        if (format != variant.capFormat) out += "CAP format: the file is $format, CapVariant.${variant.name} says ${variant.capFormat}"
        imports.filter { it.aidHex !in KNOWN_PACKAGES }.forEach { out += "unexpected import ${it.aidHex} ${it.major}.${it.minor}" }
        return out
    }

    companion object {
        const val AID_LANG = "a0000000620001"
        const val AID_FRAMEWORK = "a0000000620101"
        const val AID_SECURITY = "a0000000620102"
        const val AID_CRYPTO = "a0000000620201"
        private val KNOWN_PACKAGES = mapOf(
            AID_LANG to "java.lang", AID_FRAMEWORK to "javacard.framework",
            AID_SECURITY to "javacard.security", AID_CRYPTO to "javacardx.crypto"
        )
        private val MAGIC = byteArrayOf(0xDE.toByte(), 0xCA.toByte(), 0xFF.toByte(), 0xED.toByte())
        private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }
    }
}

/**
 * `./gradlew :simulator:capMatrix [--args="<directory with the CAPs>"]`: reads
 * the CAP files of the three variants and prints, for each, what it imports
 * and which simulated hardware levels load it. Exits 1 when a CAP is missing,
 * when one does not import what [CapVariant] says, or when the load matrix is
 * not the contract (`soft` and `none` load from JavaCard 3.0.5 on, `native`
 * from 3.1 on): the tripwire against a build change that moves a CAP to
 * another API level without anyone deciding to.
 */
fun main(args: Array<String>) {
    val dir = File(args.firstOrNull() ?: "applet/build")
    var problems = 0
    println("CAP files in ${dir.path}")
    println("%-8s %-26s %-7s %-24s %s".format("variant", "file", "format", "imports (fw/sec/crypto)", CardPlatform.Level.values().joinToString(" ") { "JC ${it.label()}".padEnd(9) }))
    for (variant in CapVariant.values()) {
        val file = File(dir, variant.fileName)
        if (!file.isFile) {
            println("%-8s %-26s MISSING (./gradlew :applet:buildJavacard -Papplet.ed25519=%s)".format(variant.id, variant.fileName, variant.id))
            problems++
            continue
        }
        val cap = CapFile(file)
        val imports = listOf(CapFile.AID_FRAMEWORK, CapFile.AID_SECURITY, CapFile.AID_CRYPTO).joinToString(" / ") { aid -> cap.importedMinor(aid)?.let { "1.$it" } ?: "-" }
        val loads = CardPlatform.Level.values().joinToString(" ") { level -> (if (cap.loadsOn(level)) "loads" else "refused").padEnd(9) }
        println("%-8s %-26s %-7s %-24s %s".format(variant.id, variant.fileName, cap.format, imports, loads))
        for (difference in cap.differencesFrom(variant)) {
            println("  MISMATCH $difference")
            problems++
        }
        for (level in CardPlatform.Level.values()) {
            val expected = level.exports(variant.frameworkMinor, variant.securityMinor, variant.cryptoMinor)
            if (cap.loadsOn(level) != expected) {
                println("  MISMATCH on JavaCard ${level.label()}: the file ${if (cap.loadsOn(level)) "loads" else "is refused"}, the contract says ${if (expected) "loads" else "refused"}")
                problems++
            }
        }
    }
    if (problems > 0) {
        System.err.println("capMatrix: $problems problem(s): the CAPs and CapVariant (simulator/src/jvmMain/.../CapVariant.kt) disagree, or a CAP is missing")
        kotlin.system.exitProcess(1)
    }
    println("capMatrix: the three CAPs import what CapVariant says; soft and none load from JavaCard 3.0.5 on, native from 3.1 on")
}
