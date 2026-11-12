package com.impala.simulator

import com.impala.jcardsim.jc31.CardPlatform
import com.impala.sdk.ImpalaSDK
import java.io.File
import java.util.Properties
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The simulator integrations name their hardware: the TCP card server
 * (`:simulator:serve`, the Android emulator lane and the demo kit), the vpcd
 * card (scardutil's simulator target) and the CAP load rule they share.
 */
class CardHardwareSimulatorTest {
    private fun sw(r: ByteArray) = ((r[r.size - 2].toInt() and 0xFF) shl 8) or (r[r.size - 1].toInt() and 0xFF)

    private val getStellarKey = byteArrayOf(0x00, 0x37, 0x00, 0x00, 0x00)
    private val initialize = byteArrayOf(0x00, 0x2C, 0x00, 0x00, 0x04, 1, 2, 3, 4)

    /** The engine byte of GET_STELLAR_KEY after INITIALIZE (1 soft, 2 native), or null for a legacy card. */
    private fun engineAfterInitialize(card: SimulatorBibo): Int? {
        assertEquals(0x623C, sw(card.transceive(getStellarKey)), "a blank card has no key yet")
        assertEquals(0x9000, sw(card.transceive(initialize)))
        val answer = card.transceive(getStellarKey)
        return if (sw(answer) == 0x9000) answer[0].toInt() else null.also { assertEquals(0x623C, sw(answer)) }
    }

    // ------------------------------------------------------------------ :simulator:serve

    @Test
    fun `serve takes the hardware and the CAP from its command line`() {
        ServeOptions.parse(arrayOf()).let {
            assertEquals(SimulatorApduServer.DEFAULT_PORT, it.port)
            assertNull(it.platform)
            assertNull(it.ed25519)
        }
        ServeOptions.parse(arrayOf("--port", "9555", "--platform", "jc32", "--ed25519", "soft")).let {
            assertEquals(9555, it.port)
            assertEquals(CardPlatform.JC32, it.platform)
            assertEquals("soft", it.ed25519)
        }
        assertEquals(CardPlatform.JC305_NO_XY, ServeOptions.parse(arrayOf("--platform", "JC305-no-xy")).platform)
        for (bad in listOf(arrayOf("--platform"), arrayOf("--platform", "jc40"), arrayOf("--ed25519", "fast"), arrayOf("--port", "x"), arrayOf("--port", "70000"), arrayOf("--verbose"))) {
            assertFailsWith<IllegalArgumentException>(bad.joinToString(" ")) { ServeOptions.parse(bad) }
        }
        // The help names every card model, so the list cannot drift from the code.
        for (p in CardPlatform.presets()) assertTrue(p.name() in ServeOptions.USAGE, p.name())
    }

    @Test
    fun `a served card of either hardware class is the card a client sees`() {
        // What the Android emulator lane and the issuance tool reach over TCP: a JavaCard 3.0.5 card and a JavaCard 3.2 card.
        for ((platform, engine) in listOf(CardPlatform.JC305 to 1, CardPlatform.JC32 to 2, CardPlatform.JC32_PER_CURVE to 2)) {
            val options = ServeOptions.parse(arrayOf("--port", "0", "--platform", platform.name()))
            val card = SimulatorBibo(ed25519 = options.ed25519, platform = options.platform)
            SimulatorApduServer(card, options.port).start().use { server ->
                TcpApduClient("127.0.0.1", server.port).use { client ->
                    val sdk = ImpalaSDK(client)
                    assertNull(sdk.getStellarKey(), "${platform.name()}: blank")
                    sdk.setSeed()
                    val key = assertNotNull(sdk.getStellarKey(), "${platform.name()}: a Stellar key over TCP")
                    assertEquals(engine, key.engine.toInt(), platform.name())
                }
            }
        }
    }

    // ------------------------------------------------------------------ vpcd (scardutil)

    private fun vpcdCard(vararg pairs: Pair<String, String>): SimulatorBibo =
        VpcdSimulator.fromConfig(Properties().apply { for ((k, v) in pairs) setProperty(k, v) }).first

    @Test
    fun `the hardware in a vpcd cfg decides what the fleet check sees`() {
        // impala.platform alone: the CAP an operator would load on that hardware.
        vpcdCard(VpcdSimulator.KEY_PLATFORM to "jc305").let {
            assertEquals(CapVariant.SOFT, it.capVariant)
            assertEquals(1, engineAfterInitialize(it))
        }
        vpcdCard(VpcdSimulator.KEY_PLATFORM to "jc32").let {
            assertEquals(CapVariant.NATIVE, it.capVariant)
            assertEquals(2, engineAfterInitialize(it))
        }
        // The default CAP on JavaCard 3.2 hardware, and on a 3.0.5 card whose ECDH is not good enough:
        // the two answers a fleet run records for ImpalaApplet.cap.
        assertEquals(1, engineAfterInitialize(vpcdCard(VpcdSimulator.KEY_PLATFORM to "jc32", VpcdSimulator.KEY_ED25519 to "soft")))
        assertNull(engineAfterInitialize(vpcdCard(VpcdSimulator.KEY_PLATFORM to "jc305-no-xy", VpcdSimulator.KEY_ED25519 to "soft")))
        assertNull(engineAfterInitialize(vpcdCard(VpcdSimulator.KEY_PLATFORM to "jc305-wrong-curve-math")))
        // The native CAP does not load on a JavaCard 3.0.5 card: the simulator has no card to serve.
        assertFailsWith<CapNotLoadableException> { vpcdCard(VpcdSimulator.KEY_PLATFORM to "jc305", VpcdSimulator.KEY_ED25519 to "native") }
        assertFailsWith<IllegalArgumentException> { vpcdCard(VpcdSimulator.KEY_PLATFORM to "jc99") }
        // Without the key nothing changes: the default CAP on a JavaCard 3.0.5 card.
        vpcdCard().let {
            assertEquals(CapVariant.SOFT to CardPlatform.JC305, it.capVariant to it.platform)
        }
    }

    // ------------------------------------------------------------------ the CAP files

    /** `applet/build`, where `:applet:buildJavacard` leaves the CAPs (set by the build; absent in a bare test run). */
    private val capDir: File? = System.getProperty("impala.cap.dir")?.let { File(it) }

    @Test
    fun `the CAP files import what CapVariant says`() {
        val present = CapVariant.values().mapNotNull { v -> capDir?.let { File(it, v.fileName) }?.takeIf { it.isFile }?.let { v to it } }
        if (present.isEmpty()) {
            println("no CAP file under ${capDir ?: "(impala.cap.dir not set)"}: build them with :applet:buildJavacard [-Papplet.ed25519=native|none] and run :simulator:capMatrix")
            return
        }
        for ((variant, file) in present) {
            val cap = CapFile(file)
            assertEquals(emptyList(), cap.differencesFrom(variant), file.name)
            assertEquals(CardPlatform.Level.values().map { variant.loadsOn(preset(it)) }, CardPlatform.Level.values().map { cap.loadsOn(it) }, "${file.name}: which levels load it")
            assertEquals(CapFile.AID_LANG, cap.imports.first { it.packageName == "java.lang" }.aidHex)
            assertTrue(cap.packageAidHex.isNotEmpty() && cap.packageVersion.isNotEmpty(), file.name)
        }
    }

    private fun preset(level: CardPlatform.Level): CardPlatform = when (level) {
        CardPlatform.Level.JC305 -> CardPlatform.JC305
        CardPlatform.Level.JC31 -> CardPlatform.JC31
        CardPlatform.Level.JC32 -> CardPlatform.JC32
    }

    @Test
    fun `a file that is not a CAP is refused`() {
        val notCap = File.createTempFile("not-a-cap", ".cap").apply { deleteOnExit(); writeBytes(byteArrayOf(1, 2, 3)) }
        assertFailsWith<Exception> { CapFile(notCap) }
    }
}
