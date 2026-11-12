package com.payala.impala.demo.card

import com.impala.simulator.SimulatorApduServer
import com.payala.impala.card.SimulatorUnreachableException
import com.payala.impala.demo.offMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.shadows.ShadowSystemProperties
import java.io.IOException
import java.net.ConnectException
import java.net.ServerSocket

/**
 * The debug build's [DebugCards] adapter over impala-lib's debug transport:
 * the failure text found anywhere in a cause chain, the probe's state mapping,
 * and read-only sessions. Simulators here are ephemeral (port 0); nothing
 * touches a long-running one.
 */
@RunWith(RobolectricTestRunner::class)
class DebugCardsTest {
    private val property = "debug.impala.tcp_card"

    @After
    fun tearDown() {
        ShadowSystemProperties.override(property, "")
    }

    private fun configure(endpoint: String) = ShadowSystemProperties.override(property, endpoint)

    private fun closedPort(): Int = ServerSocket(0).use { it.localPort }

    @Test
    fun `describeFailure finds the simulator failure anywhere in the cause chain`() {
        val unreachable = SimulatorUnreachableException("127.0.0.1:9555", ConnectException("refused"))
        val wrapped = RuntimeException("tap failed", IllegalStateException("inner", unreachable))
        val text = DebugCards.describeFailure(wrapped)!!
        assertTrue(text, text.contains("127.0.0.1:9555"))
        assertTrue(text, text.contains("unreachable"))
        assertEquals(text, DebugCards.describeFailure(unreachable))
    }

    @Test
    fun `describeFailure is null for every other failure`() {
        assertNull(DebugCards.describeFailure(IOException("HTTP 503")))
        assertNull(DebugCards.describeFailure(RuntimeException("x", ConnectException("refused"))))
    }

    @Test
    fun `nothing is configured without the property`() {
        configure("")
        assertFalse(DebugCards.isConfigured())
        assertNull(DebugCards.endpointText())
        assertNull(offMain { DebugCards.probe() })
        assertNull(offMain { DebugCards.openSession(readOnly = true) })
    }

    @Test
    fun `the probe maps READY and DOWN`() {
        SimulatorApduServer(port = 0).start().use { server ->
            configure("127.0.0.1:${server.port}")
            assertTrue(DebugCards.isConfigured())
            assertEquals("127.0.0.1:${server.port}", DebugCards.endpointText())
            val ready = offMain { DebugCards.probe() }!!
            assertEquals(SimulatorStatus.State.READY, ready.state)
            assertEquals("127.0.0.1:${server.port}", ready.endpoint)
        }
        val port = closedPort()
        configure("127.0.0.1:$port")
        val down = offMain { DebugCards.probe() }!!
        assertEquals(SimulatorStatus.State.DOWN, down.state)
    }

    @Test
    fun `a read-only session to the simulator is read-only, and the simulator is released`() {
        SimulatorApduServer(port = 0).start().use { server ->
            configure("127.0.0.1:${server.port}")
            val minor = offMain { DebugCards.openSession(readOnly = true)!!.use { s -> assertTrue(s.isReadOnly); s.sdk.getImpalaAppletVersion().minor.toInt() } }
            assertEquals(4, minor)
            assertEquals(SimulatorStatus.State.READY, offMain { DebugCards.probe() }!!.state)
        }
    }

    @Test
    fun `an unreachable simulator throws an IOException that describeFailure renders`() {
        val port = closedPort()
        configure("127.0.0.1:$port")
        val e = assertThrows(IOException::class.java) { offMain { DebugCards.openSession(readOnly = true) } }
        assertTrue(DebugCards.describeFailure(e)!!.contains("127.0.0.1:$port"))
    }
}
