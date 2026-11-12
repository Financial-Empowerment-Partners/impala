package com.payala.impala.card

import com.impala.sdk.apdu4j.ApduExchange
import com.impala.sdk.flows.CardError
import com.impala.sdk.flows.CardFlowException
import com.impala.simulator.SimulatorApduServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket

@RunWith(RobolectricTestRunner::class)
class TcpBiboTest {
    /** A loopback port nothing listens on (bound, then released). */
    private fun closedPort(): Int = ServerSocket().use { it.bind(InetSocketAddress(InetAddress.getLoopbackAddress(), 0)); it.localPort }

    @Test
    fun `round-trips GET_VERSION against SimulatorApduServer on localhost`() {
        SimulatorApduServer(port = 0).start().use { server ->
            val session = ImpalaCardSession.openForTest(TcpBibo("127.0.0.1", server.port))
            val version = offMain { session.use { it.sdk.getImpalaAppletVersion() } }
            assertEquals(0, version.major.toInt())
            assertEquals(4, version.minor.toInt())
        }
    }

    @Test
    fun `endpoint property parsing`() {
        assertEquals("10.0.2.2" to 9443, DebugCardTransport.parseEndpoint("10.0.2.2:9443"))
        assertNull(DebugCardTransport.parseEndpoint(""))
        assertNull(DebugCardTransport.parseEndpoint("host"))
        assertNull(DebugCardTransport.parseEndpoint("host:99999"))
    }

    @Test
    fun `nothing configured means no endpoint, no session and no probe`() {
        assertNull(DebugCardTransport.endpointText())
        assertNull(offMain { DebugCardTransport.openConfiguredSession() })
        assertNull(offMain { DebugCardTransport.probeConfigured() })
    }

    @Test
    fun `openSession on a closed port is SimulatorUnreachableException naming host and port`() {
        val port = closedPort()
        val e = assertThrows(SimulatorUnreachableException::class.java) {
            offMain { DebugCardTransport.openSession("127.0.0.1", port, timeoutMs = 2_000) }
        }
        assertEquals("127.0.0.1:$port", e.endpoint)
        assertTrue(e.message!!.contains("127.0.0.1:$port"))
        assertTrue(e is IOException)
        assertTrue(e.cause is IOException)
    }

    @Test
    fun `openSession passes trace and read-only through to the session`() {
        SimulatorApduServer(port = 0).start().use { server ->
            val seen = mutableListOf<ApduExchange>()
            val session = offMain { DebugCardTransport.openSession("127.0.0.1", server.port, trace = { seen += it }, readOnly = true) }
            session.use {
                assertTrue(it.isReadOnly)
                assertNull(it.aidHex)
                offMain { it.sdk.getImpalaAppletVersion() }
                val e = assertThrows(CardFlowException::class.java) { offMain { CardAuthenticator.signChallenge(it, "ab".repeat(32)) } }
                assertTrue(e.error is CardError.ReadOnlyRefused)
            }
            assertEquals(listOf("GET_VERSION", "SIGN_AUTH"), seen.map { it.insName })
            assertEquals(ApduExchange.Outcome.REFUSED, seen.last().outcome)
        }
    }

    @Test
    fun `probe answers READY for a live simulator and DOWN for a closed port`() {
        SimulatorApduServer(port = 0).start().use { server ->
            val ready = offMain { DebugCardTransport.probe("127.0.0.1", server.port) }
            assertEquals(SimProbe.State.READY, ready.state)
            assertEquals("127.0.0.1:${server.port}", ready.endpoint)
            // The probe released the one-client simulator: a session still works.
            val v = offMain { DebugCardTransport.openSession("127.0.0.1", server.port).use { it.sdk.getImpalaAppletVersion() } }
            assertEquals(4, v.minor.toInt())
        }
        val down = offMain { DebugCardTransport.probe("127.0.0.1", closedPort(), timeoutMs = 500) }
        assertEquals(SimProbe.State.DOWN, down.state)
    }

    @Test
    fun `probe answers BUSY while another client holds the simulator, which is not wedged afterwards`() {
        SimulatorApduServer(port = 0).start().use { server ->
            val holder = offMain { DebugCardTransport.openSession("127.0.0.1", server.port) }
            offMain { holder.sdk.getImpalaAppletVersion() } // the server is now serving this client
            val busy = offMain { DebugCardTransport.probe("127.0.0.1", server.port, timeoutMs = 300) }
            assertEquals(SimProbe.State.BUSY, busy.state)
            holder.close()
            // The queued probe connection is drained, then a fresh session is served.
            val v = offMain { DebugCardTransport.openSession("127.0.0.1", server.port).use { it.sdk.getImpalaAppletVersion() } }
            assertEquals(4, v.minor.toInt())
            assertEquals(SimProbe.State.READY, offMain { DebugCardTransport.probe("127.0.0.1", server.port) }.state)
        }
    }

    @Test
    fun `a failed injection closes the TCP session so the simulator serves the next client`() {
        SimulatorApduServer(port = 0).start().use { server ->
            val controller = CardReaderController(org.robolectric.Robolectric.buildActivity(android.app.Activity::class.java).get(), null)
            val session = offMain { DebugCardTransport.openSession("127.0.0.1", server.port) }
            assertEquals(false, controller.debugInjectTapOrClose(session)) // reader mode is off
            assertTrue(session.isClosed)
            val v = offMain { DebugCardTransport.openSession("127.0.0.1", server.port).use { it.sdk.getImpalaAppletVersion() } }
            assertEquals(4, v.minor.toInt())
        }
    }
}
