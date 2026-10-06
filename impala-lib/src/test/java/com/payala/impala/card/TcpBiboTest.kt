package com.payala.impala.card

import com.impala.simulator.SimulatorApduServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class TcpBiboTest {
    @Test
    fun `round-trips GET_VERSION against SimulatorApduServer on localhost`() {
        SimulatorApduServer(port = 0).start().use { server ->
            val session = ImpalaCardSession.openForTest(TcpBibo("127.0.0.1", server.port))
            val version = offMain { session.use { it.sdk.getImpalaAppletVersion() } }
            assertEquals(0, version.major.toInt())
            assertEquals(2, version.minor.toInt())
        }
    }

    @Test
    fun `endpoint property parsing`() {
        assertEquals("10.0.2.2" to 9443, DebugCardTransport.parseEndpoint("10.0.2.2:9443"))
        assertNull(DebugCardTransport.parseEndpoint(""))
        assertNull(DebugCardTransport.parseEndpoint("host"))
        assertNull(DebugCardTransport.parseEndpoint("host:99999"))
    }
}
