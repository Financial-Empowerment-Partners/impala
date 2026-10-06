package com.impala.simulator

import com.impala.sdk.ImpalaSDK
import kotlin.test.Test
import kotlin.test.assertEquals

class SimulatorApduServerTest {
    @Test
    fun `round-trips GET_VERSION and keeps the card across connections`() {
        SimulatorApduServer(port = 0).start().use { server ->
            TcpApduClient("127.0.0.1", server.port).use { client ->
                assertEquals(2, ImpalaSDK(client).getImpalaAppletVersion().minor.toInt())
                ImpalaSDK(client).setSeed()
            }
            TcpApduClient("127.0.0.1", server.port).use { client ->
                // Same card: already initialized, so a second INITIALIZE is refused (0x6686).
                val r = runCatching { ImpalaSDK(client).setSeed() }
                assertEquals(0x6686, (r.exceptionOrNull() as com.impala.sdk.models.ImpalaException).statusWord)
            }
        }
    }
}
