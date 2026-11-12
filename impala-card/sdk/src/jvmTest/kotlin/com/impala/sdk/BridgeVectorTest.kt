package com.impala.sdk

import com.impala.sdk.flows.Sep10Flow
import com.impala.sdk.models.PersonalizationProtocol
import com.impala.sdk.models.StellarCardKey
import com.impala.sdk.stellar.Jdk25519
import com.impala.sdk.stellar.Sep10Challenge
import com.impala.sdk.stellar.Sep10Expectation
import com.impala.sdk.stellar.StrKey
import com.impala.simulator.SimulatorBibo
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Cross-stream vectors shared with impala-bridge
 * (`impala-bridge/src/sep10/card_vectors.rs` holds the same constants):
 * a login challenge exactly as the bridge issues it, signed here by the real
 * applet, and bytes the applet produced that the bridge's verifier checks.
 *
 * The card is the deterministic simulator card (`distinctKeys = false`,
 * JavaCard 3.0.5 Ed25519 engine): jcardsim generates the same keys on every
 * run, so the challenge issued for its Stellar key can be a constant. A change
 * to any of these bytes on either side is a contract change.
 */
class BridgeVectorTest {
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }

    private companion object {
        const val TESTNET = "Test SDF Network ; September 2015"
        const val HOME = "api-testnet.example.com"
        const val NOW = 1_800_000_000L

        /** The bridge's vector server key: the RFC 8032 section 7.1 TEST 1 public key. */
        const val SERVER_PUB = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

        /** The deterministic simulator card. */
        const val CARD_ADDRESS = "GDLS7C3FEUC6BTSO5STMCXV2RNRPQS5RDK6ASC5LUIJFLN2VKP6ZTXHF"
        const val CARD_EC_PUB = "042b495a9b4142dc317624626ad108d4896c12a97af1a1372e9a7b0f29adcaeb49dee377c97fbb17b61480e857f5ce72408488e2763619159d032d3be091266dd6"

        /** `challenge::build` output for that card: version 7, minTime [NOW], TTL 300, r16 = 16 x 0x5a. */
        const val ISSUED =
            "AAAAAgAAAADXWpgBgrEKt9VL/tPJZAc6DuFy89qmIyWvAhpo9wdRGgAAAMgAAAAAAAAAAAAAAAEAAAAAa0nSAAAAAABrSdMsAAAAAAAAAAIAAAABAAAAANcvi2UlBeDOTuymwV66i2L4S7EavAkLq6ISVbdVU/2ZAAAACgAAABxhcGktdGVzdG5ldC5leGFtcGxlLmNvbSBhdXRoAAAAAQAAAEBXbHBhV2xwYVdscGFXbHBhV2xwYVdoRWdFNlM1UHdNeE51NnhxUS8yeXRyWWsyVkhZZjFhWDczZ0djUWVqeXZkAAAAAQAAAADXWpgBgrEKt9VL/tPJZAc6DuFy89qmIyWvAhpo9wdRGgAAAAoAAAAPd2ViX2F1dGhfZG9tYWluAAAAAAEAAAAXYXBpLXRlc3RuZXQuZXhhbXBsZS5jb20AAAAAAAAAAAH3B1EaAAAAQEaF82VZmJjfApz9tqEpS/sDsigAZIyf8SHztaUn5LdRCxw14B77qpqeKEGtGbPqepGKw3ZGe4aYXQ5PaJ64VwA="

        /** The registration account of the vector (the bridge tests' `ACCOUNT`). */
        const val ACCOUNT = "00112233445566778899aabbccddeeff"

        /**
         * [ISSUED] with the card's signature appended, as posted to
         * `POST /auth/sep10`. Captured from one run (the JavaCard 3.0.5 engine
         * hedges its nonce, so a new run gives another, equally valid signature).
         */
        const val SIGNED =
            "AAAAAgAAAADXWpgBgrEKt9VL/tPJZAc6DuFy89qmIyWvAhpo9wdRGgAAAMgAAAAAAAAAAAAAAAEAAAAAa0nSAAAAAABrSdMsAAAAAAAAAAIAAAABAAAAANcvi2UlBeDOTuymwV66i2L4S7EavAkLq6ISVbdVU/2ZAAAACgAAABxhcGktdGVzdG5ldC5leGFtcGxlLmNvbSBhdXRoAAAAAQAAAEBXbHBhV2xwYVdscGFXbHBhV2xwYVdoRWdFNlM1UHdNeE51NnhxUS8yeXRyWWsyVkhZZjFhWDczZ0djUWVqeXZkAAAAAQAAAADXWpgBgrEKt9VL/tPJZAc6DuFy89qmIyWvAhpo9wdRGgAAAAoAAAAPd2ViX2F1dGhfZG9tYWluAAAAAAEAAAAXYXBpLXRlc3RuZXQuZXhhbXBsZS5jb20AAAAAAAAAAAL3B1EaAAAAQEaF82VZmJjfApz9tqEpS/sDsigAZIyf8SHztaUn5LdRCxw14B77qpqeKEGtGbPqepGKw3ZGe4aYXQ5PaJ64VwBVU/2ZAAAAQD5j/mz4dfCycHkSai6dC23Xdio+GWlmCMT7i2qFmqUVrF0IsVp8Gq7w6REyFvr8gDG9VzN+TPEC+bBFAT7CIQk="

        // A registration (`POST /card`) of that card, captured from the same run:
        // its card id and the two cross-signatures over ACCOUNT, the card id and the keys.
        const val REG_CARD_ID = "ea94fa5b0f6b2abc1626bc50c0bd5e17"
        const val REG_BINDING_SIG = "304502202b495a9b4142dc317624626ad108d4896c12a97af1a1372e9a7b0f29adcaeb49022100fde245243f8e85f3c60a013d3423d514499cd65fa46d9b26622712ea13b90603"
        const val REG_PROOF_SIG = "6da881be63f5dc8c56e103625c67d5c89fc5c88a53629b7884775d522a763beffba92b3107031f2e0ead000068049e4bc3633b4de6428073eb429100f2e7e705"
    }

    /** The deterministic card, personalized for [ACCOUNT]. */
    private fun deterministicCard(): ImpalaSDK {
        val keys = customKeys()
        val bibo = SimulatorBibo(
            installParams = PersonalizationProtocol.installParams(false, keys, null, null),
            distinctKeys = false,
            ed25519 = SimulatorBibo.ED25519_SOFT
        )
        val sdk = ImpalaSDK(bibo, keys)
        sdk.setSeed()
        val issuer = TestIssuer()
        val ecPub = sdk.getECPubKey().toByteArray()
        sdk.openSecureChannel()
        sdk.personalize(hex(ACCOUNT), USDC, issuer.programId, issuer.certify(hex(ACCOUNT), USDC, ecPub), issuer.pub65)
        sdk.closeSecureChannel()
        return sdk
    }

    private fun verified(cardKey: ByteArray): Sep10Challenge =
        Sep10Challenge.verify(ISSUED, Sep10Expectation(hex(SERVER_PUB), TESTNET, HOME, HOME, cardKey), NOW, Jdk25519.verifier)

    @Test
    fun `the deterministic simulator card has the pinned keys`() {
        val sdk = deterministicCard()
        val key = sdk.getStellarKey()!!
        assertEquals(CARD_ADDRESS, key.address)
        assertEquals(CARD_EC_PUB, sdk.getECPubKey().hex())
        assertEquals(StellarCardKey.ENGINE_SOFT, key.engine)
    }

    @Test
    fun `the bridge's challenge passes the client checks and the card signs it`() {
        val sdk = deterministicCard()
        val key = sdk.getStellarKey()!!.publicKey
        val challenge = verified(key)
        // the challenge as the bridge documents it: 324 bytes here, two entries, five minutes
        assertEquals(324, challenge.transactionBytes.size)
        assertEquals(NOW, challenge.minTime)
        assertEquals(NOW + 300, challenge.maxTime)
        val envelope = Base64.getDecoder().decode(Sep10Flow.sign(sdk, key, challenge, Jdk25519.verifier))
        val issued = Base64.getDecoder().decode(ISSUED)
        // the server's envelope, byte for byte, with the signature count raised and one signature appended
        val txEnd = 4 + challenge.transactionBytes.size
        assertContentEquals(issued.copyOfRange(0, txEnd), envelope.copyOfRange(0, txEnd))
        assertContentEquals(byteArrayOf(0, 0, 0, 2), envelope.copyOfRange(txEnd, txEnd + 4))
        assertContentEquals(issued.copyOfRange(txEnd + 4, issued.size), envelope.copyOfRange(txEnd + 4, issued.size))
        assertEquals(issued.size + 72, envelope.size)
        assertContentEquals(key.copyOfRange(28, 32), envelope.copyOfRange(issued.size, issued.size + 4))
        assertTrue(Jdk25519.verify(key, challenge.hash, envelope.copyOfRange(issued.size + 8, envelope.size)))
    }

    @Test
    fun `the pinned card-signed envelope and registration verify here as they do in the bridge`() {
        val key = StrKey.decodeAccountId(CARD_ADDRESS)
        val challenge = verified(key)
        val signed = Base64.getDecoder().decode(SIGNED)
        val issued = Base64.getDecoder().decode(ISSUED)
        assertEquals(issued.size + 72, signed.size)
        assertContentEquals(challenge.transactionBytes, signed.copyOfRange(4, 4 + challenge.transactionBytes.size))
        assertTrue(Jdk25519.verify(hex(SERVER_PUB), challenge.hash, signed.copyOfRange(issued.size - 64, issued.size)), "server signature")
        assertTrue(Jdk25519.verify(key, challenge.hash, signed.copyOfRange(signed.size - 64, signed.size)), "card signature")
        assertEquals(SIGNED, challenge.signedEnvelope(signed.copyOfRange(signed.size - 64, signed.size)), "the framing is the SDK's own")

        val binding = StellarCardKey.bindingMessage(hex(ACCOUNT), hex(REG_CARD_ID), key)
        val proof = StellarCardKey.proofMessage(hex(ACCOUNT), hex(REG_CARD_ID), hex(CARD_EC_PUB))
        assertTrue(Jca.verifyP256(Jca.jcaPublicKey(hex(CARD_EC_PUB)), binding, hex(REG_BINDING_SIG)), "binding signature")
        assertTrue(Jdk25519.verify(key, proof, hex(REG_PROOF_SIG)), "proof of possession")
    }
}
