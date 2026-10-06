package com.payala.impala.demo.e2e

import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * E2E-2, card-authorized transfer (T1): load (issuance credit) and redeem
 * (SIGN_TRANSFER_V2 tuple → testnet payout) through the app's
 * IssuanceController / RedemptionController.
 *
 * These need the bridge's offline issuance/redemption lane (handoff lane C2,
 * plan item D-3), which is not built yet; every test skips with that reason
 * until `GET /offline/cards/{id}` is served. The client side they would drive
 * is covered against mocks + jcardsim by RedemptionViewModelTest and
 * IssuanceViewModelTest.
 */
@RunWith(RobolectricTestRunner::class)
class CardTransferE2ETest {
    @Before
    fun setUp() {
        E2e.requireBridge()
        val (_, bearer) = E2e.holder
        assumeTrue(
            "the bridge does not serve the offline issuance/redemption lane (D-3) — transfer e2e skipped",
            E2e.offlineLaneDeployed(bearer)
        )
    }

    @Test
    fun `load - issuance funded from the holder's custodial testnet account, credit applied on the simulated card, ack 9000, GET offline cards shows the outstanding balance`() {
        pending()
    }

    @Test
    fun `redeem - PIN-authorized SIGN_TRANSFER_V2 tuple is accepted, paid on testnet, and the card balance and outstanding position both decrease by the amount`() {
        pending()
    }

    @Test
    fun `re-posting the identical tuple is a replay (202) and pays nothing twice`() {
        pending()
    }

    @Test
    fun `a tuple signed for a different recipient uuid is refused`() {
        pending()
    }

    @Test
    fun `wrong PIN on the card yields WrongPin(4) and no redemption is created`() {
        pending()
    }

    /** Reached only when D-3 is deployed: the scenario must then be written against its real behaviour. */
    private fun pending(): Nothing =
        throw AssertionError("the offline lane is deployed: implement this scenario against it (plan §5.2)")
}
