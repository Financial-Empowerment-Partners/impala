package com.payala.impala.demo

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * T2 redeem UI (C-11): bad PIN shows tries remaining; the right PIN shows
 * `accepted` then `paid`. Needs the bridge's offline lane (D-3), which is not
 * built: skipped unless the orchestrator passes `-e offlineLane true`.
 */
@RunWith(AndroidJUnit4::class)
class CardRedeemUiTest {
    @Test
    fun redeemShowsTriesRemainingThenPaid() {
        assumeTrue(
            "the bridge's offline issuance/redemption lane (D-3) is not deployed",
            InstrumentationRegistry.getArguments().getString("offlineLane") == "true"
        )
        throw AssertionError("offline lane deployed: implement this scenario against it (plan §5.2 steps 7 and 9)")
    }
}
