package com.payala.impala.demo.ui.lab

import androidx.annotation.StringRes
import com.impala.sdk.apdu4j.ApduExchange
import com.impala.sdk.apdu4j.ApduStats
import com.impala.sdk.flows.CardError
import com.impala.sdk.flows.UuidBytes
import com.payala.impala.card.CardInspection
import com.payala.impala.demo.R

/** The Doctor's verdict vocabulary. FAIL only when the card or the bridge positively says no. */
enum class CheckStatus { PASS, FAIL, WARN, SKIP, INFO }

/** Every check the Doctor runs, in display order. */
enum class CheckId {
    READER, ISO14443_4, APPLET_SELECTED, APPLET_VERSION, PERSONALIZED, CERT_CARD_ISSUER,
    ISSUER_MATCHES_BRIDGE, CERT_BRIDGE_KEY, BRIDGE_KNOWS_CARD, LOCAL_RECORD, ACCOUNT_MATCHES,
    SELECTED_CARD, FIELD_QUALITY;

    /** Checks that need an answer from the card's applet (skipped when no applet answered). */
    val needsApplet: Boolean
        get() = this in setOf(
            APPLET_VERSION, PERSONALIZED, CERT_CARD_ISSUER, ISSUER_MATCHES_BRIDGE, CERT_BRIDGE_KEY,
            BRIDGE_KNOWS_CARD, LOCAL_RECORD, ACCOUNT_MATCHES, SELECTED_CARD
        )
}

/** Something the user can do about a check, offered as a button on its row. */
enum class CheckAction { OPEN_NFC_SETTINGS }

/**
 * One Doctor verdict. [detailArgs] are identifiers, versions and counts only
 * (never a name, balance or key), formatted into [detailRes].
 */
data class DoctorCheck(
    val id: CheckId,
    val status: CheckStatus,
    @StringRes val titleRes: Int,
    @StringRes val detailRes: Int,
    val detailArgs: List<String> = emptyList(),
    @StringRes val remedyRes: Int? = null,
    val action: CheckAction? = null
)

/** How this device can reach a card. */
enum class ReaderState { NFC_ENABLED, NFC_DISABLED, NFC_ABSENT, SIMULATED }

/** What the bridge's public `GET /card-issuer` said. */
sealed interface IssuerFacts {
    /** Not asked yet. */
    object NotChecked : IssuerFacts

    /** `configured: false`, or the endpoint does not exist on this bridge. */
    object Unconfigured : IssuerFacts

    /** No usable answer ([reason] is a failure class such as `CONNECT` or `HTTP_500`). */
    class Unreachable(val reason: String) : IssuerFacts

    class Known(val programIdHex: String?, val publicKeyHex: String?) : IssuerFacts
}

/** What the owner endpoint `GET /offline/cards/{id}` said about the card. */
sealed interface BridgeCardFacts {
    object NotChecked : BridgeCardFacts
    object NoSession : BridgeCardFacts
    class Found(val certified: Boolean) : BridgeCardFacts
    class Http(val code: Int) : BridgeCardFacts
    class Network(val reason: String) : BridgeCardFacts
}

/**
 * Everything the Doctor looks at. A card read happens first (in the tap); the
 * bridge facts are fetched afterwards, never while the card is in the field.
 *
 * @property inspection the last read, or null when none succeeded
 * @property readError the typed failure of the last read when it did not produce an inspection
 * @property readFailed the last read failed without a [CardError] (e.g. the simulated card was unreachable)
 * @property simulated the last read used the simulated card
 * @property sessionAccountId the signed-in account, or null pre-login
 * @property localRecord whether this device registered the card (null when there is no session)
 * @property expectedCardId the card the Lab was opened for (Cards → Inspect in Card Lab), if any
 */
class DoctorInput(
    val reader: ReaderState,
    val inspection: CardInspection? = null,
    val readError: CardError? = null,
    val readFailed: Boolean = false,
    val simulated: Boolean = false,
    val exchanges: List<ApduExchange> = emptyList(),
    val issuer: IssuerFacts = IssuerFacts.NotChecked,
    val bridgeCard: BridgeCardFacts = BridgeCardFacts.NotChecked,
    val sessionAccountId: String? = null,
    val localRecord: Boolean? = null,
    val expectedCardId: String? = null
)

/**
 * Card ↔ bridge ↔ session diagnosis. Pure: given what the Lab read and what
 * the bridge said, the ordered verdicts. Wording is honest about what was
 * checked: "verifies under this bridge's key" is a local ECDSA check, and a
 * local record is never called "registered".
 */
object CardDoctor {

    /** The minimum applet version the bridge flows need. */
    private const val MIN_MAJOR = 0
    private const val MIN_MINOR = 2

    fun run(input: DoctorInput): List<DoctorCheck> {
        val out = ArrayList<DoctorCheck>()
        out += reader(input)
        val insp = input.inspection
        val err = input.readError
        val attempted = insp != null || err != null || input.readFailed
        out += iso(input, attempted)
        val applet = applet(input, attempted)
        out += applet
        val appletOk = applet.status == CheckStatus.PASS

        fun cardCheck(id: CheckId, @StringRes title: Int, block: (CardInspection) -> DoctorCheck): DoctorCheck = when {
            !attempted -> skip(id, title, R.string.lab_doc_no_card_yet)
            !appletOk || insp == null -> skip(id, title, R.string.lab_doc_skip_no_applet)
            else -> block(insp)
        }

        out += cardCheck(CheckId.APPLET_VERSION, R.string.lab_doc_title_version) { version(it) }
        out += cardCheck(CheckId.PERSONALIZED, R.string.lab_doc_title_personalized) { personalized(it) }
        out += cardCheck(CheckId.CERT_CARD_ISSUER, R.string.lab_doc_title_cert_card_issuer) { certCardIssuer(it) }
        out += cardCheck(CheckId.ISSUER_MATCHES_BRIDGE, R.string.lab_doc_title_issuer) { issuerMatches(it, input.issuer) }
        out += cardCheck(CheckId.CERT_BRIDGE_KEY, R.string.lab_doc_title_cert_bridge) { certBridge(it, input.issuer) }
        out += cardCheck(CheckId.BRIDGE_KNOWS_CARD, R.string.lab_doc_title_bridge_card) { bridgeCard(it, input) }
        out += cardCheck(CheckId.LOCAL_RECORD, R.string.lab_doc_title_local_record) { localRecord(it, input) }
        out += cardCheck(CheckId.ACCOUNT_MATCHES, R.string.lab_doc_title_account) { account(it, input) }
        input.expectedCardId?.let { expected ->
            out += cardCheck(CheckId.SELECTED_CARD, R.string.lab_doc_title_selected) { selected(it, expected) }
        }
        out += fieldQuality(input, attempted)
        return out
    }

    private fun check(
        id: CheckId, status: CheckStatus, @StringRes title: Int, @StringRes detail: Int,
        args: List<String> = emptyList(), @StringRes remedy: Int? = null, action: CheckAction? = null
    ) = DoctorCheck(id, status, title, detail, args, remedy, action)

    private fun skip(id: CheckId, @StringRes title: Int, @StringRes detail: Int, args: List<String> = emptyList()) =
        check(id, CheckStatus.SKIP, title, detail, args)

    private fun reader(input: DoctorInput): DoctorCheck {
        val t = R.string.lab_doc_title_reader
        return when (input.reader) {
            ReaderState.NFC_ENABLED -> check(CheckId.READER, CheckStatus.PASS, t, R.string.lab_doc_reader_enabled)
            ReaderState.SIMULATED -> check(CheckId.READER, CheckStatus.PASS, t, R.string.lab_doc_reader_simulated)
            ReaderState.NFC_DISABLED -> check(
                CheckId.READER, CheckStatus.FAIL, t, R.string.lab_doc_reader_disabled,
                remedy = R.string.lab_doc_reader_disabled_fix, action = CheckAction.OPEN_NFC_SETTINGS
            )
            ReaderState.NFC_ABSENT -> check(CheckId.READER, CheckStatus.FAIL, t, R.string.lab_doc_reader_absent)
        }
    }

    private fun iso(input: DoctorInput, attempted: Boolean): DoctorCheck {
        val t = R.string.lab_doc_title_iso
        val facts = input.inspection?.transport
        return when {
            !attempted -> skip(CheckId.ISO14443_4, t, R.string.lab_doc_no_card_yet)
            input.simulated -> skip(CheckId.ISO14443_4, t, R.string.lab_doc_iso_simulated)
            // The session refuses a tag that is not ISO 14443-4 before any command.
            input.readError is CardError.InvalidRequest ->
                check(CheckId.ISO14443_4, CheckStatus.FAIL, t, R.string.lab_doc_iso_fail, remedy = R.string.lab_doc_iso_fail_fix)
            facts != null && facts.iso14443Part4 ->
                check(CheckId.ISO14443_4, CheckStatus.PASS, t, R.string.lab_doc_iso_pass, listOf(facts.techList.joinToString(", ")))
            facts != null -> check(CheckId.ISO14443_4, CheckStatus.FAIL, t, R.string.lab_doc_iso_fail, remedy = R.string.lab_doc_iso_fail_fix)
            input.inspection != null -> skip(CheckId.ISO14443_4, t, R.string.lab_doc_iso_unknown)
            else -> skip(CheckId.ISO14443_4, t, R.string.lab_doc_read_incomplete)
        }
    }

    private fun applet(input: DoctorInput, attempted: Boolean): DoctorCheck {
        val t = R.string.lab_doc_title_applet
        val insp = input.inspection
        val err = input.readError
        val firstStepError = insp?.steps?.firstOrNull()?.error
        return when {
            !attempted -> skip(CheckId.APPLET_SELECTED, t, R.string.lab_doc_no_card_yet)
            err is CardError.AppletNotFound -> appletNotFound(err)
            // Default selection: a card without the applet answers the first command instead of a SELECT.
            firstStepError is CardError.AppletNotFound -> appletNotFound(firstStepError)
            insp == null -> skip(CheckId.APPLET_SELECTED, t, R.string.lab_doc_read_incomplete)
            // Default selection sends no SELECT: only an answered GET_VERSION (every Impala applet
            // answers it) shows the default applet is ours. A refusal is a "no"; a lost or garbled
            // answer is no answer.
            insp.aidHex == null && insp.steps.firstOrNull()?.ok != true -> when {
                firstStepError?.statusWord != null && firstStepError !is CardError.TagLost -> appletNotFound(firstStepError)
                else -> skip(CheckId.APPLET_SELECTED, t, R.string.lab_doc_read_incomplete)
            }
            else -> insp.aidHex?.let { aid ->
                check(CheckId.APPLET_SELECTED, CheckStatus.PASS, t, R.string.lab_doc_applet_selected, listOf(aid))
            } ?: check(CheckId.APPLET_SELECTED, CheckStatus.PASS, t, R.string.lab_doc_applet_default)
        }
    }

    private fun appletNotFound(e: CardError): DoctorCheck = check(
        CheckId.APPLET_SELECTED, CheckStatus.FAIL, R.string.lab_doc_title_applet, R.string.lab_doc_applet_not_found,
        listOf(e.statusWordHex ?: "?"), remedy = R.string.lab_doc_applet_not_found_fix
    )

    private fun version(insp: CardInspection): DoctorCheck {
        val t = R.string.lab_doc_title_version
        val major = insp.versionMajor
        val minor = insp.versionMinor
        if (major == null || minor == null) return skip(CheckId.APPLET_VERSION, t, R.string.lab_doc_no_identity)
        val line = insp.versionLine ?: "$major.$minor"
        val ok = major > MIN_MAJOR || (major == MIN_MAJOR && minor >= MIN_MINOR)
        return if (ok) check(CheckId.APPLET_VERSION, CheckStatus.PASS, t, R.string.lab_doc_version_ok, listOf(line))
        else check(CheckId.APPLET_VERSION, CheckStatus.FAIL, t, R.string.lab_doc_version_old, listOf(line), R.string.lab_doc_version_old_fix)
    }

    private fun personalized(insp: CardInspection): DoctorCheck {
        val t = R.string.lab_doc_title_personalized
        val state = insp.stateName ?: "?"
        return when {
            insp.personalized == null -> skip(CheckId.PERSONALIZED, t, R.string.lab_doc_no_identity)
            insp.terminated == true -> check(CheckId.PERSONALIZED, CheckStatus.FAIL, t, R.string.lab_doc_terminated, listOf(state), R.string.lab_doc_terminated_fix)
            insp.personalized == false -> check(CheckId.PERSONALIZED, CheckStatus.FAIL, t, R.string.lab_doc_not_personalized, listOf(state), R.string.lab_doc_not_personalized_fix)
            else -> check(CheckId.PERSONALIZED, CheckStatus.PASS, t, R.string.lab_doc_personalized, listOf(state))
        }
    }

    private fun certCardIssuer(insp: CardInspection): DoctorCheck {
        val t = R.string.lab_doc_title_cert_card_issuer
        return when (insp.certVerifiedByCardIssuer) {
            true -> check(CheckId.CERT_CARD_ISSUER, CheckStatus.PASS, t, R.string.lab_doc_cert_card_ok)
            false -> check(CheckId.CERT_CARD_ISSUER, CheckStatus.FAIL, t, R.string.lab_doc_cert_card_bad, remedy = R.string.lab_doc_cert_bad_fix)
            null -> skip(CheckId.CERT_CARD_ISSUER, t, R.string.lab_doc_no_certificate)
        }
    }

    private fun bridgeSkip(id: CheckId, @StringRes t: Int, issuer: IssuerFacts): DoctorCheck? = when (issuer) {
        IssuerFacts.NotChecked -> skip(id, t, R.string.lab_doc_bridge_not_checked)
        IssuerFacts.Unconfigured -> skip(id, t, R.string.lab_doc_bridge_unconfigured)
        is IssuerFacts.Unreachable -> skip(id, t, R.string.lab_doc_bridge_unreachable, listOf(issuer.reason))
        is IssuerFacts.Known -> null
    }

    private fun issuerMatches(insp: CardInspection, issuer: IssuerFacts): DoctorCheck {
        val t = R.string.lab_doc_title_issuer
        bridgeSkip(CheckId.ISSUER_MATCHES_BRIDGE, t, issuer)?.let { return it }
        val bridgeProgram = (issuer as IssuerFacts.Known).programIdHex
        val cardProgram = insp.programIdHex
        return when {
            cardProgram == null -> skip(CheckId.ISSUER_MATCHES_BRIDGE, t, R.string.lab_doc_no_identity)
            bridgeProgram.isNullOrBlank() -> skip(CheckId.ISSUER_MATCHES_BRIDGE, t, R.string.lab_doc_bridge_no_program)
            cardProgram.equals(bridgeProgram.trim(), ignoreCase = true) ->
                check(CheckId.ISSUER_MATCHES_BRIDGE, CheckStatus.PASS, t, R.string.lab_doc_issuer_match, listOf(cardProgram))
            else -> check(
                CheckId.ISSUER_MATCHES_BRIDGE, CheckStatus.FAIL, t, R.string.lab_doc_issuer_mismatch,
                listOf(cardProgram, bridgeProgram.trim()), R.string.lab_doc_issuer_mismatch_fix
            )
        }
    }

    private fun certBridge(insp: CardInspection, issuer: IssuerFacts): DoctorCheck {
        val t = R.string.lab_doc_title_cert_bridge
        bridgeSkip(CheckId.CERT_BRIDGE_KEY, t, issuer)?.let { return it }
        val key = (issuer as IssuerFacts.Known).publicKeyHex
        if (key.isNullOrBlank()) return skip(CheckId.CERT_BRIDGE_KEY, t, R.string.lab_doc_bridge_no_key)
        return when (insp.certificateVerifiesUnder(key)) {
            true -> check(CheckId.CERT_BRIDGE_KEY, CheckStatus.PASS, t, R.string.lab_doc_cert_bridge_ok)
            false -> check(CheckId.CERT_BRIDGE_KEY, CheckStatus.FAIL, t, R.string.lab_doc_cert_bridge_bad, remedy = R.string.lab_doc_issuer_mismatch_fix)
            null -> skip(CheckId.CERT_BRIDGE_KEY, t, R.string.lab_doc_no_certificate)
        }
    }

    private fun bridgeCard(insp: CardInspection, input: DoctorInput): DoctorCheck {
        val t = R.string.lab_doc_title_bridge_card
        val id = CheckId.BRIDGE_KNOWS_CARD
        if (input.sessionAccountId == null) return skip(id, t, R.string.lab_doc_no_session)
        if (insp.wireCardId == null) return skip(id, t, R.string.lab_doc_no_identity)
        return when (val facts = input.bridgeCard) {
            BridgeCardFacts.NoSession -> skip(id, t, R.string.lab_doc_no_session)
            BridgeCardFacts.NotChecked -> skip(id, t, R.string.lab_doc_bridge_not_checked)
            is BridgeCardFacts.Found -> check(
                id, CheckStatus.PASS, t,
                if (facts.certified) R.string.lab_doc_bridge_card_certified else R.string.lab_doc_bridge_card_known
            )
            is BridgeCardFacts.Http -> when (facts.code) {
                // This phone registered the card (POST /card succeeded), so a 404 from the offline
                // lane's owner endpoint is not "unregistered": the lane may simply not be deployed.
                404 -> if (input.localRecord == true) {
                    check(id, CheckStatus.INFO, t, R.string.lab_doc_bridge_card_no_offline_record, listOf(facts.code.toString()))
                } else {
                    check(id, CheckStatus.WARN, t, R.string.lab_doc_bridge_card_missing, listOf(facts.code.toString()), R.string.lab_doc_bridge_card_missing_fix)
                }
                503 -> check(id, CheckStatus.WARN, t, R.string.lab_doc_bridge_card_missing, listOf(facts.code.toString()), R.string.lab_doc_bridge_card_missing_fix)
                401, 403 -> skip(id, t, R.string.lab_doc_session_expired, listOf(facts.code.toString()))
                else -> skip(id, t, R.string.lab_doc_bridge_unreachable, listOf("HTTP_${facts.code}"))
            }
            is BridgeCardFacts.Network -> skip(id, t, R.string.lab_doc_bridge_unreachable, listOf(facts.reason))
        }
    }

    private fun localRecord(insp: CardInspection, input: DoctorInput): DoctorCheck {
        val t = R.string.lab_doc_title_local_record
        val id = CheckId.LOCAL_RECORD
        return when {
            input.sessionAccountId == null || input.localRecord == null -> skip(id, t, R.string.lab_doc_no_session)
            insp.wireCardId == null -> skip(id, t, R.string.lab_doc_no_identity)
            input.localRecord -> check(id, CheckStatus.PASS, t, R.string.lab_doc_local_present)
            else -> check(id, CheckStatus.WARN, t, R.string.lab_doc_local_absent, remedy = R.string.lab_doc_local_absent_fix)
        }
    }

    private fun account(insp: CardInspection, input: DoctorInput): DoctorCheck {
        val t = R.string.lab_doc_title_account
        val id = CheckId.ACCOUNT_MATCHES
        val session = input.sessionAccountId ?: return skip(id, t, R.string.lab_doc_no_session)
        val card = insp.accountUuid ?: return skip(id, t, R.string.lab_doc_no_identity)
        return if (UuidBytes.same(session, card)) check(id, CheckStatus.PASS, t, R.string.lab_doc_account_match)
        else check(id, CheckStatus.FAIL, t, R.string.lab_doc_account_mismatch, listOf(card), R.string.lab_doc_account_mismatch_fix)
    }

    private fun selected(insp: CardInspection, expected: String): DoctorCheck {
        val t = R.string.lab_doc_title_selected
        val id = CheckId.SELECTED_CARD
        val card = insp.wireCardId ?: return skip(id, t, R.string.lab_doc_no_identity)
        return if (card.equals(expected, ignoreCase = true)) check(id, CheckStatus.PASS, t, R.string.lab_doc_selected_match)
        else check(id, CheckStatus.WARN, t, R.string.lab_doc_selected_other, listOf(expected))
    }

    private fun fieldQuality(input: DoctorInput, attempted: Boolean): DoctorCheck {
        val t = R.string.lab_doc_title_field
        if (!attempted || input.exchanges.isEmpty()) {
            return check(CheckId.FIELD_QUALITY, CheckStatus.INFO, t, R.string.lab_doc_field_none)
        }
        val stats = ApduStats.of(input.exchanges)
        val slowest = input.exchanges.maxByOrNull { it.elapsedNanos }!!
        return check(
            CheckId.FIELD_QUALITY, CheckStatus.INFO, t, R.string.lab_doc_field,
            listOf(stats.count.toString(), stats.tagLosses.toString(), slowest.insName, slowest.elapsedMillis.toString())
        )
    }
}
