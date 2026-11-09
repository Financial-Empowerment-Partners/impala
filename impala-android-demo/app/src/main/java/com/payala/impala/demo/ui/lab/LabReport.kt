package com.payala.impala.demo.ui.lab

import android.content.res.Resources
import com.impala.sdk.apdu4j.ApduExchange
import com.impala.sdk.apdu4j.ApduStats
import com.impala.sdk.flows.CardError
import com.payala.impala.card.CardCertificates
import com.payala.impala.card.CardErrorMessages
import com.payala.impala.card.CardInspection
import com.payala.impala.card.CardTransportFacts
import com.payala.impala.card.LastTransferSummary
import com.payala.impala.card.Masked
import com.payala.impala.demo.R
import com.payala.impala.demo.card.SimulatorStatus
import com.payala.impala.demo.log.AppLogger
import com.payala.impala.demo.transfer.Money

/**
 * One Card Lab list row. A [Header] starts a group; an [Item] is a labelled
 * value. [Item.copyable] values are identifiers (ids, fingerprints, SWs) and
 * get a copy button; [Item.masked] rows show the sign-in hint instead of a
 * personal value and are never copyable. [Item.toString] never renders a
 * personal value, even when it is revealed on screen.
 */
sealed class LabRow {
    class Header(val title: String) : LabRow() {
        override fun equals(other: Any?) = other is Header && other.title == title
        override fun hashCode() = title.hashCode()
        override fun toString() = "Header($title)"
    }

    class Item(
        val label: String,
        val value: String,
        val copyable: Boolean = false,
        val masked: Boolean = false,
        /** The value is personal (a revealed name, balance or transfer): never logged, exported or copied. */
        val personal: Boolean = false,
        /** Tints the value: a verdict ([CheckStatus]) for yes/no facts, null for plain text. */
        val tone: CheckStatus? = null,
        /**
         * The value is an identifier (an id, fingerprint, AID, endpoint or hex
         * fact): shown in monospace and allowed to wrap at its separators.
         * Prose values ("None: …", "Verified under …") use the body face.
         */
        val identifier: Boolean = copyable
    ) : LabRow() {
        override fun equals(other: Any?) = other is Item && other.label == label && other.value == value &&
            other.copyable == copyable && other.masked == masked && other.personal == personal && other.tone == tone &&
            other.identifier == identifier

        override fun hashCode() = label.hashCode() * 31 + value.hashCode()
        override fun toString() = "Item($label=${if (personal) Masked.MASK else value})"
    }
}

/**
 * Renders what the Lab knows, for the screen ([screen], [device]) and for the
 * shared report ([export]).
 *
 * [screen] is the only place that calls [Masked.reveal], and only when the
 * caller says the signed-in account owns the card. [export] has **no PII
 * parameter**: it is built from identifiers, versions, fingerprints, verdicts
 * and header-only exchanges, so the holder name, balance, last transfer, raw
 * keys and the certificate cannot reach a share sheet.
 */
object LabReport {

    /**
     * The Inspector rows for [inspection]. [reveal] is true only while a
     * session exists and its account is the card's account; otherwise the
     * holder name, balance and last transfer read as the sign-in hint.
     */
    fun screen(res: Resources, inspection: CardInspection, reveal: Boolean, simulatedEndpoint: String? = null): List<LabRow> {
        val rows = ArrayList<LabRow>()
        fun header(id: Int) = rows.add(LabRow.Header(res.getString(id)))
        fun item(id: Int, value: String?, copyable: Boolean = false, tone: CheckStatus? = null, identifier: Boolean = copyable) {
            if (value != null) {
                rows.add(LabRow.Item(res.getString(id), value, copyable = copyable && value.isNotEmpty(), tone = tone, identifier = identifier))
            }
        }
        fun yesNo(v: Boolean?) = v?.let { res.getString(if (it) R.string.lab_yes else R.string.lab_no) }
        fun personal(id: Int, masked: Masked<*>?, render: (Any?) -> String) {
            if (masked == null) {
                rows.add(LabRow.Item(res.getString(id), res.getString(R.string.lab_not_read)))
            } else if (reveal) {
                rows.add(LabRow.Item(res.getString(id), render(masked.reveal()), personal = true))
            } else {
                rows.add(LabRow.Item(res.getString(id), res.getString(R.string.lab_pii_hint), masked = true))
            }
        }

        header(R.string.lab_group_transport)
        val t = inspection.transport
        if (t == null) {
            item(R.string.lab_row_link, res.getString(R.string.lab_link_simulated))
            simulatedEndpoint?.let { item(R.string.lab_row_endpoint, it, copyable = true) }
        } else {
            transportRows(res, t).forEach { rows += it }
        }

        header(R.string.lab_group_applet)
        item(R.string.lab_row_aid, inspection.aidHex ?: res.getString(R.string.lab_default_selection), copyable = inspection.aidHex != null)
        item(R.string.lab_row_version, inspection.versionLine ?: res.getString(R.string.lab_not_read), identifier = inspection.versionLine != null)
        item(R.string.lab_row_alive, yesNo(inspection.alive) ?: res.getString(R.string.lab_not_read), tone = inspection.alive?.let { tone(it) })

        header(R.string.lab_group_identity)
        item(R.string.lab_row_card_id, inspection.wireCardId ?: res.getString(R.string.lab_not_read), copyable = inspection.wireCardId != null)
        item(R.string.lab_row_account, inspection.accountUuid ?: res.getString(R.string.lab_not_read), copyable = inspection.accountUuid != null)
        personal(R.string.lab_row_holder, inspection.holderName) { v ->
            (v as? String)?.takeIf { it.isNotBlank() } ?: res.getString(R.string.lab_holder_blank)
        }
        item(R.string.lab_row_card_key, inspection.cardKeyFingerprint ?: res.getString(R.string.lab_not_read), copyable = inspection.cardKeyFingerprint != null)

        header(R.string.lab_group_personalization)
        item(R.string.lab_row_state, inspection.stateName ?: res.getString(R.string.lab_not_read), identifier = inspection.stateName != null)
        item(
            R.string.lab_row_flags,
            inspection.flagNames.takeIf { it.isNotEmpty() }?.joinToString(" · ") ?: res.getString(R.string.lab_none),
            identifier = inspection.flagNames.isNotEmpty()
        )
        item(R.string.lab_row_program, inspection.programIdHex ?: res.getString(R.string.lab_not_read), copyable = inspection.programIdHex != null)
        item(R.string.lab_row_currency, inspection.currency ?: res.getString(R.string.lab_not_read), identifier = inspection.currency != null)

        header(R.string.lab_group_certificate)
        item(R.string.lab_row_issuer_key, inspection.issuerKeyFingerprint ?: res.getString(R.string.lab_none), copyable = inspection.issuerKeyFingerprint != null)
        item(R.string.lab_row_cert_length, inspection.certificateLength?.let { res.getString(R.string.lab_bytes, it) } ?: res.getString(R.string.lab_none))
        item(R.string.lab_row_cert_id, inspection.certIdHex ?: res.getString(R.string.lab_none), copyable = inspection.certIdHex != null)
        item(
            R.string.lab_row_cert_verified,
            inspection.certVerifiedByCardIssuer?.let { res.getString(if (it) R.string.lab_cert_verified else R.string.lab_cert_not_verified) }
                ?: res.getString(R.string.lab_none),
            tone = inspection.certVerifiedByCardIssuer?.let { tone(it) }
        )

        header(R.string.lab_group_counters)
        item(R.string.lab_row_receive_counter, inspection.receiveCounter?.toString() ?: res.getString(R.string.lab_not_read))
        item(R.string.lab_row_receive_digest, inspection.receiveDigestHex ?: res.getString(R.string.lab_not_read), copyable = inspection.receiveDigestHex != null)

        header(R.string.lab_group_balance)
        personal(R.string.lab_row_balance, inspection.balanceMinor) { v ->
            amountText(res, v as Long, inspection.currency)
        }

        header(R.string.lab_group_last_transfer)
        personal(R.string.lab_row_last_transfer, inspection.lastTransfer) { v ->
            val last = v as? LastTransferSummary
            if (last == null) res.getString(R.string.lab_last_transfer_none)
            else res.getString(
                R.string.lab_last_transfer_value,
                amountText(res, last.amountMinor, last.currency), last.counter, last.sendSequence.toString(), last.recipientUuid
            )
        }

        header(R.string.lab_group_steps)
        val failed = inspection.steps.filter { !it.ok }
        item(R.string.lab_row_steps, res.getString(R.string.lab_steps_value, inspection.steps.count { it.ok }, inspection.steps.size),
            tone = if (failed.isEmpty()) CheckStatus.PASS else CheckStatus.WARN)
        for (s in failed) {
            rows.add(LabRow.Item(s.name, s.error?.let { errorText(res, it) } ?: res.getString(R.string.lab_failed), tone = CheckStatus.WARN))
        }
        return rows
    }

    private fun tone(ok: Boolean) = if (ok) CheckStatus.PASS else CheckStatus.FAIL

    /** Card minor-unit scale per currency, where the app knows it (XLM cards count stroops). */
    private val CARD_SCALES = mapOf("XLM" to 7)

    /** The card scale of [currency], or null when unknown (the amount is then shown in minor units only). */
    fun cardScale(currency: String?): Int? = currency?.trim()?.uppercase()?.let { CARD_SCALES[it] }

    /**
     * A card amount as the Inspector shows it: `0.0000000 XLM · 0 minor units`
     * when the currency's card scale is known ([Money.format], integer
     * arithmetic only), else `0 minor units USDC`.
     */
    fun amountText(res: Resources, minor: Long, currency: String?): String {
        val code = currency ?: ""
        val scale = cardScale(currency) ?: return res.getString(R.string.lab_minor_units, minor.toString(), code)
        return res.getString(R.string.lab_amount_with_minor, Money.format(minor, scale), code, minor.toString())
    }

    private fun transportRows(res: Resources, t: CardTransportFacts): List<LabRow> {
        val rows = ArrayList<LabRow>()
        fun item(id: Int, value: String?, copyable: Boolean = false) {
            if (value != null) rows.add(LabRow.Item(res.getString(id), value, copyable = copyable))
        }
        item(R.string.lab_row_iso, res.getString(if (t.iso14443Part4) R.string.lab_yes else R.string.lab_no))
        item(R.string.lab_row_uid, t.uidHex.ifEmpty { null }, copyable = true)
        item(R.string.lab_row_techs, t.techList.joinToString(", ").ifEmpty { null })
        item(R.string.lab_row_max_transceive, if (t.maxTransceiveLength > 0) res.getString(R.string.lab_bytes, t.maxTransceiveLength) else null)
        item(R.string.lab_row_extended_length, res.getString(if (t.extendedLengthSupported) R.string.lab_yes else R.string.lab_no))
        item(R.string.lab_row_timeout, if (t.timeoutMs > 0) res.getString(R.string.lab_ms, t.timeoutMs.toLong().toString()) else null)
        item(R.string.lab_row_historical, t.historicalBytesHex, copyable = true)
        item(R.string.lab_row_hi_layer, t.hiLayerResponseHex, copyable = true)
        fun hex(id: Int, value: String?) {
            if (value != null) rows.add(LabRow.Item(res.getString(id), value, identifier = true))
        }
        hex(R.string.lab_row_atqa, t.atqaHex)
        hex(R.string.lab_row_sak, t.sak?.let { "0x" + it.toString(16).uppercase().padStart(2, '0') })
        hex(R.string.lab_row_nfcb_app, t.nfcBApplicationDataHex)
        hex(R.string.lab_row_nfcb_protocol, t.nfcBProtocolInfoHex)
        return rows
    }

    /** A card error as the Lab shows it: the library's message plus the SW when there is one. */
    fun errorText(res: Resources, e: CardError): String {
        val base = when (e) {
            is CardError.WrongPin -> res.getString(CardErrorMessages.resId(e.userMessageKey), e.triesLeft)
            is CardError.WrongProtocolVersion -> res.getString(CardErrorMessages.resId(e.userMessageKey), e.found)
            is CardError.InvalidRequest -> res.getString(CardErrorMessages.resId(e.userMessageKey), e.reason)
            is CardError.ReadOnlyRefused -> res.getString(CardErrorMessages.resId(e.userMessageKey), e.command)
            else -> res.getString(CardErrorMessages.resId(e.userMessageKey))
        }
        val sw = e.statusWordHex
        return if (sw != null) "$base (SW $sw)" else base
    }

    /** The Doctor's one-line summary: `8 passed · 2 failed · 1 warning · 1 skipped` (the warning count is a plural). */
    fun doctorSummary(res: Resources, checks: List<DoctorCheck>): String {
        val warnings = checks.count { it.status == CheckStatus.WARN }
        return res.getString(
            R.string.lab_doctor_summary,
            checks.count { it.status == CheckStatus.PASS },
            checks.count { it.status == CheckStatus.FAIL },
            res.getQuantityString(R.plurals.lab_doctor_warnings, warnings, warnings),
            checks.count { it.status == CheckStatus.SKIP }
        )
    }

    /** The Device tab rows: build facts, the bridge probe, and (debug builds) the simulated card. */
    fun device(
        res: Resources,
        build: List<BuildInfo.Row>,
        probe: BridgeProbe.Result?,
        simulatorEndpoint: String?,
        simulator: SimulatorStatus?
    ): List<LabRow> {
        val rows = ArrayList<LabRow>()
        rows += LabRow.Header(res.getString(R.string.lab_group_bridge))
        rows += bridgeRows(res, probe)
        rows += LabRow.Header(res.getString(R.string.lab_group_build))
        // The bridge's Stellar network row already says "(this build: …)": no second network row.
        val bridgeNamesNetwork = probe?.stellarNetwork != null
        build.filterNot { bridgeNamesNetwork && it.labelRes == R.string.lab_build_network }
            .forEach { rows += LabRow.Item(res.getString(it.labelRes), it.value, copyable = it.copyable) }
        if (simulatorEndpoint != null) {
            rows += LabRow.Header(res.getString(R.string.lab_group_simulator))
            rows += LabRow.Item(res.getString(R.string.lab_row_endpoint), simulatorEndpoint, copyable = true)
            rows += LabRow.Item(
                res.getString(R.string.lab_row_sim_state),
                simulator?.let { res.getString(R.string.lab_sim_state_value, it.state.name, it.millis.toString()) }
                    ?: res.getString(R.string.lab_not_checked),
                tone = when (simulator?.state) {
                    SimulatorStatus.State.READY -> CheckStatus.PASS
                    SimulatorStatus.State.BUSY -> CheckStatus.WARN
                    SimulatorStatus.State.DOWN -> CheckStatus.FAIL
                    null -> null
                }
            )
        }
        return rows
    }

    private fun bridgeRows(res: Resources, probe: BridgeProbe.Result?): List<LabRow> {
        if (probe == null) return listOf(LabRow.Item(res.getString(R.string.lab_row_bridge_status), res.getString(R.string.lab_not_checked)))
        fun call(c: BridgeProbe.Call, okText: String?, healthy: Boolean = true): LabRow.Item = LabRow.Item(
            c.path,
            if (c.ok) res.getString(R.string.lab_probe_ok, okText ?: "OK", c.latencyMs.toString())
            else res.getString(R.string.lab_probe_failed, c.failure ?: "?", c.latencyMs.toString()),
            tone = if (c.ok && healthy) CheckStatus.PASS else if (c.ok || c.failure == "RATE_LIMITED") CheckStatus.WARN else CheckStatus.FAIL
        )
        val rows = ArrayList<LabRow>()
        // /health answers 200 with status "degraded" when the bridge's database or Redis is down.
        rows += call(probe.health, probe.healthStatus, healthy = probe.healthStatus == null || probe.healthStatus == "healthy")
        probe.stellarNetwork?.let {
            rows += LabRow.Item(
                res.getString(R.string.lab_row_bridge_network),
                res.getString(R.string.lab_network_value, it, probe.expectedNetwork),
                tone = if (probe.networkMismatch) CheckStatus.FAIL else CheckStatus.PASS
            )
        }
        rows += call(probe.version, probe.bridgeVersion)
        probe.schemaVersion?.let { rows += LabRow.Item(res.getString(R.string.lab_row_schema), it) }
        rows += call(
            probe.issuer,
            when (probe.issuerConfigured) {
                true -> res.getString(R.string.lab_issuer_configured)
                false -> res.getString(R.string.lab_issuer_unconfigured)
                null -> null
            }
        )
        probe.programIdHex?.let { rows += LabRow.Item(res.getString(R.string.lab_row_bridge_program), it, copyable = true) }
        // The bridge key's fingerprint in the Inspector's format (CardCertificates.fingerprint), so it can be
        // compared with a card's "Issuer key fingerprint" at a glance; the bridge's own (operator) fingerprint
        // is a different, domain-separated hash and keeps its own label.
        issuerKeyFingerprint(probe.issuerPublicKeyHex)?.let {
            rows += LabRow.Item(res.getString(R.string.lab_row_bridge_issuer_fp), it, copyable = true)
        }
        probe.issuerFingerprint?.let { rows += LabRow.Item(res.getString(R.string.lab_row_bridge_operator_fp), it, copyable = true) }
        return rows
    }

    /**
     * The fingerprint of an uncompressed P-256 public key given as hex, in the
     * same `ab:cd:…` form as the Inspector's key fingerprints, or null when
     * [publicKeyHex] is not a 65-byte uncompressed point.
     */
    fun issuerKeyFingerprint(publicKeyHex: String?): String? {
        val hex = publicKeyHex?.trim() ?: return null
        if (hex.length != UNCOMPRESSED_POINT_HEX || !hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return null
        val bytes = ByteArray(hex.length / 2) { i -> hex.substring(2 * i, 2 * i + 2).toInt(16).toByte() }
        if (bytes[0] != UNCOMPRESSED_POINT_TAG) return null
        return CardCertificates.fingerprint(bytes)
    }

    private const val UNCOMPRESSED_POINT_HEX = 130
    private const val UNCOMPRESSED_POINT_TAG: Byte = 0x04

    /** `GET_PERSONALIZATION  Lc 0 → 9000 OK  159 B  11 ms`: the header-only trace line. */
    fun exchangeLine(e: ApduExchange): String {
        val sw = e.swHex?.let { "$it ${e.swName ?: ""}".trim() } ?: e.outcome.name
        return "${e.insName}  Lc ${e.lc} → $sw  ${e.responseLength} B  ${e.elapsedMillis} ms"
    }

    /**
     * The shareable plain-text report. There is deliberately no parameter
     * that could include personal data: it renders identifiers, versions,
     * fingerprints, verdicts and header-only exchanges, nothing else.
     */
    fun export(
        res: Resources,
        build: List<BuildInfo.Row>,
        probe: BridgeProbe.Result?,
        inspection: CardInspection?,
        checks: List<DoctorCheck>,
        exchanges: List<ApduExchange>,
        nowEpochMs: Long = System.currentTimeMillis()
    ): String = buildString {
        appendLine("=== Impala Card Lab report ===")
        appendLine("Generated: ${AppLogger.iso(nowEpochMs)}")
        appendLine()
        appendLine("[Build]")
        build.forEach { appendLine("${res.getString(it.labelRes)}: ${it.value}") }
        appendLine()
        appendLine("[Bridge]")
        if (probe == null) {
            appendLine("not probed")
        } else {
            appendLine("Probed: ${AppLogger.iso(probe.atEpochMs)}")
            for (c in listOf(probe.health, probe.version, probe.issuer)) appendLine("${c.path}: ${c.failure ?: "OK"} ${c.latencyMs} ms")
            appendLine("status: ${probe.healthStatus ?: "?"}")
            appendLine("stellar_network: ${probe.stellarNetwork ?: "?"} (build: ${probe.expectedNetwork})${if (probe.networkMismatch) "  MISMATCH" else ""}")
            appendLine("version: ${probe.bridgeVersion ?: "?"} schema ${probe.schemaVersion ?: "?"}")
            appendLine("card-issuer configured: ${probe.issuerConfigured ?: "?"}")
            probe.programIdHex?.let { appendLine("program_id: $it") }
            issuerKeyFingerprint(probe.issuerPublicKeyHex)?.let { appendLine("issuer key fingerprint: $it") }
            probe.issuerFingerprint?.let { appendLine("operator fingerprint: $it") }
        }
        appendLine()
        appendLine("[Card]")
        if (inspection == null) {
            appendLine("no card read")
        } else {
            appendLine("Read: ${AppLogger.iso(inspection.readAtEpochMs)}")
            inspection.transport?.let { t ->
                appendLine("transport: ISO 14443-4 ${t.iso14443Part4}, techs ${t.techList.joinToString(",")}, max ${t.maxTransceiveLength} B, extended ${t.extendedLengthSupported}")
                appendLine("uid: ${t.uidHex}")
            } ?: appendLine("transport: simulated")
            appendLine("aid: ${inspection.aidHex ?: "default selection"}")
            appendLine("version: ${inspection.versionLine ?: "?"}")
            appendLine("alive: ${inspection.alive ?: "?"}")
            appendLine("card_id: ${inspection.wireCardId ?: "?"}")
            appendLine("account: ${inspection.accountUuid ?: "?"}")
            appendLine("card key fingerprint: ${inspection.cardKeyFingerprint ?: "?"}")
            appendLine("state: ${inspection.stateName ?: "?"}  flags: ${inspection.flagNames.joinToString("|")}")
            appendLine("program_id: ${inspection.programIdHex ?: "?"}  currency: ${inspection.currency ?: "?"}")
            appendLine("issuer key fingerprint: ${inspection.issuerKeyFingerprint ?: "none"}")
            appendLine("certificate: ${inspection.certificateLength?.let { "$it B" } ?: "none"}  cert_id: ${inspection.certIdHex ?: "none"}")
            appendLine("verified by card issuer: ${inspection.certVerifiedByCardIssuer ?: "n/a"}")
            appendLine("receive counter: ${inspection.receiveCounter ?: "?"}  digest: ${inspection.receiveDigestHex ?: "?"}")
            appendLine("holder name, balance, last transfer: not exported")
            for (s in inspection.steps) appendLine("step ${s.name}: ${if (s.ok) "OK" else "failed ${s.error?.userMessageKey ?: ""} ${s.error?.statusWordHex ?: ""}".trim()}")
        }
        appendLine()
        appendLine("[Doctor]")
        if (checks.isEmpty()) appendLine("not run")
        for (c in checks) {
            val detail = res.getString(c.detailRes, *c.detailArgs.toTypedArray())
            appendLine("${c.status.name.padEnd(4)}  ${res.getString(c.titleRes)}: $detail")
        }
        appendLine()
        appendLine("[Trace]")
        if (exchanges.isEmpty()) appendLine("no exchanges")
        exchanges.forEach { appendLine("#${it.sequence} ${exchangeLine(it)}") }
        if (exchanges.isNotEmpty()) {
            val s = ApduStats.of(exchanges)
            appendLine("${s.count} commands, ${s.totalNanos / 1_000_000L} ms, ${s.tagLosses} tag losses, ${s.refusals} refused, ${s.transportFailures} transport failures, ${s.cardErrors} card errors, ${s.expectedStatuses} expected not-found answers")
        }
    }
}
