package com.payala.impala.demo.ui.lab

import android.app.Application
import android.os.Handler
import android.os.Looper
import androidx.annotation.VisibleForTesting
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.viewModelScope
import com.impala.sdk.apdu4j.ApduExchange
import com.impala.sdk.apdu4j.ApduExchangeHook
import com.impala.sdk.flows.CardError
import com.impala.sdk.flows.CardFlowException
import com.payala.impala.card.CardInspection
import com.payala.impala.card.CardInspector
import com.payala.impala.demo.BuildConfig
import com.payala.impala.demo.ImpalaApp
import com.payala.impala.demo.api.ApiClient
import com.payala.impala.demo.api.BridgeApiService
import com.payala.impala.demo.card.CardStore
import com.payala.impala.demo.card.DebugCards
import com.payala.impala.demo.card.SimulatorStatus
import com.payala.impala.demo.log.AppLogger
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import retrofit2.HttpException
import java.io.IOException

/**
 * The outcome of one Lab read: the inspection, or why there is none, plus the
 * header-only exchanges the read sent (SELECT included).
 *
 * @property failureText a non-card failure already worded for the user (the simulated card was unreachable)
 */
class LabRead(
    val inspection: CardInspection?,
    val error: CardError?,
    val failureText: String?,
    val exchanges: List<ApduExchange>,
    val simulated: Boolean,
    val atEpochMs: Long
) {
    override fun toString(): String = "LabRead(simulated=$simulated, ok=${inspection != null}, ${exchanges.size} exchanges)"
}

/**
 * The Card Lab's state, kept across rotation and never persisted: the last
 * read, the Doctor's verdicts, the bridge probe and the simulator probe.
 *
 * Card reads happen in the tap (binder thread) or on IO for the simulated
 * card; every session is read-only. Bridge calls run afterwards, in
 * [viewModelScope], never while a card is in the field. The bridge probe is
 * unauthenticated; the only authenticated call is the owner's
 * `GET /offline/cards/{id}`, and only while a session exists.
 */
class LabViewModel(app: Application) : AndroidViewModel(app) {

    enum class Phase { IDLE, READING, DONE, FAILED }

    private val _phase = MutableLiveData(Phase.IDLE)
    val phase: LiveData<Phase> = _phase

    private val _read = MutableLiveData<LabRead?>(null)
    val read: LiveData<LabRead?> = _read

    private val _checks = MutableLiveData<List<DoctorCheck>>(emptyList())
    val checks: LiveData<List<DoctorCheck>> = _checks

    private val _probe = MutableLiveData<BridgeProbe.Result?>(null)
    val probe: LiveData<BridgeProbe.Result?> = _probe

    private val _probing = MutableLiveData(false)
    val probing: LiveData<Boolean> = _probing

    private val _simulator = MutableLiveData<SimulatorStatus?>(null)
    val simulator: LiveData<SimulatorStatus?> = _simulator

    /** The signed-in account (null pre-login), as the activity read it from the session store. */
    var sessionAccountId: String? = null
        private set

    /** The card the Lab was opened for, if any (from Cards → Inspect in Card Lab). */
    var expectedCardId: String? = null
        private set

    var reader: ReaderState = ReaderState.NFC_ABSENT
        private set

    private val bridgeProbe: BridgeProbe by lazy {
        BridgeProbe(BuildConfig.BRIDGE_BASE_URL, BuildConfig.STELLAR_NETWORK, probeClient ?: BridgeProbe.defaultClient())
    }

    // ---- the current read's trace ----

    private val traceLock = Any()
    private var currentExchanges = ArrayList<ApduExchange>()

    /** Bumped by every new read and every delivered result, so a late "Reading" never overwrites a result. */
    private var readGeneration = 0L
    private val mainHandler by lazy { Handler(Looper.getMainLooper()) }

    /**
     * Receives every exchange of the Lab's own sessions, on the I/O thread;
     * it only appends under a lock and posts the Reading phase.
     */
    val traceHook = ApduExchangeHook { e ->
        val first: Boolean
        val generation: Long
        synchronized(traceLock) {
            first = currentExchanges.isEmpty()
            if (currentExchanges.size < MAX_EXCHANGES) currentExchanges.add(e)
            generation = readGeneration
        }
        if (first) postReading(generation)
    }

    /** A new read starts (any thread): its exchanges replace the previous read's. */
    fun beginRead() {
        val generation = synchronized(traceLock) {
            currentExchanges = ArrayList()
            ++readGeneration
        }
        postReading(generation)
    }

    private fun postReading(generation: Long) {
        mainHandler.post {
            val current = synchronized(traceLock) { readGeneration }
            if (current == generation) _phase.value = Phase.READING
        }
    }

    /** The finished read's exchanges; also retires its pending "Reading" posts. */
    private fun takeExchanges(): List<ApduExchange> = synchronized(traceLock) {
        readGeneration++
        currentExchanges.toList()
    }

    // ---- inputs from the activity ----

    fun setSession(accountId: String?) {
        if (accountId == sessionAccountId) return
        sessionAccountId = accountId
        if (_read.value != null) diagnose()
    }

    fun setExpectedCard(cardId: String?) {
        if (cardId == expectedCardId) return
        expectedCardId = cardId
        diagnose()
    }

    fun setReader(state: ReaderState) {
        if (state == reader && _checks.value.orEmpty().isNotEmpty()) return
        reader = state
        diagnose()
    }

    // ---- reads ----

    /** Main thread: the reader-mode tap's result (the session was read-only; see the activity's factory). */
    fun onTapResult(result: Result<CardInspection>) = deliver(result, simulated = false)

    /** Reads the simulated card (debug builds only) over a read-only session, on IO. */
    fun readSimulated() {
        if (_phase.value == Phase.READING) return
        _phase.value = Phase.READING
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                beginRead()
                try {
                    val inspection = DebugCards.openSession(traceHook, readOnly = true)?.use { CardInspector.inspect(it) }
                    if (inspection != null) Result.success(inspection) else Result.failure(IllegalStateException(NOT_CONFIGURED))
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Result.failure(e)
                }
            }
            deliver(result, simulated = true)
        }
    }

    private fun deliver(result: Result<CardInspection>, simulated: Boolean) {
        val exchanges = takeExchanges()
        val read = result.fold(
            onSuccess = { LabRead(it, null, null, exchanges, simulated, System.currentTimeMillis()) },
            onFailure = { e ->
                val text = DebugCards.describeFailure(e)
                    ?: if (e is IllegalStateException && e.message == NOT_CONFIGURED) NOT_CONFIGURED else null
                val error = if (text != null) null else (e as? CardFlowException)?.error ?: CardError.from(e)
                LabRead(null, error, text, exchanges, simulated, System.currentTimeMillis())
            }
        )
        val outcome = if (read.inspection != null) "complete" else "failed"
        val commands = exchanges.size
        val cardId = read.inspection?.wireCardId ?: "?"
        AppLogger.i(TAG, "Lab read $outcome: $commands commands, card $cardId")
        _read.value = read
        _phase.value = if (read.inspection != null) Phase.DONE else Phase.FAILED
        diagnose()
    }

    // ---- doctor ----

    /** Re-runs the Doctor: card facts at once, then again with what the bridge says. */
    fun diagnose() {
        val read = _read.value
        val base = DoctorInput(
            reader = if (read?.simulated == true) ReaderState.SIMULATED else reader,
            inspection = read?.inspection,
            readError = read?.error,
            readFailed = read != null && read.inspection == null && read.error == null,
            simulated = read?.simulated == true,
            exchanges = read?.exchanges.orEmpty(),
            issuer = _probe.value?.issuerFacts ?: IssuerFacts.NotChecked,
            bridgeCard = if (sessionAccountId == null) BridgeCardFacts.NoSession else BridgeCardFacts.NotChecked,
            sessionAccountId = sessionAccountId,
            localRecord = null,
            expectedCardId = expectedCardId
        )
        _checks.value = CardDoctor.run(base)
        val inspection = read?.inspection ?: return
        val account = sessionAccountId
        viewModelScope.launch {
            val probeResult = freshProbe()
            val cardId = inspection.wireCardId
            val (bridgeCard, local) = withContext(Dispatchers.IO) {
                if (account == null || cardId == null) {
                    BridgeCardFacts.NoSession to null
                } else {
                    fetchBridgeCard(cardId) to (CardStore(getApplication<Application>()).find(account, cardId) != null)
                }
            }
            // A newer read (or session change) replaced this one meanwhile: its own diagnose() reports.
            if (_read.value !== read || sessionAccountId != account) return@launch
            _checks.value = CardDoctor.run(
                DoctorInput(
                    reader = base.reader, inspection = inspection, readError = null, readFailed = false,
                    simulated = base.simulated, exchanges = base.exchanges,
                    issuer = probeResult?.issuerFacts ?: base.issuer,
                    bridgeCard = bridgeCard, sessionAccountId = account, localRecord = local,
                    expectedCardId = expectedCardId
                )
            )
        }
    }

    private suspend fun freshProbe(): BridgeProbe.Result? {
        val last = _probe.value
        if (last != null && System.currentTimeMillis() - last.atEpochMs < PROBE_REUSE_MS) return last
        return runProbe() ?: last
    }

    private suspend fun fetchBridgeCard(cardId: String): BridgeCardFacts {
        val api = apiOverride ?: (getApplication<Application>() as? ImpalaApp)?.let {
            ApiClient.getService(BuildConfig.BRIDGE_BASE_URL, it.tokenManager)
        } ?: return BridgeCardFacts.NoSession
        return try {
            BridgeCardFacts.Found(api.offlineCard(cardId).certified)
        } catch (e: HttpException) {
            BridgeCardFacts.Http(e.code())
        } catch (e: IOException) {
            BridgeCardFacts.Network(BridgeProbe.classify(e))
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            BridgeCardFacts.Network(e.javaClass.simpleName)
        }
    }

    // ---- probes ----

    /** Milliseconds until the bridge may be probed again. */
    fun probeCooldownMs(): Long = bridgeProbe.cooldownRemainingMs()

    /** Probes the bridge (unauthenticated). False when the 10 s cooldown is still running. */
    fun probeBridge(): Boolean {
        if (_probing.value == true || bridgeProbe.cooldownRemainingMs() > 0) return false
        viewModelScope.launch {
            runProbe()
            if (_read.value?.inspection != null) diagnose()
            else _checks.value = CardDoctor.run(DoctorInput(reader = reader, issuer = _probe.value?.issuerFacts ?: IssuerFacts.NotChecked, expectedCardId = expectedCardId))
        }
        return true
    }

    private suspend fun runProbe(): BridgeProbe.Result? {
        _probing.value = true
        val result = withContext(Dispatchers.IO) { bridgeProbe.tryRun() }
        _probing.value = false
        if (result != null) {
            _probe.value = result
            AppLogger.i(TAG, "Bridge probe: health ${result.health.failure ?: result.healthStatus ?: "OK"}, network ${result.stellarNetwork ?: "?"}")
            if (result.networkMismatch) {
                AppLogger.w(TAG, "Stellar network mismatch: bridge ${result.stellarNetwork}, build ${result.expectedNetwork}")
            }
        }
        return result
    }

    /** Probes the simulated card with one NOP (debug builds; a no-op in release). */
    fun probeSimulator() {
        if (!DebugCards.isConfigured()) return
        viewModelScope.launch {
            _simulator.value = withContext(Dispatchers.IO) { DebugCards.probe() }
        }
    }

    companion object {
        private const val TAG = "CardLab"
        private const val MAX_EXCHANGES = 256

        /** A probe this recent is reused by the Doctor instead of asking again. */
        private const val PROBE_REUSE_MS = 60_000L

        internal const val NOT_CONFIGURED = "No simulated card is configured."

        /** Tests: the probe's HTTP client (a canned-response interceptor). */
        @VisibleForTesting
        @Volatile
        internal var probeClient: OkHttpClient? = null

        /** Tests: the owner API for `GET /offline/cards/{id}`. */
        @VisibleForTesting
        @Volatile
        internal var apiOverride: BridgeApiService? = null
    }
}
