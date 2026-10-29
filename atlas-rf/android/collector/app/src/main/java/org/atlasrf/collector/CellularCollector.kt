package org.atlasrf.collector

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.location.LocationManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.SystemClock
import android.telephony.*
import org.json.JSONArray
import org.json.JSONObject

/** Public APIs only, visible-session lifetime. No device/SIM identifiers or modem interfaces. */
class CellularCollector(private val context: Context, private val session: RadioSession) {
    private var running = false
    private val registrations = mutableListOf<Pair<TelephonyManager, TelephonyCallback>>()
    private val subscriptions = context.getSystemService(SubscriptionManager::class.java)
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private var subscriptionListener: SubscriptionManager.OnSubscriptionsChangedListener? = null
    private var networkListener: ConnectivityManager.NetworkCallback? = null
    private val activeSubscriptions = mutableSetOf<Int>()
    private var targets: List<Int?> = emptyList()
    private var bindingGeneration = 0
    private val cellularNetworks = mutableSetOf<Network>()
    private var cellularListener: ConnectivityManager.NetworkCallback? = null
    private var defaultNetwork: Network? = null

    private fun permitted(permission: String) = context.checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED
    private fun attempt(label: String, block: () -> Unit) {
        try { block() }
        catch (_: SecurityException) { session.statuses["cellular:$label"] = "permission_or_api_restricted" }
        catch (_: UnsupportedOperationException) { session.statuses["cellular:$label"] = "unsupported" }
        catch (_: IllegalStateException) { session.statuses["cellular:$label"] = "unavailable" }
        catch (_: IllegalArgumentException) { session.statuses["cellular:$label"] = "invalid_or_unavailable_subscription" }
    }

    private fun row(event: String, sub: Int? = null): JSONObject = JSONObject()
        .put("cellular_event", event).put("cell_freshness", "unknown")
        .also {
            if (sub != null) it.put("subscription_id", sub)
            else if (event in setOf("cell", "signal", "service", "technology"))
                it.put("subscription_scope", "default_radio")
        }

    private fun emit(value: JSONObject, measuredNanos: Long? = null) {
        if (running) session.offerCellular(value, measuredNanos)
    }

    fun start() {
        running = true
        monitorConnectivity()
        val pm = context.packageManager
        session.statuses["cellular:radio_feature"] = pm.hasSystemFeature("android.hardware.telephony.radio.access").toString()
        session.statuses["cellular:subscription_feature"] = pm.hasSystemFeature("android.hardware.telephony.subscription").toString()
        if (!pm.hasSystemFeature(PackageManager.FEATURE_TELEPHONY)) {
            session.statuses["cellular"] = "telephony_unsupported"; return
        }
        if (!permitted(Manifest.permission.READ_PHONE_STATE)) {
            session.statuses["cellular"] = "read_phone_state_required"; return
        }
        session.statuses["cellular"] = "listening_public_apis"
        attempt("subscriptions_listener") {
            val listener = object : SubscriptionManager.OnSubscriptionsChangedListener() {
                override fun onSubscriptionsChanged() { if (running) refreshSubscriptions() }
            }
            subscriptionListener = listener
            subscriptions?.addOnSubscriptionsChangedListener(context.mainExecutor, listener)
        }
        refreshSubscriptions()
    }

    private fun refreshSubscriptions() = attempt("subscriptions") {
        val infos = subscriptions?.activeSubscriptionInfoList.orEmpty().filter { it.subscriptionId >= 0 }
        session.statuses["cellular:subscription_limit"] = if (infos.size > 8) "truncated_to_8" else "within_limit"
        val selected = infos.take(8)
        val current = selected.map { it.subscriptionId }.toSet()
        (activeSubscriptions - current).forEach {
            emit(row("subscription", it).put("subscription_status", "inactive"))
        }
        // Rebind only when the set changes; no callback multiplication or periodic active scans.
        val nextTargets = CellularTargets.select(selected.map { it.subscriptionId })
        if (nextTargets == targets) return@attempt
        bindingGeneration += 1
        val generation = bindingGeneration
        targets = nextTargets
        registrations.forEach { (tm, cb) -> attempt("unregister") { tm.unregisterTelephonyCallback(cb) } }
        registrations.clear()
        activeSubscriptions.clear(); activeSubscriptions.addAll(current)
        session.statuses["cellular:active_subscriptions"] = current.size.toString()
        session.statuses["cellular:subscriptions"] = if (current.isEmpty()) "none_active_not_a_software_failure" else "active_list_available"
        if (current.isEmpty()) session.statuses["cellular:default_radio"] = "attempting_public_apis_measurements_not_guaranteed"
        else session.statuses.remove("cellular:default_radio")
        targets.forEach { sub ->
            val info = selected.firstOrNull { it.subscriptionId == sub }
            val base = context.getSystemService(TelephonyManager::class.java)
            if (base == null) { session.statuses["cellular"] = "telephony_service_absent"; return@forEach }
            val tm = if (sub == null) base else base.createForSubscriptionId(sub)
            if (info != null) {
                val value = row("subscription", sub).put("subscription_status", "active")
                if (info.simSlotIndex in 0..7) value.put("slot_index", info.simSlotIndex)
                val carrier = info.carrierName?.toString().orEmpty()
                if (carrier.isNotBlank()) value.put("carrier", carrier.take(256))
                attempt("sim_state:$sub") { if (tm.simState in 0..11) value.put("sim_state", tm.simState) }
                emit(value)
            }
            // Late callbacks from a previous binding must not acquire a new attribution.
            fun emitCurrent(value: JSONObject) {
                if (generation == bindingGeneration) emit(value)
            }
            val basic = object : TelephonyCallback(), TelephonyCallback.ServiceStateListener,
                TelephonyCallback.SignalStrengthsListener, TelephonyCallback.DataConnectionStateListener,
                TelephonyCallback.DisplayInfoListener {
                override fun onServiceStateChanged(state: ServiceState) {
                    emitCurrent(row("service", sub).put("service_state", state.state).put("roaming", state.roaming))
                }
                override fun onSignalStrengthsChanged(strength: SignalStrength) {
                    strength.cellSignalStrengths.take(16).forEach { signal ->
                        signalRow(signal, row("signal", sub))?.let { emitCurrent(it) }
                    }
                }
                override fun onDataConnectionStateChanged(state: Int, networkType: Int) {
                    val o = row("technology", sub)
                    if (state in -1..5) o.put("data_state", state)
                    if (networkType in 0..20) o.put("network_type", networkType)
                    emitCurrent(o)
                }
                override fun onDisplayInfoChanged(info: TelephonyDisplayInfo) {
                    val o = row("technology", sub)
                    if (info.networkType in 0..20) o.put("network_type", info.networkType)
                    if (info.overrideNetworkType in 0..10) o.put("display_override", info.overrideNetworkType)
                    emitCurrent(o) // Display override is not a measured NR serving cell.
                }
            }
            attempt("state_callback:$sub") {
                tm.registerTelephonyCallback(context.mainExecutor, basic); registrations.add(tm to basic)
            }
            val location = (context.getSystemService(LocationManager::class.java)?.isLocationEnabled == true)
            if (!permitted(Manifest.permission.ACCESS_FINE_LOCATION) || !location) {
                session.statuses["cellular:cells:$sub"] = "precise_location_permission_and_location_switch_required"
            } else {
                val cellCallback = object : TelephonyCallback(), TelephonyCallback.CellInfoListener {
                    override fun onCellInfoChanged(cellInfo: MutableList<CellInfo>) { cells(sub, cellInfo, "callback", generation) }
                }
                attempt("cell_callback:$sub") {
                    tm.registerTelephonyCallback(context.mainExecutor, cellCallback); registrations.add(tm to cellCallback)
                }
                attempt("cached_cells:$sub") { cells(sub, tm.allCellInfo.orEmpty(), "cached_read", generation) }
                attempt("request_cells:$sub") {
                    session.statuses["cellular:update:$sub"] = "requested_not_guaranteed"
                    tm.requestCellInfoUpdate(context.mainExecutor, object : TelephonyManager.CellInfoCallback() {
                        override fun onCellInfo(cellInfo: MutableList<CellInfo>) {
                            if (running && generation == bindingGeneration) {
                                session.statuses["cellular:update:$sub"] = "returned_${cellInfo.size}_cells"
                                cells(sub, cellInfo, "update", generation)
                            }
                        }
                        override fun onError(errorCode: Int, detail: Throwable?) {
                            if (running && generation == bindingGeneration) session.statuses["cellular:update:$sub"] = "api_error_$errorCode"
                        }
                    })
                }
            }
        }
    }

    private fun number(o: JSONObject, key: String, value: Int, range: IntRange) {
        if (value != CellInfo.UNAVAILABLE && value in range) o.put(key, value)
    }
    private fun signalRow(signal: CellSignalStrength, o: JSONObject): JSONObject? {
        when (signal) {
            is CellSignalStrengthLte -> {
                o.put("technology", "LTE")
                number(o, "lte_rsrp", signal.rsrp, -140..-43)
                number(o, "lte_rsrq", signal.rsrq, -34..3)
                number(o, "lte_rssi", signal.rssi, -113..-51)
                number(o, "lte_rssnr", signal.rssnr, -20..30) // Public API dB, not raw RIL tenths.
            }
            is CellSignalStrengthNr -> {
                o.put("technology", "NR")
                number(o, "nr_ss_rsrp", signal.ssRsrp, -156..-31)
                number(o, "nr_ss_rsrq", signal.ssRsrq, -43..20)
                number(o, "nr_ss_sinr", signal.ssSinr, -23..40)
            }
            else -> return null
        }
        return o
    }

    private fun cells(sub: Int?, infos: List<CellInfo>, origin: String, generation: Int) {
        if (!running || generation != bindingGeneration || sub !in targets) return
        if (infos.size > 256) session.statuses["cellular:cells:$sub"] = "truncated_to_256"
        if (infos.isEmpty()) session.statuses["cellular:cells:$sub"] = "empty_not_evidence_of_no_cells"
        infos.take(256).forEach { info ->
            val o = row("cell", sub).put("registered", info.isRegistered).put("cell_origin", origin)
            o.put("connection_status", when (info.cellConnectionStatus) {
                CellInfo.CONNECTION_PRIMARY_SERVING -> "primary"
                CellInfo.CONNECTION_SECONDARY_SERVING -> "secondary"
                CellInfo.CONNECTION_NONE -> "none"
                else -> "unknown"
            })
            val measuredMs = info.timestampMillis
            val nowMs = SystemClock.elapsedRealtime()
            val knownTime = measuredMs > 0 && measuredMs <= nowMs && measuredMs < Long.MAX_VALUE / 1_000_000
            if (knownTime) {
                val age = nowMs - measuredMs
                o.put("measurement_elapsed_ms", measuredMs).put("cell_age_ms", age)
                o.put("cell_freshness", if (origin == "cached_read" || age > 10_000) "cached" else "recent")
            }
            when (info) {
                is CellInfoLte -> {
                    val ci = info.cellIdentity
                    number(o, "cell_id", ci.ci, 0..268435455)
                    number(o, "pci", ci.pci, 0..503); number(o, "tac", ci.tac, 0..65535)
                    number(o, "arfcn", ci.earfcn, 0..262143)
                    identity(o, ci.mccString, ci.mncString, ci.bands)
                    signalRow(info.cellSignalStrength, o)
                }
                is CellInfoNr -> {
                    val ci = info.cellIdentity as CellIdentityNr
                    if (ci.nci != CellInfo.UNAVAILABLE_LONG && ci.nci in 0L..68719476735L) o.put("cell_id", ci.nci)
                    number(o, "pci", ci.pci, 0..1007); number(o, "tac", ci.tac, 0..16777215)
                    number(o, "arfcn", ci.nrarfcn, 0..3279165)
                    identity(o, ci.mccString, ci.mncString, ci.bands)
                    signalRow(info.cellSignalStrength, o)
                }
                else -> { session.statuses["cellular:other_rat"] = "not_collected"; return@forEach }
            }
            emit(o, if (knownTime) measuredMs * 1_000_000 else null)
        }
    }

    private fun identity(o: JSONObject, mcc: String?, mnc: String?, bands: IntArray) {
        if (mcc?.matches(Regex("[0-9]{3}")) == true) o.put("mcc", mcc)
        if (mnc?.matches(Regex("[0-9]{2,3}")) == true) o.put("mnc", mnc)
        val valid = bands.filter { it in 1..1024 }.distinct().take(64)
        if (valid.isNotEmpty()) o.put("bands", JSONArray(valid))
    }

    private fun monitorConnectivity() {
        val connectivity = connectivity ?: run { session.statuses["cellular:connectivity"] = "service_absent"; return }
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) { defaultNetwork = network }
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                defaultNetwork = network
                emit(row("connectivity").put("default_transport", when {
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "vpn"
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
                    else -> "other"
                }).put("network_validated", caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)))
            }
            override fun onLost(network: Network) {
                if (network == defaultNetwork) {
                    defaultNetwork = null
                    emit(row("connectivity").put("default_transport", "none").put("network_validated", false))
                }
            }
        }
        attempt("default_connectivity") {
            connectivity.registerDefaultNetworkCallback(callback, android.os.Handler(context.mainLooper))
            networkListener = callback
        }
        val cellCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                cellularNetworks.add(network)
                emit(row("connectivity").put("cellular_available", true))
            }
            override fun onLost(network: Network) {
                cellularNetworks.remove(network)
                emit(row("connectivity").put("cellular_available", cellularNetworks.isNotEmpty()))
            }
        }
        attempt("cellular_connectivity") {
            val request = NetworkRequest.Builder().addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).build()
            connectivity.registerNetworkCallback(request, cellCallback, android.os.Handler(context.mainLooper))
            cellularListener = cellCallback
        }
    }

    fun stop() {
        running = false
        bindingGeneration += 1
        targets = emptyList()
        registrations.forEach { (tm, cb) -> attempt("unregister") { tm.unregisterTelephonyCallback(cb) } }
        registrations.clear()
        subscriptionListener?.let { attempt("subscriptions_stop") { subscriptions?.removeOnSubscriptionsChangedListener(it) } }
        networkListener?.let { attempt("connectivity_stop") { connectivity?.unregisterNetworkCallback(it) } }
        cellularListener?.let { attempt("cellular_connectivity_stop") { connectivity?.unregisterNetworkCallback(it) } }
        subscriptionListener = null; networkListener = null; cellularListener = null
    }
}
