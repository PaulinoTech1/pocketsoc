package org.atlasrf.collector

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.location.LocationManager
import android.net.wifi.WifiManager
import android.net.wifi.ScanResult
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.SystemClock

class WifiCollector(private val context: Context, private val session: RadioSession) {
    private val handler = Handler(Looper.getMainLooper())
    private val wifi = context.applicationContext.getSystemService(WifiManager::class.java)
    private var registered = false
    private var active = false
    private var received = false
    private val timeout = Runnable { if (!received) session.statuses["wifi"] = "timeout" }
    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context, intent: Intent) {
            if (!active || intent.action != WifiManager.SCAN_RESULTS_AVAILABLE_ACTION) return
            val updated = intent.getBooleanExtra(WifiManager.EXTRA_RESULTS_UPDATED, false)
            if (!updated) session.statuses["wifi"] = "cached_results_after_unsuccessful_scan"
            try {
                val results = wifi?.scanResults.orEmpty()
                if (updated) {
                    received = true
                    handler.removeCallbacks(timeout)
                    session.statuses["wifi"] = if (results.isEmpty()) "completed_empty" else "results_received"
                }
                // Timestamp deduplication, freshness and clock checks remain inside the session.
                for (result in results.take(RadioSession.MAX_EVENTS)) {
                    if (result.timestamp <= 0 || result.timestamp > Long.MAX_VALUE / 1000) {
                        session.drop("invalid_timestamp"); continue
                    }
                    @Suppress("DEPRECATION") val ssid = result.SSID
                    session.offer("wifi", result.BSSID, ssid, result.level, result.timestamp * 1000,
                        security(result.capabilities ?: ""), result.frequency,
                        ScanResult.convertFrequencyMhzToChannelIfSupported(result.frequency).takeIf { it > 0 },
                        if (updated) "fresh" else "cached")
                }
            } catch (_: SecurityException) { session.statuses["wifi"] = "permission_denied"; stop() }
        }
    }

    fun start() {
        if (!context.packageManager.hasSystemFeature(PackageManager.FEATURE_WIFI) || wifi == null) {
            session.statuses["wifi"] = "feature_absent"; return
        }
        if (context.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            session.statuses["wifi"] = "permission_denied"; return
        }
        if (!context.getSystemService(LocationManager::class.java).isLocationEnabled) {
            session.statuses["wifi"] = "location_disabled"; return
        }
        try {
            if (!wifi.isWifiEnabled) { session.statuses["wifi"] = "radio_disabled"; return }
            val filter = IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION)
            // A protected system broadcast; never use broadcast extras as observation payloads.
            if (Build.VERSION.SDK_INT >= 33) context.registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED)
            else { @Suppress("DEPRECATION") context.registerReceiver(receiver, filter) }
            registered = true
            active = true
            val preferences = context.getSharedPreferences("collector", Context.MODE_PRIVATE)
            val now = SystemClock.elapsedRealtime()
            val last = preferences.getLong("wifi_request_elapsed", -1)
            // Reject requests within 35s, including across activity/session recreation. A reboot permits a request.
            if (last >= 0 && now >= last && now - last < 35_000) {
                session.statuses["wifi_request"] = "rate_limited"
                session.statuses["wifi"] = "observing_system_scans"
            } else {
                preferences.edit().putLong("wifi_request_elapsed", now).apply()
                @Suppress("DEPRECATION") val accepted = wifi.startScan()
                session.statuses["wifi_request"] = if (accepted) "accepted" else "rejected_or_throttled"
                session.statuses["wifi"] = "waiting_for_fresh_results"
            }
            handler.postDelayed(timeout, 10_000)
        } catch (_: SecurityException) { session.statuses["wifi"] = "permission_denied"; stop() }
    }

    fun stop() {
        active = false
        handler.removeCallbacks(timeout)
        if (registered) { context.unregisterReceiver(receiver); registered = false }
    }

    private fun security(raw: String): String {
        val caps = raw.uppercase(java.util.Locale.ROOT)
        val labels = mutableListOf<String>()
        if (caps.contains("WEP")) labels.add("WEP")
        if (caps.contains("WPA2") || caps.contains("RSN")) labels.add("WPA2")
        if (caps.contains("WPA-")) labels.add("WPA")
        if (caps.contains("SAE") || caps.contains("SUITE_B_192")) labels.add("WPA3")
        if (caps.contains("OWE")) labels.add("OWE")
        // Empty/unknown capability strings are never interpreted as OPEN.
        if (labels.isEmpty()) return if (caps == "[ESS]") "OPEN" else "UNKNOWN"
        return labels.distinct().joinToString(" ")
    }
}
