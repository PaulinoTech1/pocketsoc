package org.atlasrf.collector

import android.content.Context
import android.net.*
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import org.json.JSONObject
import java.net.URL
import java.time.Instant
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.HttpsURLConnection

/** One opt-in HTTPS GET per transport, serial, max 64 KiB each. Never bind the process. */
class BoundedNetworkTest(private val context: Context, private val session: RadioSession,
                         private val request: JSONObject, private val finished: () -> Unit) {
    companion object {
        fun validate(text: String): JSONObject {
            val value = JSONObject(text)
            check(value.getString("kind") == "atlas-cellular-performance-request" && value.getInt("schema_version") == 1)
            check(value.getBoolean("authorized") && value.getInt("max_bytes") == 65536 && value.getInt("timeout_ms") == 5000)
            UUID.fromString(value.getString("test_id"))
            check(Instant.parse(value.getString("created_at")) <= Instant.now().plusSeconds(300))
            check(Instant.parse(value.getString("expires_at")) > Instant.now())
            check(Instant.parse(value.getString("expires_at")) <= Instant.now().plusSeconds(900))
            val uri = Uri.parse(value.getString("endpoint"))
            check(value.getString("endpoint").length <= 256 && uri.scheme == "https" && !uri.host.isNullOrBlank())
            check(uri.userInfo == null && uri.query == null && uri.fragment == null)
            return value
        }
    }
    private val cm = requireNotNull(context.getSystemService(ConnectivityManager::class.java))
    private val handler = Handler(Looper.getMainLooper())
    private val worker = Executors.newSingleThreadExecutor()
    @Volatile private var stopped = false
    @Volatile private var connection: HttpsURLConnection? = null
    private var pending: ConnectivityManager.NetworkCallback? = null
    private var timeout: Runnable? = null
    private var phase = 0

    fun start() { next() }
    private fun next() {
        if (stopped) return
        if (phase >= 2) { stopped = true; worker.shutdown(); finished(); return }
        val transport = if (phase++ == 0) "wifi" else "cellular"
        val transportType = if (transport == "wifi") NetworkCapabilities.TRANSPORT_WIFI else NetworkCapabilities.TRANSPORT_CELLULAR
        val claimed = AtomicBoolean(false)
        lateinit var callback: ConnectivityManager.NetworkCallback
        fun release() {
            timeout?.let { handler.removeCallbacks(it) }; timeout = null
            if (pending === callback) pending = null
            try { cm.unregisterNetworkCallback(callback) } catch (_: IllegalArgumentException) { }
        }
        callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                if (stopped || !claimed.compareAndSet(false, true)) return
                timeout?.let { handler.removeCallbacks(it) }; timeout = null
                val caps = cm.getNetworkCapabilities(network)
                if (caps == null || !caps.hasTransport(transportType) || caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                    record(transport, "unavailable", false, failure = "transport_not_verified")
                    release(); next(); return
                }
                worker.execute {
                    runTest(network, transport)
                    handler.post { release(); next() }
                }
            }
            override fun onUnavailable() {
                if (!stopped && claimed.compareAndSet(false, true)) {
                    record(transport, "unavailable", false, failure = "network_unavailable")
                    release(); next()
                }
            }
        }
        pending = callback
        timeout = Runnable {
            if (!stopped && claimed.compareAndSet(false, true)) {
                record(transport, "unavailable", false, failure = "network_timeout")
                release(); next()
            }
        }.also { handler.postDelayed(it, 4000) }
        try {
            val networkRequest = NetworkRequest.Builder().addTransportType(transportType)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build()
            cm.requestNetwork(networkRequest, callback, handler, 4000)
        } catch (_: SecurityException) {
            if (claimed.compareAndSet(false, true)) {
                record(transport, "unavailable", false, failure = "permission_or_policy_denied")
                release(); next()
            }
        } catch (_: RuntimeException) {
            if (claimed.compareAndSet(false, true)) {
                record(transport, "unavailable", false, failure = "request_unsupported")
                release(); next()
            }
        }
    }

    private fun runTest(network: Network, transport: String) {
        if (stopped) return
        val started = SystemClock.elapsedRealtime()
        var bytes = 0
        var code: Int? = null
        var bound = false
        try {
            val conn = network.openConnection(URL(request.getString("endpoint"))) as HttpsURLConnection
            connection = conn; bound = true
            conn.connectTimeout = 5000; conn.readTimeout = 5000
            conn.instanceFollowRedirects = false; conn.useCaches = false
            conn.setRequestProperty("Accept-Encoding", "identity")
            conn.setRequestProperty("Range", "bytes=0-65535")
            val deadline = Runnable { conn.disconnect() }
            handler.postDelayed(deadline, 5000)
            try {
                val responseCode = conn.responseCode
                code = responseCode
                check(responseCode in 200..299)
                conn.inputStream.use { input ->
                    val buffer = ByteArray(4096)
                    while (!stopped && bytes < 65536 && SystemClock.elapsedRealtime() - started < 5000) {
                        val count = input.read(buffer, 0, minOf(buffer.size, 65536 - bytes))
                        if (count < 0) break
                        bytes += count
                    }
                }
                check(!stopped && SystemClock.elapsedRealtime() - started < 5000)
                val finalCaps = cm.getNetworkCapabilities(network)
                val expected = if (transport == "wifi") NetworkCapabilities.TRANSPORT_WIFI else NetworkCapabilities.TRANSPORT_CELLULAR
                check(finalCaps != null && finalCaps.hasTransport(expected) && !finalCaps.hasTransport(NetworkCapabilities.TRANSPORT_VPN))
                record(transport, "success", true, SystemClock.elapsedRealtime() - started, bytes, code)
            } finally { handler.removeCallbacks(deadline); conn.disconnect() }
        } catch (_: Exception) {
            if (!stopped) record(transport, "failed", bound, SystemClock.elapsedRealtime() - started, bytes, code, "https_or_network_failure")
        } finally { connection = null }
    }

    private fun record(transport: String, status: String, bound: Boolean, duration: Long? = null,
                       bytes: Int? = null, code: Int? = null, failure: String? = null) {
        if (stopped) return
        val o = JSONObject().put("cellular_event", "performance").put("cell_freshness", "unknown")
            .put("test_id", request.getString("test_id")).put("test_endpoint", request.getString("endpoint"))
            .put("test_transport", transport).put("test_status", status).put("bound_network", bound).put("authorized", true)
        duration?.let { o.put("duration_ms", it.coerceIn(0L, 60000L)) }
        bytes?.let { o.put("bytes_received", it) }
        code?.let { if (it in 100..599) o.put("http_status", it) }
        failure?.let { o.put("test_failure", it) }
        session.offerCellular(o)
    }

    fun cancel() {
        stopped = true
        timeout?.let { handler.removeCallbacks(it) }; timeout = null
        pending?.let { try { cm.unregisterNetworkCallback(it) } catch (_: IllegalArgumentException) { } }; pending = null
        connection?.disconnect(); worker.shutdownNow()
    }
}
