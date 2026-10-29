package org.atlasrf.collector

import android.os.SystemClock
import org.json.JSONObject
import org.json.JSONArray
import java.io.File
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/** One bounded queue, one writer. Callback threads never perform disk I/O or blocking puts. */
class RadioSession(root: File, val sensorId: String, private val bridgeKey: ByteArray? = null,
                   private val bridgeNonce: String? = null) {
    companion object {
        const val MAX_EVENTS = 10_000
        const val MAX_BYTES = 8 * 1024 * 1024
        const val QUEUE_SIZE = 256
    }
    val id: String = UUID.randomUUID().toString()
    private val directory = File(root, id)
    val clock = ObservationClock(System.currentTimeMillis(), SystemClock.elapsedRealtimeNanos())
    val statuses = ConcurrentHashMap<String, String>()
    private val drops = ConcurrentHashMap<String, AtomicInteger>()
    private val queue = ArrayBlockingQueue<String>(QUEUE_SIZE)
    private val lastSeen = LinkedHashMap<String, Long>()
    private val accepted = AtomicInteger()
    val written = AtomicInteger()
    private val payloadFile = File(directory, "session.jsonl")
    @Volatile private var accepting = true
    @Volatile private var stopping = false
    @Volatile private var writerFailed = false
    private val writer: Thread

    init {
        directory.mkdirs()
        // Single foreground activity/session: bound both incomplete and completed leftovers.
        // Cleanup runs on session creation; exported documents are outside private cache.
        root.listFiles()?.filter { it != directory }?.sortedByDescending { it.lastModified() }
            ?.forEachIndexed { index, file ->
                if (index >= 2 || System.currentTimeMillis() - file.lastModified() > 86_400_000) file.deleteRecursively()
            }
        // A single explicit new session replaces the previous finalized private spool.
        File(directory, "session.atlas.json").delete()
        writer = Thread({
            try {
                payloadFile.outputStream().buffered().use { output ->
                    var bytes = 0
                    while (!stopping || queue.isNotEmpty()) {
                        val line = queue.poll(200, java.util.concurrent.TimeUnit.MILLISECONDS) ?: continue
                        val encoded = (line + "\n").toByteArray(Charsets.UTF_8)
                        if (bytes + encoded.size > MAX_BYTES) {
                            accepting = false
                            statuses["session"] = "limit_reached"
                            drop("spool_full")
                            continue
                        }
                        output.write(encoded)
                        bytes += encoded.size
                        written.incrementAndGet()
                    }
                }
            } catch (_: Exception) {
                writerFailed = true
                accepting = false
                statuses["session"] = "storage_failed"
            }
        }, "atlas-spool").apply { start() }
    }

    fun drop(reason: String) { drops.computeIfAbsent(reason) { AtomicInteger() }.incrementAndGet() }

    @Synchronized
    fun offer(kind: String, address: String?, name: String?, rssi: Int, measuredNanos: Long, security: String? = null,
              frequencyMhz: Int? = null, channel: Int? = null, scanFreshness: String = "unknown",
              bleMetadata: JSONObject? = null) {
        if (!accepting) return
        val identity = address?.lowercase(java.util.Locale.ROOT)
        if (identity == null || !identity.matches(Regex("([0-9a-f]{2}:){5}[0-9a-f]{2}")) ||
            identity in setOf("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "02:00:00:00:00:00") ||
            (identity.substring(0, 2).toInt(16) and 1) != 0) {
            drop("invalid_identity"); return
        }
        val elapsed = SystemClock.elapsedRealtimeNanos()
        val utc = clock.utc(measuredNanos, elapsed, System.currentTimeMillis())
        if (utc == null) {
            if (kotlin.math.abs(System.currentTimeMillis() - (clock.wallMillis + (elapsed - clock.elapsedNanos) / 1_000_000)) > 5000) {
                statuses["session"] = "clock_changed"
                accepting = false
            }
            drop("invalid_timestamp"); return
        }
        val maxAge = if (kind == "wifi") 30_000_000_000L else 10_000_000_000L
        if (kind != "wifi" && (measuredNanos < clock.elapsedNanos || elapsed - measuredNanos > maxAge)) {
            drop("stale_result"); return
        }
        val ageMs = (elapsed - measuredNanos) / 1_000_000
        val freshness = if (ageMs > 30_000) "stale"
            else if (scanFreshness == "fresh" && measuredNanos < clock.elapsedNanos) "cached" else scanFreshness
        // Wi-Fi cache records stay as evidence; downstream baseline excludes them.
        val key = if (kind == "wifi") "$kind:$identity:$freshness" else "$kind:$identity"
        val previous = lastSeen[key]
        if (previous != null && (measuredNanos <= previous || (kind == "ble" && measuredNanos - previous < 1_000_000_000L))) {
            drop("duplicate_or_sampled"); return
        }
        if (lastSeen.size >= MAX_EVENTS && previous == null) { drop("identity_limit"); return }
        if (accepted.get() >= MAX_EVENTS) { accepting = false; statuses["session"] = "limit_reached"; return }
        val observation = JSONObject().put("kind", kind).put("id", identity)
            .put("source", "android:$sensorId:$kind").put("observed_at", utc)
        if (!name.isNullOrEmpty()) observation.put("name", name.take(256))
        if (rssi in -127..0) observation.put("rssi", rssi)
        if (kind == "wifi") {
            observation.put("security", security ?: "UNKNOWN").put("scan_freshness", freshness).put("scan_age_ms", ageMs)
            if (frequencyMhz != null && frequencyMhz in 2400..7125) observation.put("frequency_mhz", frequencyMhz)
            if (channel != null && channel in 1..233) observation.put("channel", channel)
        }
        if (kind == "ble") {
            observation.put("evidence_confidence", "reported")
            bleMetadata?.keys()?.forEach { key -> observation.put(key, bleMetadata.get(key)) }
        }
        val line = observation.toString()
        if (line.toByteArray(Charsets.UTF_8).size > 16_383) { drop("line_limit"); return }
        if (!queue.offer(line)) { drop("queue_full"); return }
        lastSeen[key] = measuredNanos
        accepted.incrementAndGet()
    }

    @Synchronized
    fun offerGatt(address: String, authorizationId: String, status: String, services: JSONArray) {
        if (!accepting || accepted.get() >= MAX_EVENTS) { drop("gatt_queue_closed"); return }
        val measured = SystemClock.elapsedRealtimeNanos()
        val utc = clock.utc(measured, measured, System.currentTimeMillis())
        if (utc == null) { drop("invalid_timestamp"); return }
        val observation = JSONObject().put("kind", "ble_gatt").put("id", address.lowercase(java.util.Locale.ROOT))
            .put("source", "android:$sensorId:ble").put("observed_at", utc)
            .put("evidence_confidence", "reported").put("authorization_id", authorizationId)
            .put("gatt_status", status).put("gatt_services", services).put("operation", "discover_services")
            .put("writes_performed", false).put("pairing_initiated", false)
        var line = observation.toString()
        if (line.toByteArray(Charsets.UTF_8).size > 16_383) {
            drop("gatt_line_limit")
            statuses["gatt"] = "truncated"
            line = observation.put("gatt_status", "truncated").put("gatt_services", JSONArray()).toString()
        }
        if (!queue.offer(line)) { drop("queue_full"); return }
        accepted.incrementAndGet()
    }

    /** Cellular callback receipt time is distinct from a modem measurement timestamp. */
    @Synchronized
    fun offerCellular(fields: JSONObject, measuredNanos: Long? = null) {
        if (!accepting) return
        if (accepted.get() >= MAX_EVENTS) { drop("cellular_event_limit"); return }
        val elapsed = SystemClock.elapsedRealtimeNanos()
        val utc = clock.utc(measuredNanos ?: elapsed, elapsed, System.currentTimeMillis())
        val received = clock.utc(elapsed, elapsed, System.currentTimeMillis())
        if (utc == null || received == null) { drop("cellular_invalid_timestamp"); return }
        val observation = JSONObject(fields.toString()).put("kind", "cellular")
            .put("id", UUID.randomUUID().toString()).put("source", "android:$sensorId:cellular")
            .put("collection_session", id).put("observed_at", utc).put("received_at", received)
        if (measuredNanos != null) {
            val age = (elapsed - measuredNanos) / 1_000_000
            observation.put("cell_age_ms", age).put("cell_freshness",
                if (observation.optString("cell_origin") == "cached_read" || age > 10_000) "cached" else "recent")
        }
        val line = observation.toString()
        if (line.toByteArray(Charsets.UTF_8).size > 16_383) { drop("cellular_line_limit"); return }
        if (!queue.offer(line)) { drop("queue_full"); return }
        accepted.incrementAndGet()
    }

    @Synchronized
    fun stopAccepting() { accepting = false; stopping = true }

    /** Called on the activity's single I/O worker after callbacks have been stopped. */
    fun finish(): File {
        stopAccepting()
        writer.join(5000)
        check(!writer.isAlive && !writerFailed) { "Spool failed or writer did not finish" }
        val bytes = payloadFile.readBytes()
        check(bytes.size <= MAX_BYTES)
        val hash = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 255) }
        val dropJson = JSONObject()
        drops.forEach { (key, value) -> dropJson.put(key, value.get()) }
        val metadata = JSONObject().put("session_id", id).put("sensor_id", sensorId).put("synthetic", false)
            .put("rows", written.get()).put("bytes", bytes.size)
            .put("clock_wall_ms", clock.wallMillis).put("clock_elapsed_ns", clock.elapsedNanos)
            .put("statuses", JSONObject(statuses.toMap())).put("drops", dropJson)
            .put("queue_capacity", QUEUE_SIZE).put("app_version", "0.1.0")
        if (bridgeNonce != null) metadata.put("bridge_nonce", bridgeNonce)
        val bundle = JSONObject().put("kind", "atlas-radio-export").put("schema_version", 1)
            .put("complete", true).put("metadata", metadata).put("sha256", hash)
            .put("payload_jsonl", bytes.toString(Charsets.UTF_8))
        val temporary = File(directory, "session.atlas.partial")
        val output = if (bridgeKey != null && bridgeNonce != null) {
            val signed = bundle.toString()
            val digest = BridgeAuthentication.sign(bridgeKey, signed)
            JSONObject().put("kind", "atlas-authenticated-export").put("schema_version", 1)
                .put("signed_json", signed).put("hmac_sha256", digest).toString()
        } else bundle.toString()
        temporary.writeText(output, Charsets.UTF_8)
        val finalized = File(directory, "session.atlas.json")
        check(temporary.renameTo(finalized)) { "Could not finalize export" }
        return finalized
    }
}
