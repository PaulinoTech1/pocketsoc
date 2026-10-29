package org.atlasrf.collector

import android.Manifest
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.content.Context
import android.content.pm.PackageManager
import android.os.Handler
import android.os.Looper
import org.json.JSONArray
import org.json.JSONObject
import java.time.Instant
import java.util.UUID

/** One explicitly approved, already-bonded target. Discovery metadata only; no value reads or writes. */
class GattInspector(private val context: Context, private val session: RadioSession,
                    private val request: JSONObject, private val onFinished: () -> Unit) {
    private val handler = Handler(Looper.getMainLooper())
    private var gatt: BluetoothGatt? = null
    private var finished = false
    private val timeout = Runnable { finish("timeout") }
    private val callback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(connection: BluetoothGatt, status: Int, newState: Int) {
            handler.post {
                if (finished) { try { connection.close() } catch (_: SecurityException) { }; return@post }
                gatt = connection
                if (status == BluetoothGatt.GATT_INSUFFICIENT_AUTHENTICATION || status == BluetoothGatt.GATT_INSUFFICIENT_ENCRYPTION) {
                    finish("authentication_required")
                } else if (status != BluetoothGatt.GATT_SUCCESS) finish("failed")
                else if (newState == BluetoothProfile.STATE_CONNECTED) {
                    try { if (!connection.discoverServices()) finish("failed") }
                    catch (_: SecurityException) { finish("permission_denied") }
                } else if (newState == BluetoothProfile.STATE_DISCONNECTED) finish("failed")
            }
        }
        override fun onServicesDiscovered(connection: BluetoothGatt, status: Int) {
            handler.post {
                if (finished) return@post
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    finish(if (status == BluetoothGatt.GATT_INSUFFICIENT_AUTHENTICATION || status == BluetoothGatt.GATT_INSUFFICIENT_ENCRYPTION)
                        "authentication_required" else "failed")
                    return@post
                }
                try {
                    val services = JSONArray()
                    var characteristics = 0
                    if (connection.services.size > 64) { finish("truncated"); return@post }
                    for (service in connection.services) {
                        val chars = JSONArray()
                        for (characteristic in service.characteristics) {
                            characteristics++
                            if (characteristics > 128) { finish("truncated"); return@post }
                            chars.put(JSONObject().put("uuid", characteristic.uuid.toString()).put("properties", characteristic.properties))
                        }
                        services.put(JSONObject().put("uuid", service.uuid.toString()).put("characteristics", chars))
                    }
                    finish("complete", services)
                } catch (_: SecurityException) { finish("permission_denied") }
            }
        }
    }
    fun start() {
        if (context.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
            finish("permission_denied"); return
        }
        try {
            val created = Instant.parse(request.getString("created_at"))
            val expires = Instant.parse(request.getString("expires_at"))
            val now = Instant.now()
            check((request.get("authorized") == true) && request.getString("operation") == "discover_services")
            check((request.get("writes_allowed") == false) && (request.get("pairing_allowed") == false))
            check(!created.isAfter(now.plusSeconds(30)) && expires.isAfter(now) && expires.isAfter(created) &&
                java.time.Duration.between(created, expires).seconds <= 900)
            val adapter = context.getSystemService(BluetoothManager::class.java)?.adapter
            if (adapter == null || !adapter.isEnabled) { finish("unavailable"); return }
            val target = adapter.getRemoteDevice(request.getString("address"))
            if (target.bondState != BluetoothDevice.BOND_BONDED) { finish("not_bonded"); return }
            // No autoConnect, no pairing request, no characteristic/descriptor/notification operations.
            handler.postDelayed(timeout, 10_000)
            gatt = target.connectGatt(context, false, callback, BluetoothDevice.TRANSPORT_LE)
            if (gatt == null) finish("failed")
        } catch (_: SecurityException) { finish("permission_denied") }
        catch (_: Exception) { finish("failed") }
    }
    fun cancel() { finish("cancelled") }
    private fun finish(status: String, services: JSONArray = JSONArray()) {
        if (finished) return
        finished = true
        handler.removeCallbacks(timeout)
        try { gatt?.disconnect() } catch (_: SecurityException) { /* Best-effort close still follows. */ }
        try { gatt?.close() } catch (_: SecurityException) { }
        gatt = null
        session.statuses["gatt"] = status
        session.offerGatt(request.getString("address"), request.getString("authorization_id"), status, services)
        onFinished()
    }
    companion object {
        fun validateRequest(body: String): JSONObject {
            check(body.toByteArray(Charsets.UTF_8).size <= 4096)
            val request = JSONObject(body)
            val fields = setOf("kind", "schema_version", "authorization_id", "address", "created_at", "expires_at", "authorized",
                "operation", "writes_allowed", "pairing_allowed")
            check(request.keys().asSequence().toSet() == fields)
            check(request.getString("kind") == "atlas-gatt-request" && request.get("schema_version") is Int && request.getInt("schema_version") == 1)
            UUID.fromString(request.getString("authorization_id"))
            val address = request.getString("address")
            check(address.matches(Regex("(?i)([0-9a-f]{2}:){5}[0-9a-f]{2}")))
            check(address.lowercase() !in setOf("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "02:00:00:00:00:00"))
            check((address.substring(0,2).toInt(16) and 1) == 0)
            check((request.get("authorized") == true) && request.getString("operation") == "discover_services")
            check((request.get("writes_allowed") == false) && (request.get("pairing_allowed") == false))
            val now = Instant.now()
            val created = Instant.parse(request.getString("created_at"))
            val expires = Instant.parse(request.getString("expires_at"))
            check(!created.isAfter(now.plusSeconds(30)) && expires.isAfter(now) && expires.isAfter(created) &&
                java.time.Duration.between(created,expires).seconds <= 900)
            return request
        }
    }
}
