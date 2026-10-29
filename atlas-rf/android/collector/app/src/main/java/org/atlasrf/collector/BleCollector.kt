package org.atlasrf.collector

import android.Manifest
import android.bluetooth.BluetoothManager
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.content.pm.PackageManager
import android.os.Handler
import android.os.Looper
import org.json.JSONObject
import org.json.JSONArray

class BleCollector(private val context: Context, private val session: RadioSession) {
    private val handler = Handler(Looper.getMainLooper())
    private var scanner: BluetoothLeScanner? = null
    @Volatile private var active = false
    private val stopTimer = Runnable {
        stop()
        if (session.statuses["ble"] == "scanning") session.statuses["ble"] = "completed_empty"
        else if (session.statuses["ble"] == "results_received") session.statuses["ble"] = "completed_with_results"
    }
    private val callback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) { receive(result) }
        override fun onBatchScanResults(results: MutableList<ScanResult>) {
            for (result in results.take(RadioSession.MAX_EVENTS)) receive(result)
        }
        override fun onScanFailed(errorCode: Int) {
            session.statuses["ble"] = "scan_failed_$errorCode"
            stop()
        }
    }
    private fun receive(result: ScanResult) {
        if (!active) return
        try {
            val record = result.scanRecord
            val metadata = JSONObject().put("connectable", result.isConnectable)
                .put("advertisement_complete", result.dataStatus == ScanResult.DATA_COMPLETE)
            if (record != null) {
                val bytes = record.bytes
                // Oversized fields are omitted and incompleteness recorded, never silently truncated as complete.
                if (bytes != null && bytes.size <= 1650) metadata.put("advertisement_hex", bytes.toHex())
                else { metadata.put("advertisement_complete", false); session.drop("ble_payload_limit") }
                val services = record.serviceUuids
                if (services == null || services.size <= 64)
                    metadata.put("service_uuids", JSONArray(services.orEmpty().map { it.uuid.toString() }))
                else { metadata.put("advertisement_complete", false); session.drop("ble_uuid_limit") }
                val manufacturers = record.manufacturerSpecificData
                if (manufacturers != null && manufacturers.size() <= 16) {
                    val values = JSONObject()
                    var valid = true
                    for (index in 0 until manufacturers.size()) {
                        val data = manufacturers.valueAt(index)
                        if (data == null || data.size > 256) valid = false
                        else values.put(manufacturers.keyAt(index).toString(), data.toHex())
                    }
                    if (valid) metadata.put("manufacturer_data", values)
                    else { metadata.put("advertisement_complete", false); session.drop("ble_manufacturer_limit") }
                } else if (manufacturers != null) {
                    metadata.put("advertisement_complete", false); session.drop("ble_manufacturer_limit")
                }
            } else metadata.put("advertisement_complete", false)
            session.offer("ble", result.device.address, record?.deviceName, result.rssi, result.timestampNanos,
                bleMetadata = metadata)
            session.statuses["ble"] = "results_received"
        } catch (_: SecurityException) { session.statuses["ble"] = "permission_denied"; stop() }
    }
    fun start() {
        if (!context.packageManager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE)) {
            session.statuses["ble"] = "feature_absent"; return
        }
        val required = listOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT,
            Manifest.permission.ACCESS_FINE_LOCATION)
        if (required.any { context.checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED }) {
            session.statuses["ble"] = "permission_denied"; return
        }
        try {
            val adapter = context.getSystemService(BluetoothManager::class.java)?.adapter
            if (adapter == null) { session.statuses["ble"] = "feature_absent"; return }
            if (!adapter.isEnabled) { session.statuses["ble"] = "radio_disabled"; return }
            scanner = adapter.bluetoothLeScanner
            if (scanner == null) { session.statuses["ble"] = "scanner_unavailable"; return }
            active = true
            session.statuses["ble"] = "scanning"
            scanner?.startScan(null, ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_POWER).build(), callback)
            handler.postDelayed(stopTimer, 10_000)
        } catch (_: SecurityException) { session.statuses["ble"] = "permission_denied"; stop() }
        catch (_: IllegalStateException) { session.statuses["ble"] = "radio_unavailable"; stop() }
    }
    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 255) }

    fun stop() {
        active = false
        handler.removeCallbacks(stopTimer)
        try { scanner?.stopScan(callback) } catch (_: SecurityException) { session.statuses["ble"] = "permission_denied" }
        catch (_: IllegalStateException) { session.statuses["ble"] = "radio_unavailable" }
        scanner = null
    }
}
