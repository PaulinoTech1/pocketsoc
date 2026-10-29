package org.atlasrf.collector

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.net.Uri
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.CheckBox
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import org.json.JSONObject
import java.io.File
import java.util.UUID
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

/** Visible activity only. No services, network sockets, boot receiver or automatic collection. */
class MainActivity : Activity() {
    private val handler = Handler(Looper.getMainLooper())
    private val io = ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS, ArrayBlockingQueue<Runnable>(1))
    private var ioBusy = false // All task submission is guarded on the UI thread: at most one task.
    private lateinit var text: TextView
    private lateinit var includeCellular: CheckBox
    private var cellular: CellularCollector? = null
    private var networkTest: BoundedNetworkTest? = null
    private lateinit var includeWifi: CheckBox
    private lateinit var startButton: Button
    private lateinit var exportButton: Button
    private lateinit var probeButton: Button
    private lateinit var gattButton: Button
    private var gattInspector: GattInspector? = null
    private var session: RadioSession? = null
    private var wifi: WifiCollector? = null
    private var ble: BleCollector? = null
    private var finalized: File? = null
    private var pendingProbe: JSONObject? = null
    private var exportMode = ""
    private var pickerOpen = false
    private val stopTimer = Runnable { stopSession("time_limit") }
    private val refresh = object : Runnable {
        override fun run() {
            session?.let { text.text = "Live session: ${it.written.get()} written\n${it.statuses}\nAuto-stop after 15 seconds (25 for network tests). BLE discovery lasts 10 seconds." }
            handler.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        val layout = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(24, 24, 24, 24) }
        text = TextView(this).apply { text = "ATLAS RF Collector\nSource prototype; field verification required.\nNo collection starts automatically. Export to local Documents, then import in Debian." }
        layout.addView(text)
        fun button(label: String, action: () -> Unit): Button = Button(this).apply {
            this.text = label; setOnClickListener { action() }; layout.addView(this)
        }
        button("Grant BLE scan/controller permissions (no location)") {
            requestPermissions(arrayOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT), 100)
        }
        button("Grant optional Wi-Fi scan permissions (Android requires location)") {
            // Android requires coarse + fine together for an explicit precise permission request.
            // No coordinates are requested, inferred or written by this application.
            requestPermissions(arrayOf(Manifest.permission.ACCESS_COARSE_LOCATION, Manifest.permission.ACCESS_FINE_LOCATION), 101)
        }
        includeWifi = CheckBox(this).apply {
            text = "Include Wi-Fi scanning in this session (off by default)"
            isChecked = false
            layout.addView(this)
        }
        button("Grant optional cellular permissions (phone state and precise location)") {
            requestPermissions(arrayOf(Manifest.permission.READ_PHONE_STATE,
                Manifest.permission.ACCESS_COARSE_LOCATION, Manifest.permission.ACCESS_FINE_LOCATION), 102)
        }
        includeCellular = CheckBox(this).apply {
            text = "Include cellular telemetry (off by default; paired key + challenge required)"
            isChecked = false; layout.addView(this)
        }
        button("Import bridge key (trusted private document transfer)") { chooseCellularDocument(202) }
        button("Import current Debian bridge challenge") { chooseCellularDocument(203) }
        button("Open authorized Wi-Fi / cellular HTTPS test request") { chooseCellularDocument(204) }
        startButton = button("Start 15-second session (replaces displayed session)") { startSession() }
        button("Stop and finalize") { stopSession("user_stop") }
        exportButton = button("Export finalized telemetry") { chooseExport("telemetry") }
        probeButton = button("Export transport nonce (no radio permissions needed)") { chooseExport("probe") }
        gattButton = button("Open authorized GATT request (no pairing or writes)") { chooseGattRequest() }
        exportButton.isEnabled = false
        setContentView(android.widget.ScrollView(this).apply { addView(layout) })
    }

    override fun onStart() { super.onStart(); handler.post(refresh) }
    override fun onStop() {
        handler.removeCallbacks(refresh)
        stopSession("activity_stopped")
        super.onStop()
    }
    override fun onDestroy() { io.shutdown(); super.onDestroy() }

    private fun startSession() {
        if (session != null || ioBusy || pickerOpen) return
        val prefs = getSharedPreferences("collector", MODE_PRIVATE)
        val sensor = prefs.getString("sensor_id", null) ?: UUID.randomUUID().toString().also {
            prefs.edit().putString("sensor_id", it).apply()
        }
        val pairing = cellularPairing()
        if (includeCellular.isChecked && pairing == null) {
            text.text = "Import a bridge key and a new Debian challenge before cellular collection."; return
        }
        finalized = null
        val created = RadioSession(File(cacheDir, "atlas-radio"), sensor, pairing?.first, pairing?.second)
        session = created
        startButton.isEnabled = false; exportButton.isEnabled = false; probeButton.isEnabled = false; gattButton.isEnabled = false
        if (includeWifi.isChecked) wifi = WifiCollector(this, created).also { it.start() }
        else created.statuses["wifi"] = "disabled_by_default"
        ble = BleCollector(this, created).also { it.start() }
        if (includeCellular.isChecked) cellular = CellularCollector(this, created).also { it.start() }
        else created.statuses["cellular"] = "disabled_by_default"
        handler.postDelayed(stopTimer, 15_000)
    }

    private fun stopSession(reason: String) {
        val active = session ?: return
        session = null
        val inspection = gattInspector; gattInspector = null
        inspection?.cancel()
        handler.removeCallbacks(stopTimer)
        wifi?.stop(); ble?.stop(); cellular?.stop(); networkTest?.cancel()
        wifi = null; ble = null; cellular = null; networkTest = null
        active.statuses.putIfAbsent("session", reason)
        active.stopAccepting()
        ioBusy = true
        text.text = "Finalizing bounded queue…"
        io.execute {
            val result = runCatching { active.finish() }
            handler.post {
                ioBusy = false
                if (!isDestroyed) {
                    result.onSuccess {
                        finalized = it
                        text.text = "Finalized ${active.written.get()} real observations.\n${active.statuses}\nExport explicitly; no data has been sent yet."
                    }.onFailure { text.text = "Finalization failed; no complete export available." }
                    startButton.isEnabled = true
                    exportButton.isEnabled = finalized != null
                    probeButton.isEnabled = true; gattButton.isEnabled = true
                }
            }
        }
    }

    private fun cellularPairing(): Pair<ByteArray, String>? {
        val prefs = getSharedPreferences("cellular_bridge", MODE_PRIVATE)
        val key = prefs.getString("key", null) ?: return null
        val nonce = prefs.getString("nonce", null) ?: return null
        if (!key.matches(Regex("[0-9a-f]{64}")) || !nonce.matches(Regex("[0-9a-f]{64}"))) return null
        return key.chunked(2).map { it.toInt(16).toByte() }.toByteArray() to nonce
    }

    private fun chooseCellularDocument(code: Int) {
        if (session != null || ioBusy || pickerOpen) return
        pickerOpen = true
        @Suppress("DEPRECATION")
        startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE); type = if (code == 202) "*/*" else "application/json"
        }, code)
    }

    private fun receiveCellularDocument(uri: Uri, code: Int) {
        ioBusy = true
        io.execute {
            val result = runCatching {
                contentResolver.openInputStream(uri)?.use { stream ->
                    val bytes = ByteArray(4097)
                    var size = 0
                    while (size < bytes.size) {
                        val n = stream.read(bytes, size, bytes.size - size)
                        if (n < 0) break
                        size += n
                    }
                    check(size <= 4096)
                    String(bytes, 0, size, Charsets.UTF_8)
                } ?: error("No document")
            }
            handler.post {
                ioBusy = false
                if (isDestroyed || isFinishing) return@post
                result.onSuccess { content ->
                    try {
                        val prefs = getSharedPreferences("cellular_bridge", MODE_PRIVATE)
                        when (code) {
                            202 -> {
                                val hex = content.trim(); check(hex.matches(Regex("[0-9a-f]{64}")))
                                // Private app storage, backup disabled. Never display/log the key.
                                prefs.edit().putString("key", hex).remove("nonce").apply()
                                text.text = "Bridge key imported. Delete transfer copies. Import a new Debian challenge next."
                            }
                            203 -> {
                                val doc = JSONObject(content)
                                check(doc.getString("kind") == "atlas-cellular-challenge" && doc.getInt("schema_version") == 1)
                                val nonce = doc.getString("nonce"); check(nonce.matches(Regex("[0-9a-f]{64}")))
                                prefs.edit().putString("nonce", nonce).apply()
                                text.text = "Bridge challenge imported. Start an explicit cellular session, export, and verify in Debian."
                            }
                            204 -> {
                                val request = BoundedNetworkTest.validate(content)
                                check(cellularPairing() != null)
                                AlertDialog.Builder(this).setTitle("Authorize two bounded HTTPS tests")
                                    .setMessage("Endpoint: ${request.getString("endpoint")}\nOne Wi-Fi GET then one cellular GET. Up to 64 KiB response per test plus protocol overhead. Mobile data charges may apply. No redirects; only this endpoint. Confirm you are authorized to test it.")
                                    .setNegativeButton("Cancel", null)
                                    .setPositiveButton("Authorized: test") { _, _ -> startNetworkTest(request) }.show()
                            }
                        }
                    } catch (_: Exception) { text.text = "Invalid document, expired test request, or missing bridge pairing. No test started." }
                }.onFailure { text.text = "Could not read bounded document. No test started." }
            }
        }
    }

    private fun startNetworkTest(request: JSONObject) {
        if (session != null || ioBusy || pickerOpen) return
        val pairing = cellularPairing() ?: return
        // Revalidate expiry at final authorization, not only document-open time.
        try { BoundedNetworkTest.validate(request.toString()) } catch (_: Exception) { text.text = "Request expired."; return }
        val prefs = getSharedPreferences("collector", MODE_PRIVATE)
        val sensor = prefs.getString("sensor_id", null) ?: UUID.randomUUID().toString().also {
            prefs.edit().putString("sensor_id", it).apply()
        }
        val active = RadioSession(File(cacheDir, "atlas-radio"), sensor, pairing.first, pairing.second)
        session = active; finalized = null
        startButton.isEnabled = false; exportButton.isEnabled = false; probeButton.isEnabled = false; gattButton.isEnabled = false
        handler.postDelayed(stopTimer, 25_000)
        networkTest = BoundedNetworkTest(this, active, request) { stopSession("network_tests_finished") }
        networkTest?.start()
    }

    private fun chooseGattRequest() {
        if (session != null || ioBusy || pickerOpen) return
        pickerOpen = true
        @Suppress("DEPRECATION")
        startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE); type = "application/json"
        }, 201)
    }

    private fun receiveGattRequest(uri: Uri) {
        if (ioBusy || session != null) return
        ioBusy = true
        io.execute {
            val result = runCatching {
                val body = contentResolver.openInputStream(uri)?.use { input ->
                    val bytes = ByteArray(4097)
                    var size = 0
                    while (size < bytes.size) {
                        val count = input.read(bytes, size, bytes.size - size)
                        if (count < 0) break
                        size += count
                    }
                    check(size <= 4096)
                    String(bytes, 0, size, Charsets.UTF_8)
                } ?: error("No document stream")
                GattInspector.validateRequest(body)
            }
            handler.post {
                ioBusy = false
                if (!isDestroyed && !isFinishing) {
                    result.onSuccess { request ->
                        AlertDialog.Builder(this).setTitle("Authorize one GATT inspection")
                            .setMessage("Target: ${request.getString("address")}\nScope: discover services and characteristic properties only. Already-bonded target required. No pairing, value reads or writes. Addresses do not prove physical identity.\nConfirm that you are authorized to assess this target.")
                            .setNegativeButton("Cancel", null)
                            .setPositiveButton("Authorized: enumerate") { _, _ -> startGattSession(request) }.show()
                    }.onFailure { text.text = "Invalid, expired or oversized request. No connection made." }
                }
            }
        }
    }

    private fun startGattSession(request: JSONObject) {
        if (session != null || ioBusy || pickerOpen) return
        val prefs = getSharedPreferences("collector", MODE_PRIVATE)
        val sensor = prefs.getString("sensor_id", null) ?: UUID.randomUUID().toString().also {
            prefs.edit().putString("sensor_id", it).apply()
        }
        val active = RadioSession(File(cacheDir, "atlas-radio"), sensor)
        session = active; finalized = null
        startButton.isEnabled = false; exportButton.isEnabled = false; probeButton.isEnabled = false; gattButton.isEnabled = false
        handler.postDelayed(stopTimer, 15_000)
        gattInspector = GattInspector(this, active, request) { stopSession("gatt_finished") }
        gattInspector?.start()
    }

    private fun chooseExport(mode: String) {
        if (session != null || ioBusy || pickerOpen || (mode == "telemetry" && finalized == null)) return
        exportMode = mode
        if (mode == "probe") {
            val nonce = UUID.randomUUID().toString()
            pendingProbe = JSONObject().put("kind", "atlas-transport-probe").put("schema_version", 1)
                .put("nonce", nonce).put("synthetic", false)
            text.text = "Transport nonce: $nonce\nAfter export, compare this exact nonce in Debian. This checks file delivery, not authentication."
        }
        pickerOpen = true
        val filename = if (mode == "probe") "atlas-transport-probe.json" else "atlas-${UUID.randomUUID()}.atlas.json"
        @Suppress("DEPRECATION")
        startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE); type = "application/json"
            putExtra(Intent.EXTRA_TITLE, filename)
        }, 200)
    }

    @Deprecated("Platform callback retained to avoid an AndroidX runtime dependency")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode in 202..204) {
            pickerOpen = false
            if (resultCode == RESULT_OK && data?.data != null) receiveCellularDocument(data.data!!, requestCode)
            else text.text = "Document selection cancelled."
            return
        }
        if (requestCode == 201) {
            pickerOpen = false
            if (resultCode == RESULT_OK && data?.data != null) receiveGattRequest(data.data!!)
            else text.text = "GATT request selection cancelled; no connection made."
            return
        }
        if (requestCode != 200) return
        pickerOpen = false
        if (resultCode != RESULT_OK || data?.data == null) { text.text = "Export cancelled; private spool retained."; return }
        val uri = data.data!!
        val mode = exportMode
        val source = finalized
        val probe = pendingProbe?.toString()
        ioBusy = true
        startButton.isEnabled = false; exportButton.isEnabled = false; probeButton.isEnabled = false; gattButton.isEnabled = false
        io.execute {
            val result = runCatching {
                contentResolver.openOutputStream(uri, "w")?.use { output ->
                    if (mode == "probe") output.write(checkNotNull(probe).toByteArray(Charsets.UTF_8))
                    else checkNotNull(source).inputStream().use { input -> input.copyTo(output, 16 * 1024) }
                    output.flush()
                } ?: error("Document provider did not open output")
            }
            handler.post {
                ioBusy = false
                if (!isDestroyed) {
                    text.text = if (result.isSuccess) {
                        if (mode == "probe") "Probe export closed. Nonce: ${pendingProbe?.getString("nonce")}\nVerify it from the shared Debian path."
                        else "Export stream closed. Verify and import the .atlas.json file in Debian. This alone does not prove VM delivery."
                    } else "Export failed. A partial document may remain; do not import it. Private spool retained."
                    startButton.isEnabled = true; exportButton.isEnabled = finalized != null; probeButton.isEnabled = true; gattButton.isEnabled = true
                }
            }
        }
    }
}
