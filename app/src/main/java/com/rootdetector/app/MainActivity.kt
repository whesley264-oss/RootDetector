package com.rootdetector.app

import android.os.Bundle
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

class MainActivity : AppCompatActivity() {

    private lateinit var btnCheck: com.google.android.material.button.MaterialButton
    private lateinit var tvStatus: TextView
    private lateinit var tvSubtitle: TextView
    private lateinit var tvResult: TextView
    private lateinit var progressBar: ProgressBar

    companion object {
        init {
            System.loadLibrary("rootdetector")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        btnCheck = findViewById(R.id.checkButton)
        tvStatus = findViewById(R.id.statusTextView)
        tvSubtitle = findViewById(R.id.statusSubtitle)
        tvResult = findViewById(R.id.resultTextView)
        progressBar = findViewById(R.id.progressBar)

        btnCheck.setOnClickListener { performScan() }
    }

    private fun performScan() {
        btnCheck.isEnabled = false
        tvStatus.text = "SCANNING"
        tvStatus.setTextColor(getColor(R.color.primary))
        tvSubtitle.text = "Running security checks..."
        tvResult.text = ""
        progressBar.visibility = ProgressBar.VISIBLE

        lifecycleScope.launch {
            try {
                val result = withContext(Dispatchers.Default) { nativeDetectRoot() }
                displayResults(result)
            } catch (e: Exception) {
                displayError("Error: ${e.message}")
            } finally {
                btnCheck.isEnabled = true
                progressBar.visibility = ProgressBar.GONE
            }
        }
    }

    private fun displayResults(json: String) {
        val data = JSONObject(json)
        val hasRoot = data.getBoolean("rootDetected")
        val checks = data.getJSONArray("checks")

        if (hasRoot) {
            tvStatus.text = "ROOT DETECTED"
            tvStatus.setTextColor(getColor(R.color.status_danger))
            tvSubtitle.text = "Security compromise found"
        } else {
            tvStatus.text = "DEVICE SECURE"
            tvStatus.setTextColor(getColor(R.color.status_secure))
            tvSubtitle.text = "No root access detected"
        }

        val sb = StringBuilder()
        var warnings = 0
        var clean = 0

        for (i in 0 until checks.length()) {
            val check = checks.getJSONObject(i)
            val name = check.getString("name")
            val passed = check.getBoolean("result")
            val reason = check.getString("reason")

            if (passed) warnings++ else clean++

            val symbol = if (passed) "!" else "-"
            sb.appendLine("[$symbol] ${name.uppercase()}")
            sb.appendLine("    $reason")
        }

        sb.appendLine()
        sb.appendLine("---")
        sb.appendLine("Summary: $warnings warnings, $clean clean")

        tvResult.text = sb.toString()
    }

    private fun displayError(message: String) {
        tvStatus.text = "ERROR"
        tvStatus.setTextColor(getColor(R.color.status_warning))
        tvSubtitle.text = "Scan failed"
        tvResult.text = message
    }

    external fun nativeDetectRoot(): String
    external fun nativeGetVersion(): String
}
