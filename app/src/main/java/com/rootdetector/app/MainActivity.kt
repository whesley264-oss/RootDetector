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

    private lateinit var checkButton: com.google.android.material.button.MaterialButton
    private lateinit var statusTextView: TextView
    private lateinit var statusSubtitle: TextView
    private lateinit var resultTextView: TextView
    private lateinit var progressBar: ProgressBar

    companion object {
        init {
            System.loadLibrary("rootdetector")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        checkButton = findViewById(R.id.checkButton)
        statusTextView = findViewById(R.id.statusTextView)
        statusSubtitle = findViewById(R.id.statusSubtitle)
        resultTextView = findViewById(R.id.resultTextView)
        progressBar = findViewById(R.id.progressBar)

        checkButton.setOnClickListener {
            performRootDetection()
        }
    }

    private fun performRootDetection() {
        checkButton.isEnabled = false
        statusTextView.text = "SCANNING"
        statusTextView.setTextColor(getColor(R.color.primary))
        statusSubtitle.text = "Running security checks..."
        resultTextView.text = ""
        progressBar.visibility = ProgressBar.VISIBLE

        lifecycleScope.launch {
            try {
                val jsonResult = withContext(Dispatchers.Default) {
                    nativeDetectRoot()
                }
                displayResults(jsonResult)
            } catch (e: Exception) {
                displayError("Error: ${e.message}")
            } finally {
                checkButton.isEnabled = true
                progressBar.visibility = ProgressBar.GONE
            }
        }
    }

    private fun displayResults(jsonResult: String) {
        try {
            val json = JSONObject(jsonResult)
            val rootDetected = json.getBoolean("rootDetected")
            val checks = json.getJSONArray("checks")

            if (rootDetected) {
                statusTextView.text = "ROOT DETECTED"
                statusTextView.setTextColor(getColor(R.color.status_danger))
                statusSubtitle.text = "Security compromise found"
            } else {
                statusTextView.text = "DEVICE SECURE"
                statusTextView.setTextColor(getColor(R.color.status_secure))
                statusSubtitle.text = "No root access detected"
            }

            val builder = StringBuilder()
            builder.appendLine("Device Analysis Complete")
            builder.appendLine()

            var detectedCount = 0
            var cleanCount = 0

            for (i in 0 until checks.length()) {
                val check = checks.getJSONObject(i)
                val name = check.getString("name")
                val result = check.getBoolean("result")
                val reason = check.getString("reason")

                if (result) detectedCount++ else cleanCount++

                val symbol = if (result) "!" else "-"
                builder.appendLine("[$symbol] ${name.uppercase()}")
                builder.appendLine("    $reason")
            }

            builder.appendLine()
            builder.appendLine("---")
            builder.appendLine("Summary: $detectedCount warnings, $cleanCount clean")

            resultTextView.text = builder.toString()

        } catch (e: Exception) {
            displayError("Error parsing results: ${e.message}")
        }
    }

    private fun displayError(message: String) {
        statusTextView.text = "ERROR"
        statusTextView.setTextColor(getColor(R.color.status_warning))
        statusSubtitle.text = "Scan failed"
        resultTextView.text = message
    }

    external fun nativeDetectRoot(): String
    external fun nativeGetVersion(): String
}
