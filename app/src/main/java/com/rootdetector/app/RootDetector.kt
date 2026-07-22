package com.rootdetector.app

import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * Main activity that displays the root detection results.
 *
 * This class serves as the minimal Kotlin interface that:
 * 1. Initializes the native library
 * 2. Calls the JNI function to perform root detection
 * 3. Displays the JSON results in the UI
 */
class MainActivity : AppCompatActivity() {

    private lateinit var resultTextView: TextView
    private lateinit var statusTextView: TextView

    companion object {
        init {
            // Load the native library
            System.loadLibrary("rootdetector")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        resultTextView = findViewById(R.id.resultTextView)
        statusTextView = findViewById(R.id.statusTextView)

        // Run root detection asynchronously
        performRootDetection()
    }

    /**
     * Performs root detection using the native library.
     * This is called asynchronously to avoid blocking the UI thread.
     */
    private fun performRootDetection() {
        lifecycleScope.launch {
            try {
                val jsonResult = withContext(Dispatchers.Default) {
                    // Call the native function
                    nativeDetectRoot()
                }

                // Parse and display results
                displayResults(jsonResult)
            } catch (e: Exception) {
                displayError("Error during root detection: ${e.message}")
            }
        }
    }

    /**
     * Displays the root detection results in the UI.
     * Parses the JSON and formats it for human-readable display.
     */
    private fun displayResults(jsonResult: String) {
        try {
            val json = JSONObject(jsonResult)
            val rootDetected = json.getBoolean("rootDetected")
            val checks = json.getJSONArray("checks")

            val builder = StringBuilder()

            // Add header
            builder.appendLine("╔══════════════════════════════════════╗")
            builder.appendLine("║     ROOT DETECTION REPORT            ║")
            builder.appendLine("╚══════════════════════════════════════╝")
            builder.appendLine()

            // Overall status
            val statusIcon = if (rootDetected) "⚠️" else "✓"
            val statusText = if (rootDetected) "ROOT DETECTED" else "NO ROOT DETECTED"
            builder.appendLine("$statusIcon $statusText")
            builder.appendLine("─".repeat(40))
            builder.appendLine()

            // Individual checks
            builder.appendLine("CHECK RESULTS:")
            builder.appendLine()

            for (i in 0 until checks.length()) {
                val check = checks.getJSONObject(i)
                val name = check.getString("name")
                val result = check.getBoolean("result")
                val reason = check.getString("reason")

                val icon = if (result) "✓" else "✗"
                builder.appendLine("$icon ${name.uppercase()}")
                builder.appendLine("  └─ $reason")
                builder.appendLine()
            }

            builder.appendLine("─".repeat(40))
            builder.appendLine("Native Library Version: ${nativeGetVersion()}")

            // Update UI
            statusTextView.text = statusText
            statusTextView.setTextColor(
                if (rootDetected) getColor(android.R.color.holo_red_dark)
                else getColor(android.R.color.holo_green_dark)
            )

            resultTextView.text = builder.toString()

        } catch (e: Exception) {
            displayError("Error parsing results: ${e.message}")
        }
    }

    /**
     * Displays an error message in the UI.
     */
    private fun displayError(message: String) {
        statusTextView.text = "ERROR"
        statusTextView.setTextColor(getColor(android.R.color.holo_orange_dark))
        resultTextView.text = message
    }

    /**
     * Native function to detect root and return JSON report.
     * This is implemented in JNI.cpp and calls the C++ RootDetector.
     */
    external fun nativeDetectRoot(): String

    /**
     * Native function to get the library version.
     */
    external fun nativeGetVersion(): String
}
