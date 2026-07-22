package com.rootdetector.app

import android.os.Bundle
import android.widget.Button
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

class MainActivity : AppCompatActivity() {

    private lateinit var checkButton: Button
    private lateinit var statusTextView: TextView
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
        resultTextView = findViewById(R.id.resultTextView)
        progressBar = findViewById(R.id.progressBar)

        statusTextView.text = "Pressione Check para iniciar"
        resultTextView.text = ""

        checkButton.setOnClickListener {
            performRootDetection()
        }
    }

    private fun performRootDetection() {
        checkButton.isEnabled = false
        statusTextView.text = "Verificando..."
        resultTextView.text = ""
        progressBar.visibility = ProgressBar.VISIBLE

        lifecycleScope.launch {
            try {
                val jsonResult = withContext(Dispatchers.Default) {
                    nativeDetectRoot()
                }
                displayResults(jsonResult)
            } catch (e: Exception) {
                displayError("Erro: ${e.message}")
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

            val builder = StringBuilder()
            builder.appendLine("ROOT DETECTION REPORT")
            builder.appendLine("========================")
            builder.appendLine()

            val statusLabel = if (rootDetected) "[ ROOT DETECTADO ]" else "[ SEM ROOT ]"
            statusTextView.text = statusLabel

            if (rootDetected) {
                statusTextView.setTextColor(getColor(android.R.color.holo_red_dark))
            } else {
                statusTextView.setTextColor(getColor(android.R.color.holo_green_dark))
            }

            builder.appendLine("RESULTADO: ${if (rootDetected) "ROOT DETECTADO" else "DISPOSITIVO SEGURO"}")
            builder.appendLine()
            builder.appendLine("VERIFICACOES:")
            builder.appendLine("-".repeat(40))

            for (i in 0 until checks.length()) {
                val check = checks.getJSONObject(i)
                val name = check.getString("name")
                val result = check.getBoolean("result")
                val reason = check.getString("reason")

                val status = if (result) "[OK]" else "[--]"
                builder.appendLine("$status $name")
                builder.appendLine("    $reason")
                builder.appendLine()
            }

            builder.appendLine("-".repeat(40))
            builder.appendLine("Versao: ${nativeGetVersion()}")

            resultTextView.text = builder.toString()

        } catch (e: Exception) {
            displayError("Erro ao processar: ${e.message}")
        }
    }

    private fun displayError(message: String) {
        statusTextView.text = "[ ERRO ]"
        statusTextView.setTextColor(getColor(android.R.color.holo_orange_dark))
        resultTextView.text = message
    }

    external fun nativeDetectRoot(): String
    external fun nativeGetVersion(): String
}
