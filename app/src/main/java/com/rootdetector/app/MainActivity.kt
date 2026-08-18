package com.rootdetector.app

import android.graphics.Typeface
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.cardview.widget.CardView
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

class MainActivity : AppCompatActivity() {

    private lateinit var btnCheck: com.google.android.material.button.MaterialButton
    private lateinit var shieldIcon: ImageView
    private lateinit var tvStatus: TextView
    private lateinit var tvSubtitle: TextView
    private lateinit var statTotal: TextView
    private lateinit var statClean: TextView
    private lateinit var statAlerts: TextView
    private lateinit var resultsHeader: View
    private lateinit var resultsDivider: View
    private lateinit var resultsContainer: LinearLayout
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
        shieldIcon = findViewById(R.id.shieldIcon)
        tvStatus = findViewById(R.id.statusTextView)
        tvSubtitle = findViewById(R.id.statusSubtitle)
        statTotal = findViewById(R.id.statTotal)
        statClean = findViewById(R.id.statClean)
        statAlerts = findViewById(R.id.statAlerts)
        resultsHeader = findViewById(R.id.resultsHeader)
        resultsDivider = findViewById(R.id.resultsDivider)
        resultsContainer = findViewById(R.id.resultsContainer)
        progressBar = findViewById(R.id.progressBar)

        btnCheck.setOnClickListener { performScan() }
    }

    private fun performScan() {
        btnCheck.isEnabled = false
        tvStatus.text = "SCANNING"
        tvStatus.setTextColor(getColor(R.color.status_info))
        tvSubtitle.text = "Running security checks..."
        shieldIcon.setImageResource(R.drawable.ic_shield_idle)
        resultsHeader.visibility = View.GONE
        resultsDivider.visibility = View.GONE
        resultsContainer.removeAllViews()
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
        val total = data.optInt("totalChecks", 0)
        val alerts = data.optInt("detectedCount", 0)
        val clean = total - alerts
        val checks = data.getJSONArray("checks")

        statTotal.text = total.toString()
        statClean.text = clean.toString()
        statAlerts.text = alerts.toString()

        if (hasRoot) {
            tvStatus.text = "ROOT DETECTED"
            tvStatus.setTextColor(getColor(R.color.status_danger))
            tvSubtitle.text = "Security compromise found"
            shieldIcon.setImageResource(R.drawable.ic_shield_danger)
        } else if (alerts > 0) {
            tvStatus.text = "ATTENTION NEEDED"
            tvStatus.setTextColor(getColor(R.color.status_warning))
            tvSubtitle.text = "Minor indicators detected"
            shieldIcon.setImageResource(R.drawable.ic_shield_warning)
        } else {
            tvStatus.text = "DEVICE SECURE"
            tvStatus.setTextColor(getColor(R.color.status_secure))
            tvSubtitle.text = "No root access detected"
            shieldIcon.setImageResource(R.drawable.ic_shield_secure)
        }

        resultsHeader.visibility = View.VISIBLE
        resultsDivider.visibility = View.VISIBLE
        resultsContainer.removeAllViews()

        for (i in 0 until checks.length()) {
            val check = checks.getJSONObject(i)
            val name = check.getString("name")
            val passed = check.getBoolean("result")
            val reason = check.getString("reason")
            resultsContainer.addView(buildCheckCard(name, passed, reason, hasRoot))
        }
    }

    private fun buildCheckCard(name: String, flagged: Boolean, reason: String, rootDetected: Boolean): View {
        val density = resources.displayMetrics.density
        val padH = (16 * density).toInt()
        val padV = (12 * density).toInt()

        val card = CardView(this).apply {
            radius = 16 * density
            cardElevation = 2 * density
            useCompatPadding = true
            setContentPadding(padH, padV, padH, padV)
            setCardBackgroundColor(getColor(R.color.card_background))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = (10 * density).toInt() }
        }

        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }

        val icon = ImageView(this).apply {
            setImageResource(if (flagged) R.drawable.ic_check_alert else R.drawable.ic_check_ok)
            layoutParams = LinearLayout.LayoutParams((24 * density).toInt(), (24 * density).toInt()).apply {
                marginEnd = (12 * density).toInt()
            }
        }

        val textCol = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }

        val title = TextView(this).apply {
            text = name.uppercase()
            setTextColor(getColor(if (flagged) R.color.status_danger else R.color.text_primary))
            textSize = 13f
            typeface = Typeface.DEFAULT_BOLD
        }

        val detail = TextView(this).apply {
            text = reason
            setTextColor(getColor(R.color.text_secondary))
            textSize = 11f
            setPadding(0, (3 * density).toInt(), 0, 0)
        }

        textCol.addView(title)
        textCol.addView(detail)
        row.addView(icon)
        row.addView(textCol)

        // Tint the whole card when the device is rooted and this check triggered
        if (flagged && rootDetected) {
            card.setCardBackgroundColor(getColor(R.color.card_danger_bg))
        }

        card.addView(row)
        return card
    }

    private fun displayError(message: String) {
        tvStatus.text = "ERROR"
        tvStatus.setTextColor(getColor(R.color.status_warning))
        tvSubtitle.text = "Scan failed"
        shieldIcon.setImageResource(R.drawable.ic_shield_warning)
        statTotal.text = "--"
        statClean.text = "--"
        statAlerts.text = "--"
        resultsHeader.visibility = View.VISIBLE
        resultsDivider.visibility = View.VISIBLE
        resultsContainer.removeAllViews()
        val tv = TextView(this).apply {
            text = message
            setTextColor(getColor(R.color.status_warning))
            textSize = 12f
        }
        resultsContainer.addView(tv)
    }

    external fun nativeDetectRoot(): String
    external fun nativeGetVersion(): String
}
