#include <jni.h>
#include <string>
#include <sstream>
#include <iomanip>

#include "RootDetector.h"

/**
 * @file JNI.cpp
 * @brief JNI bridge between Java/Kotlin and the C++ RootDetector.
 *
 * This file implements the JNI functions that are called from the
 * Android Java/Kotlin code to perform root detection.
 */

using namespace RootDetector;

/**
 * @brief Escapes special characters in a string for JSON output.
 * @param str String to escape.
 * @return Escaped string suitable for JSON.
 */
static std::string jsonEscape(const std::string& str) {
    std::ostringstream escaped;
    for (char c : str) {
        switch (c) {
            case '"':
                escaped << "\\\"";
                break;
            case '\\':
                escaped << "\\\\";
                break;
            case '\b':
                escaped << "\\b";
                break;
            case '\f':
                escaped << "\\f";
                break;
            case '\n':
                escaped << "\\n";
                break;
            case '\r':
                escaped << "\\r";
                break;
            case '\t':
                escaped << "\\t";
                break;
            default:
                if (c >= 0 && c < 32) {
                    escaped << "\\u" << std::hex << std::setw(4)
                            << std::setfill('0') << static_cast<int>(c);
                } else {
                    escaped << c;
                }
                break;
        }
    }
    return escaped.str();
}

/**
 * @brief Generates JSON representation of the root detection report.
 * @param report The root detection report to convert.
 * @return JSON string representation.
 */
static std::string generateJsonReport(const RootDetectionReport& report) {
    std::ostringstream json;

    json << "{\n";
    json << "  \"rootDetected\": " << (report.rootDetected ? "true" : "false") << ",\n";
    json << "  \"checks\": [\n";

    for (size_t i = 0; i < report.checks.size(); ++i) {
        const CheckResult& check = report.checks[i];
        json << "    {\n";
        json << "      \"name\": \"" << jsonEscape(check.name) << "\",\n";
        json << "      \"result\": " << (check.result ? "true" : "false") << ",\n";
        json << "      \"reason\": \"" << jsonEscape(check.reason) << "\"\n";
        json << "    }";
        if (i < report.checks.size() - 1) {
            json << ",";
        }
        json << "\n";
    }

    json << "  ]\n";
    json << "}";

    return json.str();
}

/**
 * @brief JNI function to detect root and return a JSON report.
 *
 * This is the main entry point called from Java/Kotlin.
 *
 * @param env JNI environment pointer.
 * @param jobject The Java object calling this method (unused).
 * @return JSON string containing the root detection report.
 */
extern "C" JNIEXPORT jstring JNICALL
Java_com_rootdetector_app_RootDetector_nativeDetectRoot(
    JNIEnv* env,
    jobject /* this */) {

    // Create RootDetector instance and run detection
    RootDetector detector;
    RootDetectionReport report = detector.detectRoot();

    // Generate JSON report
    std::string jsonReport = generateJsonReport(report);

    // Return as Java String
    return env->NewStringUTF(jsonReport.c_str());
}

/**
 * @brief JNI function to get the native library version.
 *
 * @param env JNI environment pointer.
 * @param jobject The Java object calling this method (unused).
 * @return Version string.
 */
extern "C" JNIEXPORT jstring JNICALL
Java_com_rootdetector_app_RootDetector_nativeGetVersion(
    JNIEnv* env,
    jobject /* this */) {
    return env->NewStringUTF("1.0.0");
}
