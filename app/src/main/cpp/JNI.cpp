#include <jni.h>
#include <string>
#include <sstream>
#include <iomanip>

#include "RootDetector.h"

#include <jni.h>
#include <string>
#include <sstream>
#include <iomanip>
#include "RootDetector.h"

static std::string jsonEscape(const std::string& s) {
    std::ostringstream out;
    for (char c : s) {
        switch (c) {
            case '"': out << "\\\""; break;
            case '\\': out << "\\\\"; break;
            case '\b': out << "\\b"; break;
            case '\f': out << "\\f"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (c >= 0 && c < 32) {
                    out << "\\u" << std::hex << std::setw(4)
                        << std::setfill('0') << static_cast<int>(c);
                } else {
                    out << c;
                }
        }
    }
    return out.str();
}

static std::string generateJson(const RootDetector::RootDetectionReport& report) {
    std::ostringstream json;
    json << "{\n";
    json << "  \"rootDetected\": " << (report.rootDetected ? "true" : "false") << ",\n";
    json << "  \"checks\": [\n";
    for (size_t i = 0; i < report.checks.size(); ++i) {
        const auto& c = report.checks[i];
        json << "    {\n";
        json << "      \"name\": \"" << jsonEscape(c.name) << "\",\n";
        json << "      \"result\": " << (c.result ? "true" : "false") << ",\n";
        json << "      \"reason\": \"" << jsonEscape(c.reason) << "\"\n";
        json << "    }";
        if (i < report.checks.size() - 1) json << ",";
        json << "\n";
    }
    json << "  ]\n";
    json << "}";
    return json.str();
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_rootdetector_app_MainActivity_nativeDetectRoot(JNIEnv* env, jobject) {
    RootDetector::RootDetector detector;
    RootDetector::RootDetectionReport report = detector.detectRoot();
    return env->NewStringUTF(generateJson(report).c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_rootdetector_app_MainActivity_nativeGetVersion(JNIEnv* env, jobject) {
    return env->NewStringUTF("1.0.0");
}
