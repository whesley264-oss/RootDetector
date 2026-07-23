#include "RootDetector.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

namespace RootDetector {

const char* const RootDetector::SU_PATHS[] = {
    "/system/bin/su", "/system/xbin/su", "/sbin/su", "/vendor/bin/su",
    "/system/su", "/data/local/bin/su", "/data/local/xbin/su", "/data/local/su"
};

const char* const RootDetector::MAGISK_PATHS[] = {
    "/data/adb/magisk", "/data/adb/magisk.img", "/data/adb/magiskrc",
    "/system/etc/magisk", "/system/xbin/magisk", "/system/bin/magisk", "/sbin/magisk",
    "/data/app/com.topjohnwu.magisk*", "/data/app/*/com.topjohnwu.magisk*",
    "/system/app/Magisk.apk", "/system/app/Magisk", "/cache/magisk.log"
};

const char* const RootDetector::ROOT_APP_PACKAGES[] = {
    "eu.chainfire.supersu", "com.topjohnwu.magisk", "com.koushikdutta.superuser",
    "com.noshufou.android.su", "com.noshufou.android.su.elite", "com.thirdparty.superuser",
    "com.yellowes.su", "com.kingroot.kinguser", "com.kingo.root",
    "com.smedialink.oneclickroot", "com.zhiqupk.root.global"
};

bool RootDetector::fileExists(const char* path) {
    return path != nullptr && access(path, F_OK) == 0;
}

bool RootDetector::readFile(const char* path, std::string& content) {
    if (!path) return false;
    std::ifstream file(path);
    if (!file.is_open()) return false;
    std::stringstream buffer;
    buffer << file.rdbuf();
    content = buffer.str();
    return file.eof() || !buffer.fail();
}

bool RootDetector::getSystemProperty(const char* name, std::string& value) {
    if (!name) return false;
    FILE* pipe = popen(("getprop " + std::string(name)).c_str(), "r");
    if (!pipe) return false;
    char buf[256] = {0};
    if (fgets(buf, sizeof(buf), pipe)) {
        size_t len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n') buf[len - 1] = '\0';
        value = buf;
    }
    int status = pclose(pipe);
    return status == 0 && !value.empty();
}

bool RootDetector::isRunningAsRoot() {
    return geteuid() == 0;
}

std::pair<bool, std::string> RootDetector::executeCommand(const char* cmd, int timeoutMs) {
    std::pair<bool, std::string> result{false, ""};
    if (!cmd) return result;

    FILE* pipe = popen(cmd, "r");
    if (!pipe) return result;

    int fd = fileno(pipe);
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

    std::string output;
    char buf[256] = {0};

    alarm(timeoutMs / 1000);
    while (true) {
        ssize_t bytesRead = read(fd, buf, sizeof(buf) - 1);
        if (bytesRead > 0) {
            buf[bytesRead] = '\0';
            output += buf;
        } else if (bytesRead == 0) {
            break;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            break;
        } else if (!output.empty()) {
            break;
        }
    }
    alarm(0);

    int status = pclose(pipe);
    result.first = status == 0;
    result.second = output;
    return result;
}

RootDetectionReport RootDetector::detectRoot() {
    RootDetectionReport report;

    report.checks.push_back(checkSuBinary());
    report.checks.push_back(checkMagiskFiles());
    report.checks.push_back(checkSuExecution());
    report.checks.push_back(checkSystemProperties());
    report.checks.push_back(checkMounts());
    report.checks.push_back(checkBuildTags());
    report.checks.push_back(checkRootManagementApps());
    report.checks.push_back(checkSelinuxStatus());
    report.checks.push_back(checkSystemPaths());
    report.checks.push_back(checkLsCommand());
    report.checks.push_back(checkSuBinaryPermissions());
    report.checks.push_back(checkRWPartitions());
    report.checks.push_back(checkRootProcesses());
    report.checks.push_back(checkCustomRom());

    for (const auto& check : report.checks) {
        if (check.result) {
            report.rootDetected = true;
            break;
        }
    }
    return report;
}

CheckResult RootDetector::checkSuBinary() {
    for (const char* path : SU_PATHS) {
        struct stat st;
        if (stat(path, &st) == 0 && (st.st_mode & S_IXUSR)) {
            return CheckResult("su binary", true, std::string("Found at: ") + path);
        }
    }
    return CheckResult("su binary", false, "Not found in known locations");
}

CheckResult RootDetector::checkMagiskFiles() {
    std::vector<std::string> found;
    for (const char* path : MAGISK_PATHS) {
        if (fileExists(path)) found.push_back(path);
    }
    if (!found.empty()) {
        std::string paths;
        for (size_t i = 0; i < found.size(); ++i) {
            if (i > 0) paths += ", ";
            paths += found[i];
        }
        return CheckResult("Magisk files", true, "Found: " + paths);
    }
    return CheckResult("Magisk files", false, "No Magisk files detected");
}

CheckResult RootDetector::checkSuExecution() {
    auto [success, output] = executeCommand("su -c id 2>&1", 2000);
    if (success && !output.empty()) {
        bool isRoot = output.find("uid=0") != std::string::npos ||
                      output.find("euid=0") != std::string::npos;
        return CheckResult("su execution", true,
            isRoot ? "Root access: " + output : "su works but not root: " + output);
    }
    return CheckResult("su execution", false, "su command unavailable");
}

CheckResult RootDetector::checkSystemProperties() {
    std::string roSecure, roDebuggable, roBuildTags, roBootVerified;
    std::vector<std::string> issues;

    getSystemProperty("ro.secure", roSecure);
    getSystemProperty("ro.debuggable", roDebuggable);
    getSystemProperty("ro.build.tags", roBuildTags);
    getSystemProperty("ro.boot.verifiedbootstate", roBootVerified);

    if (roSecure == "0") issues.push_back("ro.secure=0");
    if (roDebuggable == "1") issues.push_back("ro.debuggable=1");
    if (!roBuildTags.empty() && roBuildTags.find("test-keys") != std::string::npos) {
        issues.push_back("test-keys");
    }
    if (!roBootVerified.empty() && roBootVerified != "green") {
        issues.push_back("verified_boot=" + roBootVerified);
    }

    if (!issues.empty()) {
        std::string reason;
        for (size_t i = 0; i < issues.size(); ++i) {
            if (i > 0) reason += "; ";
            reason += issues[i];
        }
        return CheckResult("system properties", true, reason);
    }

    std::string props;
    if (!roSecure.empty()) props += "ro.secure=" + roSecure + " ";
    if (!roDebuggable.empty()) props += "ro.debuggable=" + roDebuggable;
    return CheckResult("system properties", false, "All clear. " + props);
}

CheckResult RootDetector::checkMounts() {
    std::string mounts;
    if (!readFile("/proc/mounts", mounts)) {
        readFile("/proc/self/mountinfo", mounts);
    }
    if (mounts.empty()) return CheckResult("mount points", false, "Cannot read mounts");

    bool systemRW = mounts.find("/system") != std::string::npos &&
                    (mounts.find("rw") != std::string::npos || mounts.find(",rw,") != std::string::npos);
    bool rootRW = mounts.find(" / ") != std::string::npos &&
                  (mounts.find(" rw") != std::string::npos || mounts.find(",rw,") != std::string::npos);

    if (systemRW || rootRW) {
        std::string reason;
        if (systemRW && rootRW) reason = "system and root mounted RW";
        else if (systemRW) reason = "/system mounted RW";
        else reason = "/ mounted RW";
        return CheckResult("mount points", true, reason);
    }
    return CheckResult("mount points", false, "Partitions mounted correctly");
}

CheckResult RootDetector::checkBuildTags() {
    std::string tags;
    if (!getSystemProperty("ro.build.tags", tags)) {
        std::string buildProp;
        if (readFile("/system/build.prop", buildProp)) {
            size_t pos = buildProp.find("ro.build.tags=");
            if (pos != std::string::npos) {
                size_t start = pos + 14;
                size_t end = buildProp.find("\n", start);
                tags = buildProp.substr(start, end - start);
                if (!tags.empty() && tags.back() == '\r') tags.pop_back();
            }
        }
    }
    if (tags.empty()) return CheckResult("build tags", false, "Cannot read build tags");
    if (tags.find("test-keys") != std::string::npos) {
        return CheckResult("build tags", true, "test-keys detected");
    }
    return CheckResult("build tags", false, "release-keys: " + tags);
}

CheckResult RootDetector::checkRootManagementApps() {
    const char* paths[] = {
        "/data/app/eu.chainfire.supersu*", "/data/app/com.topjohnwu.magisk*",
        "/data/su", "/su", "/system/app/Superuser.apk", "/system/app/SuperSU",
        "/system/xbin/daemonsu", "/system/xbin/sugote", "/system/xbin/sugote-debug",
        "/system/xbin/supolicy", "/system/bin/sugote", "/system/bin/magisk",
        "/system/etc/init.d/99SuperSUDaemon", "/system/etc/.magisk.version",
        "/cache/superuser.img"
    };
    std::vector<std::string> found;
    for (const char* path : paths) {
        std::string pathStr(path);
        if (pathStr.find('*') != std::string::npos) {
            if (fileExists(pathStr.substr(0, pathStr.find('*')).c_str())) found.push_back(pathStr);
        } else if (fileExists(path)) {
            found.push_back(pathStr);
        }
    }
    if (!found.empty()) {
        std::string reason;
        for (size_t i = 0; i < found.size() && i < 5; ++i) {
            if (i > 0) reason += ", ";
            reason += found[i];
        }
        if (found.size() > 5) reason += " +" + std::to_string(found.size() - 5) + " more";
        return CheckResult("root management apps", true, reason);
    }
    return CheckResult("root management apps", false, "No root apps detected");
}

CheckResult RootDetector::checkSelinuxStatus() {
    std::string status;
    getSystemProperty("ro.build.selinux", status);
    if (status.empty() && fileExists("/sys/fs/selinux/enforce")) {
        std::string enforce;
        if (readFile("/sys/fs/selinux/enforce", enforce)) {
            status = enforce.find("0") != std::string::npos ? "disabled" : "enforcing";
        }
    }
    if (status == "disabled") return CheckResult("SELinux status", true, "SELinux is permissive");
    if (!status.empty()) return CheckResult("SELinux status", false, "SELinux enforcing");
    return CheckResult("SELinux status", false, "Cannot determine status");
}

CheckResult RootDetector::checkSystemPaths() {
    const char* paths[] = {"/sbin", "/vendor/sbin", "/system/xbin",
                          "/system/bin/su", "/data/local/su", "/data/local/bin/su"};
    std::vector<std::string> found;
    for (const char* path : paths) {
        if (fileExists(path)) found.push_back(path);
    }
    if (!found.empty()) {
        std::string reason;
        for (size_t i = 0; i < found.size(); ++i) {
            if (i > 0) reason += ", ";
            reason += found[i];
        }
        return CheckResult("system paths", true, reason);
    }
    return CheckResult("system paths", false, "No suspicious paths");
}

CheckResult RootDetector::checkLsCommand() {
    const char* dirs[] = {"/data/root", "/data/su", "/sbin", "/system/app"};
    std::vector<std::string> accessible;
    for (const char* dir : dirs) {
        auto [success, output] = executeCommand(dir, 500);
        if (success && !output.empty() && output.find("Permission denied") == std::string::npos) {
            accessible.push_back(dir);
        }
    }
    if (!accessible.empty()) {
        std::string reason;
        for (size_t i = 0; i < accessible.size() && i < 3; ++i) {
            if (i > 0) reason += ", ";
            reason += accessible[i];
        }
        return CheckResult("ls command access", true, reason);
    }
    return CheckResult("ls command access", false, "Restricted dirs not accessible");
}

CheckResult RootDetector::checkSuBinaryPermissions() {
    const char* paths[] = {"/system/bin/su", "/system/xbin/su", "/sbin/su"};
    for (const char* path : paths) {
        struct stat st;
        if (stat(path, &st) == 0 && (st.st_mode & S_ISUID) && st.st_uid == 0) {
            return CheckResult("su binary permissions", true, std::string("SUID root: ") + path);
        }
    }
    return CheckResult("su binary permissions", false, "No dangerous SUID found");
}

CheckResult RootDetector::checkRWPartitions() {
    std::string mounts;
    if (!readFile("/proc/mounts", mounts)) {
        return CheckResult("RW partitions", false, "Cannot read mounts");
    }
    bool systemRW = false, rootRW = false;
    std::istringstream stream(mounts);
    std::string line;
    while (std::getline(stream, line)) {
        if (line.find("/system") != std::string::npos &&
            (line.find(" rw") != std::string::npos || line.find(",rw,") != std::string::npos)) {
            systemRW = true;
        }
        if (line.find(" / ") != std::string::npos && line.find(" / ") < 10 &&
            (line.find(" rw") != std::string::npos || line.find(",rw,") != std::string::npos)) {
            rootRW = true;
        }
    }
    if (systemRW || rootRW) {
        std::string reason = systemRW && rootRW ? "system and / mounted RW" :
                             systemRW ? "/system mounted RW" : "/ mounted RW";
        return CheckResult("RW partitions", true, reason);
    }
    return CheckResult("RW partitions", false, "All partitions RO");
}

CheckResult RootDetector::checkRootProcesses() {
    auto [success, output] = executeCommand("ps -A 2>/dev/null", 1000);
    if (!success) return CheckResult("root processes", false, "Cannot read processes");
    const char* processes[] = {"su daemon", "magiskd", "daemonsu", "superuser"};
    std::vector<std::string> found;
    for (const char* proc : processes) {
        if (output.find(proc) != std::string::npos) found.push_back(proc);
    }
    if (!found.empty()) {
        std::string reason;
        for (size_t i = 0; i < found.size(); ++i) {
            if (i > 0) reason += ", ";
            reason += found[i];
        }
        return CheckResult("root processes", true, reason);
    }
    return CheckResult("root processes", false, "No root processes");
}

CheckResult RootDetector::checkCustomRom() {
    std::string buildDisplay, buildFingerprint;
    getSystemProperty("ro.build.display.id", buildDisplay);
    getSystemProperty("ro.build.fingerprint", buildFingerprint);
    const char* roms[] = {"lineage", "pixelExperience", "crDroid", "evolution",
                          "arrowos", "havoc", "los", "resurrection", "xiaomi.eu", "flyme"};
    std::string search = buildDisplay + " " + buildFingerprint;
    std::transform(search.begin(), search.end(), search.begin(), ::tolower);
    for (const char* rom : roms) {
        if (search.find(rom) != std::string::npos) {
            return CheckResult("custom ROM", true, buildDisplay);
        }
    }
    return CheckResult("custom ROM", false, "Stock ROM");
}

}
