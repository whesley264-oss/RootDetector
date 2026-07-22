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

// Static member array definitions
constexpr const char* RootDetector::SU_PATHS[] = {
    "/system/bin/su",
    "/system/xbin/su",
    "/sbin/su",
    "/vendor/bin/su",
    "/system/su",
    "/data/local/bin/su",
    "/data/local/xbin/su",
    "/data/local/su"
};

constexpr const char* RootDetector::MAGISK_PATHS[] = {
    "/data/adb/magisk",
    "/data/adb/magisk.img",
    "/data/adb/magiskrc",
    "/system/etc/magisk",
    "/system/xbin/magisk",
    "/system/bin/magisk",
    "/sbin/magisk",
    "/data/app/com.topjohnwu.magisk*",
    "/data/app/*/com.topjohnwu.magisk*",
    "/system/app/Magisk.apk",
    "/system/app/Magisk",
    "/cache/magisk.log"
};

constexpr const char* RootDetector::ROOT_APP_PACKAGES[] = {
    "eu.chainfire.supersu",
    "com.topjohnwu.magisk",
    "com.koushikdutta.superuser",
    "com.noshufou.android.su",
    "com.noshufou.android.su.elite",
    "com.thirdparty.superuser",
    "com.yellowes.su",
    "com.kingroot.kinguser",
    "com.kingo.root",
    "com.smedialink.oneclickroot",
    "com.zhiqupk.root.global"
};

// ============================================================================
// File System Utilities
// ============================================================================

bool RootDetector::fileExists(const char* path) {
    if (path == nullptr) {
        return false;
    }
    return (access(path, F_OK) == 0);
}

bool RootDetector::readFile(const char* path, std::string& outContent) {
    if (path == nullptr) {
        return false;
    }

    std::ifstream file(path);
    if (!file.is_open()) {
        return false;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    outContent = buffer.str();
    return file.eof() || !buffer.fail();
}

bool RootDetector::getSystemProperty(const char* propName, std::string& outValue) {
    if (propName == nullptr) {
        return false;
    }

    // Use getprop command to read system properties
    std::string cmd = "getprop ";
    cmd += propName;

    FILE* pipe = popen(cmd.c_str(), "r");
    if (pipe == nullptr) {
        return false;
    }

    char buffer[256] = {0};
    if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        // Remove trailing newline
        size_t len = strlen(buffer);
        if (len > 0 && buffer[len - 1] == '\n') {
            buffer[len - 1] = '\0';
        }
        outValue = buffer;
    }

    int status = pclose(pipe);
    return status == 0 && !outValue.empty();
}

bool RootDetector::isRunningAsRoot() {
    return (geteuid() == 0);
}

std::pair<bool, std::string> RootDetector::executeCommand(
    const char* cmd, int timeoutMs) {

    std::pair<bool, std::string> result{false, ""};

    if (cmd == nullptr) {
        return result;
    }

    FILE* pipe = popen(cmd, "r");
    if (pipe == nullptr) {
        return result;
    }

    // Set pipe to non-blocking mode
    int fd = fileno(pipe);
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    std::string output;
    char buffer[256] = {0};

    // Simple timeout using alarm
    alarm(timeoutMs / 1000);

    while (true) {
        ssize_t bytesRead = read(fd, buffer, sizeof(buffer) - 1);
        if (bytesRead > 0) {
            buffer[bytesRead] = '\0';
            output += buffer;
        } else if (bytesRead == 0) {
            break;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (output.empty()) {
                    continue;
                }
                break;
            }
            break;
        }
    }

    alarm(0);  // Cancel alarm

    // Check if command exited successfully
    int status = pclose(pipe);
    result.first = (status == 0);
    result.second = output;

    return result;
}

// ============================================================================
// Main Detection Report
// ============================================================================

RootDetectionReport RootDetector::detectRoot() {
    RootDetectionReport report;

    // Run all checks
    report.checks.push_back(checkSuBinary());
    report.checks.push_back(checkMagiskFiles());
    report.checks.push_back(checkSuExecution());
    report.checks.push_back(checkSystemProperties());
    report.checks.push_back(checkMounts());
    report.checks.push_back(checkBuildTags());
    report.checks.push_back(checkRootManagementApps());
    report.checks.push_back(checkSelinuxStatus());
    report.checks.push_back(checkSystemPaths());

    // Determine overall root detection
    // If any check indicates root, mark as detected
    for (const auto& check : report.checks) {
        if (check.result) {
            report.rootDetected = true;
            break;
        }
    }

    return report;
}

// ============================================================================
// Individual Check Implementations
// ============================================================================

CheckResult RootDetector::checkSuBinary() {
    const char* foundPath = nullptr;

    for (const char* path : SU_PATHS) {
        if (fileExists(path)) {
            // Additional check: verify it's executable
            struct stat st;
            if (stat(path, &st) == 0 && (st.st_mode & S_IXUSR)) {
                foundPath = path;
                break;
            }
        }
    }

    if (foundPath != nullptr) {
        return CheckResult(
            "su binary",
            true,
            std::string("Found 'su' binary at: ") + foundPath
        );
    }

    return CheckResult(
        "su binary",
        false,
        "'su' binary not found in any known location"
    );
}

CheckResult RootDetector::checkMagiskFiles() {
    const char* foundPath = nullptr;
    std::vector<std::string> foundPaths;

    for (const char* path : MAGISK_PATHS) {
        if (fileExists(path)) {
            foundPaths.push_back(path);
            foundPath = path;  // Keep reference to first found path
        }
    }

    if (!foundPaths.empty()) {
        std::string pathsStr;
        for (size_t i = 0; i < foundPaths.size(); ++i) {
            if (i > 0) pathsStr += ", ";
            pathsStr += foundPaths[i];
        }
        return CheckResult(
            "Magisk files",
            true,
            "Magisk-related files/directories found: " + pathsStr
        );
    }

    return CheckResult(
        "Magisk files",
        false,
        "No Magisk-related files or directories found"
    );
}

CheckResult RootDetector::checkSuExecution() {
    // Try to execute 'su -c id' to see if su works and what user we are
    auto [success, output] = executeCommand("su -c id 2>&1", 2000);

    if (success && !output.empty()) {
        // Check if output indicates root (uid=0)
        if (output.find("uid=0") != std::string::npos ||
            output.find("euid=0") != std::string::npos) {
            return CheckResult(
                "su execution",
                true,
                "'su' command executed successfully with root privileges: " + output
            );
        }
        return CheckResult(
            "su execution",
            true,
            "'su' command executed but not as root: " + output
        );
    }

    return CheckResult(
        "su execution",
        false,
        "'su' command failed or not available"
    );
}

CheckResult RootDetector::checkSystemProperties() {
    std::string roSecure, roDebuggable, roBuildTags, roBootVerified;
    std::vector<std::string> indicators;

    getSystemProperty("ro.secure", roSecure);
    getSystemProperty("ro.debuggable", roDebuggable);
    getSystemProperty("ro.build.tags", roBuildTags);
    getSystemProperty("ro.boot.verifiedbootstate", roBootVerified);

    // Check ro.secure=0 indicates shell has root access
    if (roSecure == "0") {
        indicators.push_back("ro.secure=0 (root access enabled)");
    }

    // Check ro.debuggable=1 indicates debugging is enabled
    if (roDebuggable == "1") {
        indicators.push_back("ro.debuggable=1 (debug enabled)");
    }

    // Check for test-keys in build tags
    if (roBuildTags.find("test-keys") != std::string::npos) {
        indicators.push_back("ro.build.tags contains 'test-keys'");
    }

    // Check verified boot state
    if (roBootVerified == "orange" || roBootVerified == "unverified") {
        indicators.push_back("ro.boot.verifiedbootstate=" + roBootVerified);
    }

    if (!indicators.empty()) {
        std::string reason;
        for (size_t i = 0; i < indicators.size(); ++i) {
            if (i > 0) reason += "; ";
            reason += indicators[i];
        }
        return CheckResult("system properties", true, reason);
    }

    std::string allProps = "ro.secure=" + roSecure +
                           ", ro.debuggable=" + roDebuggable +
                           ", ro.build.tags=" + roBuildTags;
    return CheckResult(
        "system properties",
        false,
        "No suspicious system properties found. " + allProps
    );
}

CheckResult RootDetector::checkMounts() {
    std::string mountsContent, mountinfoContent;
    bool hasMounts = readFile("/proc/mounts", mountsContent);
    bool hasMountinfo = readFile("/proc/self/mountinfo", mountinfoContent);

    std::string content = mountsContent;
    if (hasMountinfo) {
        content += mountinfoContent;
    }

    if (!hasMounts && !hasMountinfo) {
        return CheckResult(
            "mount points",
            false,
            "Unable to read mount information files"
        );
    }

    std::vector<std::string> suspiciousMounts;

    // Check for system partition mounted as RW (should be RO on secure devices)
    if (content.find("/dev/block/system") != std::string::npos) {
        if (content.find("/system") != std::string::npos) {
            // Check if system is mounted RW
            size_t systemPos = content.find("/system");
            if (systemPos != std::string::npos) {
                std::string afterSystem = content.substr(systemPos, 200);
                if (afterSystem.find("rw") != std::string::npos &&
                    afterSystem.find("/system") < afterSystem.find(" ")) {
                    suspiciousMounts.push_back("System partition mounted as RW");
                }
            }
        }
    }

    // Check for RW mount on critical paths
    const char* criticalPaths[] = {
        "/system",
        "/sbin",
        "/vendor"
    };

    for (const char* path : criticalPaths) {
        std::string searchStr = std::string(path) + " ";
        size_t pos = content.find(searchStr);
        if (pos != std::string::npos) {
            std::string afterPath = content.substr(pos + strlen(path));
            // Extract mount options
            if (afterPath.find("rw") < afterPath.find(" ") ||
                (afterPath.find("rw,") != std::string::npos &&
                 afterPath.find("ro,") == std::string::npos)) {
                std::string indicator = std::string(path);
                indicator += " mounted RW";
                suspiciousMounts.push_back(indicator);
            }
        }
    }

    if (!suspiciousMounts.empty()) {
        std::string reason;
        for (size_t i = 0; i < suspiciousMounts.size(); ++i) {
            if (i > 0) reason += "; ";
            reason += suspiciousMounts[i];
        }
        return CheckResult("mount points", true, reason);
    }

    return CheckResult(
        "mount points",
        false,
        "No suspicious mount configurations detected"
    );
}

CheckResult RootDetector::checkBuildTags() {
    std::string buildTags;
    if (!getSystemProperty("ro.build.tags", buildTags)) {
        // Try reading directly from build.prop
        std::string buildProp;
        if (readFile("/system/build.prop", buildProp)) {
            size_t pos = buildProp.find("ro.build.tags=");
            if (pos != std::string::npos) {
                size_t start = pos + 14;
                size_t end = buildProp.find("\n", start);
                if (end == std::string::npos) end = buildProp.size();
                buildTags = buildProp.substr(start, end - start);
                // Remove any trailing carriage return
                if (!buildTags.empty() && buildTags.back() == '\r') {
                    buildTags.pop_back();
                }
            }
        }
    }

    if (buildTags.empty()) {
        return CheckResult(
            "build tags",
            false,
            "Unable to read build tags"
        );
    }

    if (buildTags.find("test-keys") != std::string::npos) {
        return CheckResult(
            "build tags",
            true,
            "Build tag 'test-keys' detected. This indicates a custom/unsigned build."
        );
    }

    return CheckResult(
        "build tags",
        false,
        "Build tags are release keys. Tags: " + buildTags
    );
}

CheckResult RootDetector::checkRootManagementApps() {
    // These paths are where root management apps store their data
    const char* appPaths[] = {
        "/data/app/eu.chainfire.supersu*",
        "/data/app/com.topjohnwu.magisk*",
        "/data/su",
        "/su",
        "/system/app/Superuser.apk",
        "/system/app/SuperSU",
        "/system/xbin/daemonsu",
        "/system/xbin/sugote",
        "/system/xbin/sugote-debug",
        "/system/xbin/supolicy",
        "/system/bin/sugote",
        "/system/bin/magisk",
        "/system/etc/init.d/99SuperSUDaemon",
        "/system/etc/.magisk.version",
        "/cache/superuser.img"
    };

    std::vector<std::string> foundApps;

    for (const char* path : appPaths) {
        // Handle wildcard patterns
        std::string pathStr(path);
        if (pathStr.find('*') != std::string::npos) {
            // For wildcard patterns, we need to check parent directory
            // Simplified: just check if the base path exists
            std::string basePath = pathStr.substr(0, pathStr.find('*'));
            if (fileExists(basePath.c_str())) {
                foundApps.push_back(pathStr);
            }
        } else if (fileExists(path)) {
            foundApps.push_back(pathStr);
        }
    }

    if (!foundApps.empty()) {
        std::string reason = "Root management app files detected: ";
        for (size_t i = 0; i < foundApps.size() && i < 5; ++i) {
            if (i > 0) reason += ", ";
            reason += foundApps[i];
        }
        if (foundApps.size() > 5) {
            reason += " and " + std::to_string(foundApps.size() - 5) + " more";
        }
        return CheckResult("root management apps", true, reason);
    }

    return CheckResult(
        "root management apps",
        false,
        "No root management app files detected"
    );
}

CheckResult RootDetector::checkSelinuxStatus() {
    std::string selinuxStatus;

    // Try to get SELinux status using getprop
    if (!getSystemProperty("ro.build.selinux", selinuxStatus)) {
        // Try reading from /sys/fs/selinux/enforce
        if (fileExists("/sys/fs/selinux/enforce")) {
            std::string enforce;
            if (readFile("/sys/fs/selinux/enforce", enforce)) {
                if (enforce.find("0") != std::string::npos) {
                    selinuxStatus = "disabled";
                } else {
                    selinuxStatus = "enforcing";
                }
            }
        }
    }

    if (selinuxStatus == "disabled" || selinuxStatus == "0") {
        return CheckResult(
            "SELinux status",
            true,
            "SELinux is disabled (permissive mode)"
        );
    }

    if (!selinuxStatus.empty()) {
        return CheckResult(
            "SELinux status",
            false,
            "SELinux is enabled and enforcing"
        );
    }

    return CheckResult(
        "SELinux status",
        false,
        "Unable to determine SELinux status"
    );
}

CheckResult RootDetector::checkSystemPaths() {
    // Check for suspicious directories and paths
    const char* suspiciousPaths[] = {
        "/sbin",
        "/vendor/sbin",
        "/system/xbin",
        "/system/bin/su",
        "/data/local/su",
        "/data/local/bin/su"
    };

    std::vector<std::string> foundSuspicious;

    for (const char* path : suspiciousPaths) {
        if (fileExists(path)) {
            foundSuspicious.push_back(path);
        }
    }

    if (!foundSuspicious.empty()) {
        std::string reason = "Suspicious system paths found: ";
        for (size_t i = 0; i < foundSuspicious.size(); ++i) {
            if (i > 0) reason += ", ";
            reason += foundSuspicious[i];
        }
        return CheckResult("system paths", true, reason);
    }

    return CheckResult(
        "system paths",
        false,
        "No suspicious system paths detected"
    );
}

} // namespace RootDetector
