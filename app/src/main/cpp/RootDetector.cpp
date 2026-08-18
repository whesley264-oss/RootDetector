#include "RootDetector.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

namespace RootDetector {

namespace {

constexpr const char* SU_PATHS[] = {
    "/system/bin/su", "/system/xbin/su", "/sbin/su", "/vendor/bin/su",
    "/system/su", "/data/local/bin/su", "/data/local/xbin/su", "/data/local/su",
    "/su/bin/su", "/system/sbin/su"
};

constexpr const char* MAGISK_PATHS[] = {
    "/data/adb/magisk", "/data/adb/magisk.img", "/data/adb/magiskrc",
    "/data/adb/modules", "/system/etc/magisk", "/system/xbin/magisk",
    "/system/bin/magisk", "/sbin/magisk", "/system/app/Magisk.apk",
    "/system/app/Magisk", "/cache/magisk.log", "/data/adb/magisk_busybox",
    "/data/adb/ksu"
};

constexpr const char* KSU_PATHS[] = {
    "/data/adb/ksu", "/data/adb/ksud", "/data/adb/ap/kernelsu",
    "/data/adb/ksu/bin/ksud", "/system/bin/ksud", "/debug/ksu"
};

constexpr const char* ROOT_APP_PACKAGES[] = {
    "eu.chainfire.supersu", "com.topjohnwu.magisk", "com.koushikdutta.superuser",
    "com.noshufou.android.su", "com.noshufou.android.su.elite", "com.thirdparty.superuser",
    "com.yellowes.su", "com.kingroot.kinguser", "com.kingo.root",
    "com.smedialink.oneclickroot", "com.zhiqupk.root.global", "me.weber.frida.server"
};

constexpr const char* ROOT_PROCESSES[] = {
    "su daemon", "magiskd", "daemonsu", "superuser", "ksud", "ksu_daemon",
    "frida-server", "frida-server-"
};

constexpr const char* CUSTOM_ROMS[] = {
    "lineage", "pixelexperience", "crdroid", "evolution",
    "arrowos", "havoc", "los", "resurrection", "xiaomi.eu", "flyme",
    "cyanogen", "OmniROM", "Slim", "AICP", "Paranoid"
};

constexpr const char* EMULATOR_INDICATORS[] = {
    "google_sdk", "sdk_gphone", "generic_x86", "generic_x64", "vbox", "genymotion",
    "nox", "bluestacks", "ttvm", "ldplayer", "mumu", "ro.kernel.qemu"
};

constexpr const char* XPOSED_PATHS[] = {
    "/system/framework/XposedBridge.jar", "/system/lib/libxposed_art.so",
    "/system/bin/app_process64_xposed", "/system/bin/app_process32_xposed",
    "/data/app/de.robv.android.xposed*", "/system/etc/init.d/99xposed",
    "/sbin/magiskpolicy", "/data/adb/lspd"
};

constexpr const char* SU_ENV_DIRS[] = {
    "/system/bin", "/system/xbin", "/sbin", "/vendor/bin",
    "/system/sbin", "/su/bin", "/data/local/bin", "/data/local/xbin"
};

std::string join(const std::vector<std::string>& v, const std::string& sep) {
    std::string out;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i > 0) out += sep;
        out += v[i];
    }
    return out;
}

}

bool RootDetector::fileExists(const char* path) {
    return path != nullptr && access(path, F_OK) == 0;
}

bool RootDetector::dirExists(const char* path) {
    if (!path) return false;
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

bool RootDetector::globExists(const std::string& pattern) {
    if (pattern.empty()) return false;
    size_t star = pattern.find('*');
    if (star == std::string::npos) return fileExists(pattern.c_str());

    size_t slash = pattern.rfind('/', star);
    std::string dirPath = (slash == std::string::npos) ? "." : pattern.substr(0, slash);
    std::string prefix = pattern.substr(slash + 1, star - slash - 1);
    std::string suffix = (star + 1 < pattern.size()) ? pattern.substr(star + 1) : "";

    DIR* dir = opendir(dirPath.c_str());
    if (!dir) return false;

    struct dirent* entry;
    bool found = false;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        if (name == "." || name == "..") continue;
        if (name.size() >= prefix.size() + suffix.size() &&
            name.compare(0, prefix.size(), prefix) == 0 &&
            name.compare(name.size() - suffix.size(), suffix.size(), suffix) == 0) {
            found = true;
            break;
        }
    }
    closedir(dir);
    return found;
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

bool RootDetector::processIsTraced() {
    std::string status;
    if (!readFile("/proc/self/status", status)) return false;
    const std::string key = "TracerPid:";
    size_t pos = status.find(key);
    if (pos == std::string::npos) return false;
    size_t start = pos + key.size();
    while (start < status.size() && (status[start] == ' ' || status[start] == '\t')) ++start;
    if (start >= status.size()) return false;
    return status[start] != '0';
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

    // su binary e execução
    report.checks.push_back(checkSuBinary());
    report.checks.push_back(checkSuExecution());
    report.checks.push_back(checkSuBinaryPermissions());
    report.checks.push_back(checkSuEnvPath());

    // Magisk / KernelSU / Zygisk
    report.checks.push_back(checkMagiskFiles());
    report.checks.push_back(checkMagiskDaemon());
    report.checks.push_back(checkKernelSU());
    report.checks.push_back(checkZygiskDenyList());
    report.checks.push_back(checkMagiskHide());

    // Apps de root
    report.checks.push_back(checkRootManagementApps());

    // Propriedades / build
    report.checks.push_back(checkSystemProperties());
    report.checks.push_back(checkBuildTags());
    report.checks.push_back(checkCustomRom());

    // Bootloader / boot verificado
    report.checks.push_back(checkBootloader());
    report.checks.push_back(checkVerifiedBoot());

    // Debug / ADB
    report.checks.push_back(checkDebuggerAttached());
    report.checks.push_back(checkAdbEnabled());
    report.checks.push_back(checkDevelopmentSettings());

    // Integridade do sistema
    report.checks.push_back(checkSelinuxStatus());
    report.checks.push_back(checkMounts());
    report.checks.push_back(checkRWPartitions());
    report.checks.push_back(checkSystemPaths());
    report.checks.push_back(checkRootProcesses());
    report.checks.push_back(checkLsCommand());

    // Hooks / instrumentação
    report.checks.push_back(checkFridaHooks());
    report.checks.push_back(checkXposedFramework());
    report.checks.push_back(checkEmulator());

    report.totalChecks = static_cast<int>(report.checks.size());
    for (const auto& check : report.checks) {
        if (check.result) {
            report.detectedCount++;
            report.rootDetected = true;
        }
    }
    return report;
}

// ---------------------------------------------------------------------------
// su binary e execução
// ---------------------------------------------------------------------------

CheckResult RootDetector::checkSuBinary() {
    for (const char* path : SU_PATHS) {
        struct stat st;
        if (stat(path, &st) == 0 && (st.st_mode & S_IXUSR)) {
            return CheckResult("su binary", true, std::string("Found at: ") + path);
        }
    }
    return CheckResult("su binary", false, "Not found in known locations");
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

CheckResult RootDetector::checkSuBinaryPermissions() {
    const char* paths[] = {"/system/bin/su", "/system/xbin/su", "/sbin/su", "/vendor/bin/su"};
    for (const char* path : paths) {
        struct stat st;
        if (stat(path, &st) == 0 && (st.st_mode & S_ISUID) && st.st_uid == 0) {
            return CheckResult("su binary permissions", true, std::string("SUID root: ") + path);
        }
    }
    return CheckResult("su binary permissions", false, "No dangerous SUID found");
}

CheckResult RootDetector::checkSuEnvPath() {
    const char* path = getenv("PATH");
    if (!path) return CheckResult("su in PATH", false, "PATH not set");
    std::string pathStr(path);
    std::istringstream stream(pathStr);
    std::string dir;
    std::vector<std::string> found;
    while (std::getline(stream, dir, ':')) {
        if (dir.empty()) continue;
        std::string candidate = dir + "/su";
        struct stat st;
        if (stat(candidate.c_str(), &st) == 0 && (st.st_mode & S_IXUSR)) {
            found.push_back(candidate);
        }
    }
    if (!found.empty()) {
        return CheckResult("su in PATH", true, join(found, ", "));
    }
    return CheckResult("su in PATH", false, "su not in PATH");
}

// ---------------------------------------------------------------------------
// Magisk / KernelSU / Zygisk
// ---------------------------------------------------------------------------

CheckResult RootDetector::checkMagiskFiles() {
    std::vector<std::string> found;
    for (const char* path : MAGISK_PATHS) {
        if (fileExists(path)) found.push_back(path);
    }
    if (globExists("/data/app/*/com.topjohnwu.magisk*")) found.push_back("com.topjohnwu.magisk app");
    if (!found.empty()) {
        return CheckResult("Magisk files", true, "Found: " + join(found, ", "));
    }
    return CheckResult("Magisk files", false, "No Magisk files detected");
}

CheckResult RootDetector::checkMagiskDaemon() {
    std::string magiskrc;
    if (readFile("/proc/self/mountinfo", magiskrc)) {
        if (magiskrc.find("magisk") != std::string::npos ||
            magiskrc.find("/sbin/.magisk") != std::string::npos) {
            return CheckResult("Magisk daemon", true, "Magisk mount namespace detected");
        }
    }
    if (fileExists("/proc/1/root/magisk") || fileExists("/proc/1/root/.magisk")) {
        return CheckResult("Magisk daemon", true, "Magisk in init namespace");
    }
    auto [success, output] = executeCommand("pgrep -x magiskd 2>/dev/null", 1000);
    if (success && !output.empty()) {
        return CheckResult("Magisk daemon", true, "magiskd running");
    }
    return CheckResult("Magisk daemon", false, "No Magisk daemon found");
}

CheckResult RootDetector::checkKernelSU() {
    std::vector<std::string> found;
    for (const char* path : KSU_PATHS) {
        if (fileExists(path)) found.push_back(path);
    }
    if (!found.empty()) {
        return CheckResult("KernelSU", true, "Found: " + join(found, ", "));
    }
    std::string ksuVersion;
    if (getSystemProperty("ro.kernel.version", ksuVersion)) {
        std::string lower = ksuVersion;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        if (lower.find("kernelsu") != std::string::npos || lower.find("ksu") != std::string::npos) {
            return CheckResult("KernelSU", true, "KernelSU in kernel version");
        }
    }
    return CheckResult("KernelSU", false, "No KernelSU detected");
}

CheckResult RootDetector::checkZygiskDenyList() {
    if (fileExists("/data/adb/magisk/db") || fileExists("/data/adb/magisk/.magisk")) {
        return CheckResult("Zygisk deny list", true, "Magisk db/structure present");
    }
    std::string props;
    std::string propValues;
    if (readFile("/data/adb/magisk.db", props) || readFile("/data/adb/magisk/config", propValues)) {
        return CheckResult("Zygisk deny list", true, "Magisk config present");
    }
    return CheckResult("Zygisk deny list", false, "No Zygisk deny list evidence");
}

CheckResult RootDetector::checkMagiskHide() {
    std::string mounts;
    if (readFile("/proc/self/mounts", mounts)) {
        if (mounts.find("magisk") != std::string::npos ||
            mounts.find("/sbin/.magisk") != std::string::npos) {
            return CheckResult("MagiskHide", true, "Magisk mount detected");
        }
    }
    if (fileExists("/sbin/.magisk") || fileExists("/debug/.magisk")) {
        return CheckResult("MagiskHide", true, "MagiskHide directory present");
    }
    return CheckResult("MagiskHide", false, "No MagiskHide detected");
}

// ---------------------------------------------------------------------------
// Apps de gerenciamento de root
// ---------------------------------------------------------------------------

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
            if (globExists(pathStr)) found.push_back(pathStr);
        } else if (fileExists(path)) {
            found.push_back(pathStr);
        }
    }
    if (!found.empty()) {
        std::string reason = join(found, ", ");
        if (found.size() > 5) reason += " +" + std::to_string(found.size() - 5) + " more";
        return CheckResult("root management apps", true, reason);
    }
    return CheckResult("root management apps", false, "No root apps detected");
}

// ---------------------------------------------------------------------------
// Propriedades do sistema / build
// ---------------------------------------------------------------------------

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
        return CheckResult("system properties", true, join(issues, "; "));
    }

    std::string props;
    if (!roSecure.empty()) props += "ro.secure=" + roSecure + " ";
    if (!roDebuggable.empty()) props += "ro.debuggable=" + roDebuggable;
    return CheckResult("system properties", false, "All clear. " + props);
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

CheckResult RootDetector::checkCustomRom() {
    std::string buildDisplay, buildFingerprint;
    getSystemProperty("ro.build.display.id", buildDisplay);
    getSystemProperty("ro.build.fingerprint", buildFingerprint);
    std::string search = buildDisplay + " " + buildFingerprint;
    std::transform(search.begin(), search.end(), search.begin(), ::tolower);
    for (const char* rom : CUSTOM_ROMS) {
        std::string romLower(rom);
        std::transform(romLower.begin(), romLower.end(), romLower.begin(), ::tolower);
        if (search.find(romLower) != std::string::npos) {
            return CheckResult("custom ROM", true, buildDisplay);
        }
    }
    return CheckResult("custom ROM", false, "Stock ROM");
}

// ---------------------------------------------------------------------------
// Bootloader / boot verificado
// ---------------------------------------------------------------------------

CheckResult RootDetector::checkBootloader() {
    std::string bootloaderStatus, verityMode;
    getSystemProperty("ro.boot.flash.locked", bootloaderStatus);
    getSystemProperty("ro.boot.veritymode", verityMode);
    std::vector<std::string> issues;
    if (!bootloaderStatus.empty() && bootloaderStatus != "1") {
        issues.push_back("flash.locked=" + bootloaderStatus);
    }
    if (!verityMode.empty() && verityMode.find("enforcing") == std::string::npos) {
        issues.push_back("veritymode=" + verityMode);
    }
    if (!issues.empty()) {
        return CheckResult("bootloader", true, join(issues, "; "));
    }
    return CheckResult("bootloader", false,
        "locked=" + (bootloaderStatus.empty() ? std::string("unknown") : bootloaderStatus));
}

CheckResult RootDetector::checkVerifiedBoot() {
    std::string state, color;
    getSystemProperty("ro.boot.verifiedbootstate", state);
    getSystemProperty("ro.boot.veritymode", color);
    if (!state.empty() && state != "green") {
        return CheckResult("verified boot", true, "boot state=" + state);
    }
    if (!color.empty() && color.find("enforcing") == std::string::npos) {
        return CheckResult("verified boot", true, "verity=" + color);
    }
    return CheckResult("verified boot", false,
        "state=" + (state.empty() ? std::string("green") : state));
}

// ---------------------------------------------------------------------------
// Debug / ADB
// ---------------------------------------------------------------------------

CheckResult RootDetector::checkDebuggerAttached() {
    if (processIsTraced()) {
        return CheckResult("debugger", true, "Process is being traced (ptrace)");
    }
    std::string status;
    if (readFile("/proc/self/status", status)) {
        size_t pos = status.find("TracerPid:");
        if (pos != std::string::npos) {
            size_t start = pos + 10;
            while (start < status.size() && std::isspace(static_cast<unsigned char>(status[start]))) ++start;
            if (start < status.size() && status[start] != '0') {
                return CheckResult("debugger", true, "TracerPid != 0");
            }
        }
    }
    return CheckResult("debugger", false, "No debugger attached");
}

CheckResult RootDetector::checkAdbEnabled() {
    std::string adbPort, secure;
    getSystemProperty("service.adb.tcp.port", adbPort);
    getSystemProperty("ro.secure", secure);
    std::string settings;
    readFile("/data/misc/property/persist.sys.usb.config", settings);
    if (!adbPort.empty()) {
        return CheckResult("ADB", true, "ADB TCP port set: " + adbPort);
    }
    if (settings.find("adb") != std::string::npos) {
        return CheckResult("ADB", true, "USB config includes adb: " + settings);
    }
    std::string globalSettings;
    if (readFile("/data/system/users/0/settings_global.xml", globalSettings)) {
        if (globalSettings.find("adb_enabled\">1") != std::string::npos ||
            globalSettings.find("adb_enabled=1") != std::string::npos) {
            return CheckResult("ADB", true, "ADB enabled in settings");
        }
    }
    return CheckResult("ADB", false, "ADB not detected");
}

CheckResult RootDetector::checkDevelopmentSettings() {
    std::string roDebuggable, devSettings;
    getSystemProperty("ro.debuggable", roDebuggable);
    std::vector<std::string> issues;
    if (roDebuggable == "1") issues.push_back("ro.debuggable=1");
    if (readFile("/data/system/users/0/settings_global.xml", devSettings)) {
        if (devSettings.find("development_settings_enabled\">1") != std::string::npos ||
            devSettings.find("adb_enabled\">1") != std::string::npos) {
            issues.push_back("dev settings on");
        }
    }
    if (!issues.empty()) {
        return CheckResult("development settings", true, join(issues, "; "));
    }
    return CheckResult("development settings", false, "Development settings off");
}

// ---------------------------------------------------------------------------
// Integridade do sistema
// ---------------------------------------------------------------------------

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

CheckResult RootDetector::checkSystemPaths() {
    const char* paths[] = {"/sbin", "/vendor/sbin", "/system/xbin",
                          "/system/bin/su", "/data/local/su", "/data/local/bin/su"};
    std::vector<std::string> found;
    for (const char* path : paths) {
        if (fileExists(path)) found.push_back(path);
    }
    if (!found.empty()) {
        return CheckResult("system paths", true, join(found, ", "));
    }
    return CheckResult("system paths", false, "No suspicious paths");
}

CheckResult RootDetector::checkRootProcesses() {
    auto [success, output] = executeCommand("ps -A 2>/dev/null", 1000);
    if (!success) return CheckResult("root processes", false, "Cannot read processes");
    std::vector<std::string> found;
    for (const char* proc : ROOT_PROCESSES) {
        if (output.find(proc) != std::string::npos) found.push_back(proc);
    }
    if (!found.empty()) {
        return CheckResult("root processes", true, join(found, ", "));
    }
    return CheckResult("root processes", false, "No root processes");
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
        return CheckResult("ls command access", true, join(accessible, ", "));
    }
    return CheckResult("ls command access", false, "Restricted dirs not accessible");
}

// ---------------------------------------------------------------------------
// Hooks / instrumentação
// ---------------------------------------------------------------------------

CheckResult RootDetector::checkFridaHooks() {
    std::vector<std::string> found;
    const char* fridaPaths[] = {
        "/data/local/tmp/frida-server", "/data/local/tmp/frida-server-",
        "/system/bin/frida-server", "/sbin/frida-server",
        "/data/local/tmp/re.frida.server"
    };
    for (const char* path : fridaPaths) {
        std::string p(path);
        if (p.find('*') != std::string::npos) {
            if (globExists(p)) found.push_back(path);
        } else if (fileExists(path)) {
            found.push_back(path);
        }
    }
    auto [success, output] = executeCommand("ps -A 2>/dev/null", 1000);
    if (success && (output.find("frida-server") != std::string::npos ||
                    output.find("frida-") != std::string::npos)) {
        found.push_back("frida process");
    }
    std::string maps;
    if (readFile("/proc/self/maps", maps)) {
        if (maps.find("frida") != std::string::npos ||
            maps.find("gum-js-loop") != std::string::npos ||
            maps.find("linjector") != std::string::npos) {
            found.push_back("frida in maps");
        }
    }
    if (!found.empty()) {
        return CheckResult("Frida hooks", true, join(found, ", "));
    }
    return CheckResult("Frida hooks", false, "No Frida detected");
}

CheckResult RootDetector::checkXposedFramework() {
    std::vector<std::string> found;
    for (const char* path : XPOSED_PATHS) {
        std::string p(path);
        if (p.find('*') != std::string::npos) {
            if (globExists(p)) found.push_back(path);
        } else if (fileExists(path)) {
            found.push_back(path);
        }
    }
    std::string props;
    getSystemProperty("init.svc.zygote", props);
    std::string maps;
    if (readFile("/proc/self/maps", maps)) {
        if (maps.find("XposedBridge") != std::string::npos ||
            maps.find("xposed") != std::string::npos ||
            maps.find("LSPosed") != std::string::npos ||
            maps.find("lspd") != std::string::npos) {
            found.push_back("Xposed in maps");
        }
    }
    if (!found.empty()) {
        return CheckResult("Xposed framework", true, join(found, ", "));
    }
    return CheckResult("Xposed framework", false, "No Xposed detected");
}

CheckResult RootDetector::checkEmulator() {
    std::string fingerprint, model, product, brand, device, hardware;
    getSystemProperty("ro.build.fingerprint", fingerprint);
    getSystemProperty("ro.product.model", model);
    getSystemProperty("ro.product.name", product);
    getSystemProperty("ro.product.brand", brand);
    getSystemProperty("ro.product.device", device);
    getSystemProperty("ro.hardware", hardware);
    std::string search = fingerprint + " " + model + " " + product + " " + brand +
                         " " + device + " " + hardware;
    std::transform(search.begin(), search.end(), search.begin(), ::tolower);
    std::vector<std::string> found;
    for (const char* ind : EMULATOR_INDICATORS) {
        std::string indLower(ind);
        std::transform(indLower.begin(), indLower.end(), indLower.begin(), ::tolower);
        if (search.find(indLower) != std::string::npos) {
            found.push_back(ind);
        }
    }
    if (fileExists("/dev/qemu_pipe") || fileExists("/dev/socket/qemud") ||
        fileExists("/dev/qemu_trace")) {
        found.push_back("qemu device");
    }
    std::string qemu;
    getSystemProperty("ro.kernel.qemu", qemu);
    if (qemu == "1") found.push_back("ro.kernel.qemu=1");
    if (!found.empty()) {
        return CheckResult("emulator", true, join(found, ", "));
    }
    return CheckResult("emulator", false, "Running on real device");
}

}
