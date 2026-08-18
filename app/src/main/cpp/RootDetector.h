#ifndef ROOTDETECTOR_ROOTDETECTOR_H
#define ROOTDETECTOR_ROOTDETECTOR_H

#include <string>
#include <vector>
#include <utility>

namespace RootDetector {

struct CheckResult {
    std::string name;
    bool result;
    std::string reason;

    CheckResult() : result(false) {}
    CheckResult(std::string n, bool r, std::string msg)
        : name(std::move(n)), result(r), reason(std::move(msg)) {}
};

struct RootDetectionReport {
    bool rootDetected;
    int totalChecks;
    int detectedCount;
    std::vector<CheckResult> checks;
    RootDetectionReport() : rootDetected(false), totalChecks(0), detectedCount(0) {}
};

class RootDetector {
public:
    RootDetector() = default;
    ~RootDetector() = default;

    RootDetectionReport detectRoot();

    // --- Binário su e execução ---
    CheckResult checkSuBinary();
    CheckResult checkSuExecution();
    CheckResult checkSuBinaryPermissions();
    CheckResult checkSuEnvPath();

    // --- Magisk / KernelSU / Zygisk ---
    CheckResult checkMagiskFiles();
    CheckResult checkMagiskDaemon();
    CheckResult checkKernelSU();
    CheckResult checkZygiskDenyList();
    CheckResult checkMagiskHide();

    // --- Apps de gerenciamento de root ---
    CheckResult checkRootManagementApps();

    // --- Propriedades do sistema / build ---
    CheckResult checkSystemProperties();
    CheckResult checkBuildTags();
    CheckResult checkCustomRom();

    // --- Bootloader / verificação de boot ---
    CheckResult checkBootloader();
    CheckResult checkVerifiedBoot();

    // --- Debug / ADB ---
    CheckResult checkDebuggerAttached();
    CheckResult checkAdbEnabled();
    CheckResult checkDevelopmentSettings();

    // --- Integridade do sistema ---
    CheckResult checkSelinuxStatus();
    CheckResult checkMounts();
    CheckResult checkRWPartitions();
    CheckResult checkSystemPaths();
    CheckResult checkRootProcesses();
    CheckResult checkLsCommand();

    // --- Hooks / instrumentação ---
    CheckResult checkFridaHooks();
    CheckResult checkXposedFramework();
    CheckResult checkEmulator();

private:
    static bool fileExists(const char* path);
    static bool dirExists(const char* path);
    static bool globExists(const std::string& pattern);
    static bool getSystemProperty(const char* name, std::string& out);
    static bool readFile(const char* path, std::string& out);
    static bool isRunningAsRoot();
    static bool processIsTraced();
    static std::pair<bool, std::string> executeCommand(const char* cmd, int timeoutMs = 1000);
};

}

#endif
