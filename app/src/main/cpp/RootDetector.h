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
    std::vector<CheckResult> checks;
    RootDetectionReport() : rootDetected(false) {}
};

class RootDetector {
public:
    RootDetector() = default;
    ~RootDetector() = default;

    RootDetectionReport detectRoot();

    CheckResult checkSuBinary();
    CheckResult checkMagiskFiles();
    CheckResult checkSuExecution();
    CheckResult checkSystemProperties();
    CheckResult checkMounts();
    CheckResult checkBuildTags();
    CheckResult checkRootManagementApps();
    CheckResult checkSelinuxStatus();
    CheckResult checkSystemPaths();
    CheckResult checkLsCommand();
    CheckResult checkSuBinaryPermissions();
    CheckResult checkRWPartitions();
    CheckResult checkRootProcesses();
    CheckResult checkCustomRom();

private:
    static bool fileExists(const char* path);
    static bool getSystemProperty(const char* name, std::string& out);
    static bool readFile(const char* path, std::string& out);
    static bool isRunningAsRoot();
    static std::pair<bool, std::string> executeCommand(const char* cmd, int timeoutMs = 1000);
};

}

#endif
