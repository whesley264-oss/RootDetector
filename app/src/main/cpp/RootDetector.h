#ifndef ROOTDETECTOR_ROOTDETECTOR_H
#define ROOTDETECTOR_ROOTDETECTOR_H

#include <string>
#include <vector>
#include <utility>

/**
 * @file RootDetector.h
 * @brief Header file containing declarations for Android root detection.
 *
 * This file defines the data structures and function declarations
 * for detecting root access on Android devices.
 */

namespace RootDetector {

/**
 * @struct CheckResult
 * @brief Represents the result of a single root detection check.
 *
 * Each check has a name, a boolean result indicating success/failure,
 * and a reason explaining the outcome.
 */
struct CheckResult {
    std::string name;     ///< Name of the check performed
    bool result;          ///< true if check passed (root detected), false otherwise
    std::string reason;   ///< Human-readable explanation of the result

    CheckResult() : result(false) {}
    CheckResult(std::string n, bool r, std::string msg)
        : name(std::move(n)), result(r), reason(std::move(msg)) {}
};

/**
 * @struct RootDetectionReport
 * @brief Contains the complete root detection report.
 *
 * Aggregates all individual check results and provides an overall
 * root detection status.
 */
struct RootDetectionReport {
    bool rootDetected;    ///< true if any root indicator was found
    std::vector<CheckResult> checks;  ///< List of all performed checks

    RootDetectionReport() : rootDetected(false) {}
};

/**
 * @class RootDetector
 * @brief Main class for detecting root access on Android devices.
 *
 * Provides various methods to check for common root indicators
 * including binary files, system properties, mount points, and build tags.
 */
class RootDetector {
public:
    /**
     * @brief Default constructor.
     */
    RootDetector() = default;

    /**
     * @brief Virtual destructor for proper cleanup in derived classes.
     */
    virtual ~RootDetector() = default;

    /**
     * @brief Runs all root detection checks and returns a comprehensive report.
     * @return RootDetectionReport containing all check results.
     */
    RootDetectionReport detectRoot();

    /**
     * @brief Checks for the existence of 'su' binary in common locations.
     * @return CheckResult with the outcome of the check.
     */
    CheckResult checkSuBinary();

    /**
     * @brief Checks for files and directories related to Magisk.
     * @return CheckResult with the outcome of the check.
     */
    CheckResult checkMagiskFiles();

    /**
     * @brief Attempts to execute the 'su' command and verify its response.
     * @return CheckResult with the outcome of the check.
     */
    CheckResult checkSuExecution();

    /**
     * @brief Reads and analyzes system properties for root indicators.
     * @return CheckResult with the outcome of the check.
     */
    CheckResult checkSystemProperties();

    /**
     * @brief Checks mount points for suspicious configurations.
     * @return CheckResult with the outcome of the check.
     */
    CheckResult checkMounts();

    /**
     * @brief Detects test-keys in build tags.
     * @return CheckResult with the outcome of the check.
     */
    CheckResult checkBuildTags();

    /**
     * @brief Checks for root management apps (Superuser, KingRoot, etc.).
     * @return CheckResult with the outcome of the check.
     */
    CheckResult checkRootManagementApps();

    /**
     * @brief Checks for dangerous SELinux statuses.
     * @return CheckResult with the outcome of the check.
     */
    CheckResult checkSelinuxStatus();

    /**
     * @brief Checks for specific system paths that may indicate root.
     * @return CheckResult with the outcome of the check.
     */
    CheckResult checkSystemPaths();

private:
    /**
     * @brief Common paths where 'su' binary might exist.
     */
    static constexpr const char* SU_PATHS[];

    /**
     * @brief Magisk-related files and directories.
     */
    static constexpr const char* MAGISK_PATHS[];

    /**
     * @brief Root management application package names.
     */
    static constexpr const char* ROOT_APP_PACKAGES[];

    /**
     * @brief Checks if a file exists at the given path.
     * @param path Path to check.
     * @return true if file exists, false otherwise.
     */
    static bool fileExists(const char* path);

    /**
     * @brief Reads a system property from /system/build.prop.
     * @param propName Name of the property to read.
     * @param outValue Output string to store the property value.
     * @return true if property was found, false otherwise.
     */
    static bool getSystemProperty(const char* propName, std::string& outValue);

    /**
     * @brief Reads file content into a string.
     * @param path Path to the file to read.
     * @param outContent Output string to store file content.
     * @return true if file was read successfully, false otherwise.
     */
    static bool readFile(const char* path, std::string& outContent);

    /**
     * @brief Checks if the process is running with root privileges.
     * @return true if running as root, false otherwise.
     */
    static bool isRunningAsRoot();

    /**
     * @brief Safely executes a command and captures its output.
     * @param cmd Command to execute.
     * @param timeoutMs Timeout in milliseconds.
     * @return Pair of (success, output).
     */
    static std::pair<bool, std::string> executeCommand(
        const char* cmd, int timeoutMs = 1000);
};

} // namespace RootDetector

#endif // ROOTDETECTOR_ROOTDETECTOR_H
