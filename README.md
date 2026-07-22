# RootDetector

Android root detection application with native C++ core. The app provides a simple interface with a single button to trigger all root detection checks.

## Structure

```
rootdetector/
├── app/
│   ├── src/main/
│   │   ├── cpp/           # C++ NDK code
│   │   │   ├── RootDetector.h
│   │   │   ├── RootDetector.cpp
│   │   │   ├── JNI.cpp
│   │   │   └── CMakeLists.txt
│   │   ├── java/          # Kotlin interface
│   │   │   └── MainActivity.kt
│   │   └── res/           # Android resources
│   └── build.gradle.kts
├── build.gradle.kts
└── settings.gradle.kts
```

## Detection Methods

The application performs the following checks when the CHECK button is pressed:

1. **su binary** - Searches common paths for the 'su' binary (/system/bin/su, /system/xbin/su, etc.)

2. **Magisk files** - Detects Magisk-related files and directories in the system

3. **su execution** - Attempts to execute 'su -c id' to verify if superuser access works

4. **System properties** - Checks ro.secure, ro.debuggable, ro.build.tags for dangerous values

5. **Mount points** - Analyzes /proc/mounts and /proc/self/mountinfo for suspicious configurations

6. **Build tags** - Detects 'test-keys' in build tags, indicating custom/unsigned builds

7. **Root management apps** - Searches for SuperSU, Magisk, KingRoot and other root app files

8. **SELinux status** - Checks if SELinux is disabled/permissive

9. **System paths** - Verifies suspicious system paths like /sbin, /data/local/su

10. **ls command access** - Attempts to list restricted directories (/data/root, /sbin, /system/app)

11. **su binary permissions** - Checks if su binary has SUID bit set with root ownership

12. **RW partitions** - Verifies if /system or / are mounted as RW (should be RO)

13. **Root processes** - Scans running processes for root-related daemons (magiskd, daemonsu)

14. **Custom ROM** - Detects custom ROM indicators in build display ID and fingerprint

## Building

The project uses GitHub Actions for CI/CD. Builds are triggered on push and pull requests to main branch.

Debug and release APKs are generated and available as workflow artifacts.

## Requirements

- Android Studio with NDK support
- Android SDK 34
- NDK version as specified in CMakeLists.txt
- CMake 3.22+
- C++17

## Native Library

The C++ core exposes the following JNI functions:

- `Java_com_rootdetector_app_MainActivity_nativeDetectRoot()` - Runs all checks and returns JSON report
- `Java_com_rootdetector_app_MainActivity_nativeGetVersion()` - Returns library version

The JSON response format:

```json
{
  "rootDetected": true,
  "checks": [
    {
      "name": "su binary",
      "result": true,
      "reason": "Found 'su' binary at: /system/xbin/su"
    }
  ]
}
```

## CI/CD

GitHub Actions workflow is configured in `.github/workflows/android.yml`:
- Runs on every push and pull request to main
- Builds both debug and release APKs
- Uploads artifacts for download

## License

MIT
