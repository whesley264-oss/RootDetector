# RootDetector

Android root detection application with native C++ core.

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
│   │   └── res/           # Android resources
│   └── build.gradle.kts
├── build.gradle.kts
└── settings.gradle.kts
```

## Detection Methods

- su binary presence in common paths
- Magisk files and directories
- Root management apps (SuperSU, Magisk, KingRoot, etc.)
- Dangerous system properties (ro.secure, ro.debuggable, etc.)
- Mount points and partition permissions
- Build tags (test-keys detection)
- SELinux status

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

The C++ core exposes a single JNI function:

```
Java_com_rootdetector_app_RootDetector_nativeDetectRoot()
```

Returns a JSON report with all detection results.

## License

MIT
