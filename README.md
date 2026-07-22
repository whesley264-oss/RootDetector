# RootDetector

Android root detection application with native C++ core. The app provides a simple interface with a single button to trigger all root detection checks.

## Project Overview

This application detects whether an Android device has been rooted by performing multiple security checks. All detection logic is implemented in C++ using the Android NDK, ensuring efficient and secure root detection.

### Key Features

- Native C++ core for performance
- 14 different detection methods
- Dark silver metallic theme
- Simple one-button interface
- Detailed JSON reports for each check
- GitHub Actions CI/CD pipeline

## Project Structure

```
rootdetector/
├── app/
│   ├── src/main/
│   │   ├── cpp/           # C++ NDK code
│   │   │   ├── RootDetector.h    # Header with class definitions
│   │   │   ├── RootDetector.cpp  # Core detection logic implementation
│   │   │   ├── JNI.cpp          # JNI bridge to Java/Kotlin
│   │   │   └── CMakeLists.txt   # CMake build configuration
│   │   ├── java/com/rootdetector/app/
│   │   │   └── MainActivity.kt   # Kotlin UI controller
│   │   └── res/
│   │       ├── layout/           # XML layouts
│   │       ├── values/           # Colors, themes, strings
│   │       └── drawable/         # Icons and drawables
│   └── build.gradle.kts
├── build.gradle.kts              # Root build config
├── settings.gradle.kts
├── gradle.properties
└── .github/workflows/
    └── android.yml               # CI/CD pipeline
```

## Detection Methods

The application performs the following 14 checks when the CHECK button is pressed:

| # | Check | Description | Threat Level |
|---|-------|-------------|--------------|
| 1 | **su binary** | Searches common paths for the 'su' binary | Critical |
| 2 | **Magisk files** | Detects Magisk-related files and directories | Critical |
| 3 | **su execution** | Attempts to execute 'su -c id' to verify access | Critical |
| 4 | **System properties** | Checks ro.secure, ro.debuggable, ro.build.tags | High |
| 5 | **Mount points** | Analyzes /proc/mounts for suspicious configs | Medium |
| 6 | **Build tags** | Detects 'test-keys' indicating custom builds | High |
| 7 | **Root apps** | Searches for SuperSU, Magisk, KingRoot files | High |
| 8 | **SELinux status** | Checks if SELinux is disabled/permissive | High |
| 9 | **System paths** | Verifies /sbin, /data/local/su paths | Medium |
| 10 | **ls command access** | Lists restricted directories | High |
| 11 | **su permissions** | Checks SUID bit on su binary | Critical |
| 12 | **RW partitions** | Verifies /system mounted as RW | High |
| 13 | **Root processes** | Scans for magiskd, daemonsu | Critical |
| 14 | **Custom ROM** | Detects ROM indicators in build ID | Low |

## Paths Checked for su Binary

- /system/bin/su
- /system/xbin/su
- /sbin/su
- /vendor/bin/su
- /system/su
- /data/local/bin/su
- /data/local/xbin/su
- /data/local/su

## Magisk Files Checked

- /data/adb/magisk
- /data/adb/magisk.img
- /data/adb/magiskrc
- /system/etc/magisk
- /system/xbin/magisk
- /system/bin/magisk
- /sbin/magisk
- /cache/magisk.log
- Magisk APK in /data/app/

## System Properties Analyzed

- ro.secure (should be 1)
- ro.debuggable (should be 0)
- ro.build.tags (should not contain test-keys)
- ro.boot.verifiedbootstate
- ro.build.selinux

## Building

### Local Build

1. Open project in Android Studio
2. Sync Gradle files
3. Build > Build Bundle(s) / APK(s)

### CI/CD Build

The project uses GitHub Actions for CI/CD. Builds are triggered automatically on push and pull requests to main branch.

Workflow steps:
1. Checkout code
2. Setup JDK 17
3. Setup Gradle 8.4
4. Setup Android SDK
5. Build debug APK
6. Build release APK
7. Upload artifacts

Debug and release APKs are generated and available as workflow artifacts for download.

## Requirements

- Android Studio with NDK support
- Android SDK 34
- NDK version as specified in CMakeLists.txt (r25b)
- CMake 3.22+
- C++17
- JDK 17

## Native Library

The C++ core exposes the following JNI functions:

```cpp
// Runs all root detection checks and returns JSON report
extern "C" JNIEXPORT jstring JNICALL
Java_com_rootdetector_app_MainActivity_nativeDetectRoot(
    JNIEnv* env,
    jobject this);

// Returns native library version
extern "C" JNIEXPORT jstring JNICALL
Java_com_rootdetector_app_MainActivity_nativeGetVersion(
    JNIEnv* env,
    jobject this);
```

### JSON Response Format

```json
{
  "rootDetected": true,
  "checks": [
    {
      "name": "su binary",
      "result": true,
      "reason": "Found 'su' binary at: /system/xbin/su"
    },
    {
      "name": "Magisk files",
      "result": false,
      "reason": "No Magisk-related files or directories found"
    }
  ]
}
```

The `result` field is `true` when a root indicator is detected, `false` otherwise.

## Architecture

```
┌─────────────────────────────────────┐
│           MainActivity.kt            │
│  (UI Controller - Kotlin)           │
│                                     │
│  - Button click handler              │
│  - Results display                  │
│  - Loading state management          │
└───────────────┬─────────────────────┘
                │ JNI
┌───────────────▼─────────────────────┐
│              JNI.cpp                │
│  (Java Native Interface Bridge)     │
│                                     │
│  - Calls C++ RootDetector           │
│  - JSON report generation           │
└───────────────┬─────────────────────┘
                │
┌───────────────▼─────────────────────┐
│          RootDetector.cpp           │
│  (Core Detection Logic - C++17)     │
│                                     │
│  - 14 detection methods             │
│  - File system checks               │
│  - System property reading          │
│  - Command execution                │
└─────────────────────────────────────┘
```

## CI/CD

GitHub Actions workflow configured in `.github/workflows/android.yml`:

- **Trigger**: Every push and PR to main branch
- **Jobs**: Build debug and release APKs
- **Artifacts**: Available for 7 days

---

# RootDetector

Aplicativo Android para deteccao de root com nucleo nativo em C++. O app fornece uma interface simples com um unico botao para acionar todos os verificadores de root.

## Visao Geral do Projeto

Este aplicativo detecta se um dispositivo Android foi desbloqueado (rooted) atraves de multiplas verificacoes de seguranca. Toda a logica de deteccao e implementada em C++ usando o Android NDK, garantindo deteccao eficiente e segura.

### Funcionalidades Principais

- Nucleo nativo em C++ para melhor desempenho
- 14 metodos diferentes de deteccao
- Tema escuro prateado metalico
- Interface simples com um botao
- Relatorios JSON detalhados para cada verificacao
- Pipeline CI/CD com GitHub Actions

## Estrutura do Projeto

```
rootdetector/
├── app/
│   ├── src/main/
│   │   ├── cpp/           # Codigo C++ NDK
│   │   │   ├── RootDetector.h    # Header com definicoes da classe
│   │   │   ├── RootDetector.cpp  # Implementacao da logica de deteccao
│   │   │   ├── JNI.cpp          # Ponte JNI para Java/Kotlin
│   │   │   └── CMakeLists.txt   # Configuracao de build CMake
│   │   ├── java/com/rootdetector/app/
│   │   │   └── MainActivity.kt   # Controlador UI Kotlin
│   │   └── res/
│   │       ├── layout/           # Layouts XML
│   │       ├── values/           # Cores, temas, strings
│   │       └── drawable/         # Icones e drawables
│   └── build.gradle.kts
├── build.gradle.kts              # Config de build raiz
├── settings.gradle.kts
├── gradle.properties
└── .github/workflows/
    └── android.yml               # Pipeline CI/CD
```

## Metodos de Deteccao

O aplicativo realiza as seguintes 14 verificacoes quando o botao CHECK e pressionado:

| # | Verificacao | Descricao | Nivel de Ameaca |
|---|-------------|-----------|-----------------|
| 1 | **binario su** | Procura o binario 'su' em caminhos comuns | Critico |
| 2 | **arquivos Magisk** | Detecta arquivos e diretorios relacionados ao Magisk | Critico |
| 3 | **execucao su** | Tenta executar 'su -c id' para verificar acesso | Critico |
| 4 | **propriedades sistema** | Verifica ro.secure, ro.debuggable, ro.build.tags | Alto |
| 5 | **pontos de montagem** | Analisa /proc/mounts em busca de configuracoes suspeitas | Medio |
| 6 | **tags de build** | Detecta 'test-keys' indicando builds personalizados | Alto |
| 7 | **apps de root** | Busca arquivos do SuperSU, Magisk, KingRoot | Alto |
| 8 | **status SELinux** | Verifica se SELinux esta desabilitado/permissivo | Alto |
| 9 | **caminhos sistema** | Verifica caminhos /sbin, /data/local/su | Medio |
| 10 | **acesso ls** | Lista diretorios restritos | Alto |
| 11 | **permissoes su** | Verifica bit SUID no binario su | Critico |
| 12 | **particoes RW** | Verifica se /system esta montado como RW | Alto |
| 13 | **processos root** | Procura por magiskd, daemonsu | Critico |
| 14 | **ROM personalizado** | Detecta indicadores de ROM customizado | Baixo |

## Caminhos Verificados para binario su

- /system/bin/su
- /system/xbin/su
- /sbin/su
- /vendor/bin/su
- /system/su
- /data/local/bin/su
- /data/local/xbin/su
- /data/local/su

## Arquivos Magisk Verificados

- /data/adb/magisk
- /data/adb/magisk.img
- /data/adb/magiskrc
- /system/etc/magisk
- /system/xbin/magisk
- /system/bin/magisk
- /sbin/magisk
- /cache/magisk.log
- APK do Magisk em /data/app/

## Propriedades do Sistema Analisadas

- ro.secure (deve ser 1)
- ro.debuggable (deve ser 0)
- ro.build.tags (nao deve conter test-keys)
- ro.boot.verifiedbootstate
- ro.build.selinux

## Compilacao

### Build Local

1. Abra o projeto no Android Studio
2. Sincronize os arquivos Gradle
3. Build > Build Bundle(s) / APK(s)

### Build CI/CD

O projeto usa GitHub Actions para CI/CD. Os builds sao acionados automaticamente a cada push e pull request na branch main.

Passos do workflow:
1. Checkout do codigo
2. Configuracao JDK 17
3. Configuracao Gradle 8.4
4. Configuracao Android SDK
5. Build do APK debug
6. Build do APK release
7. Upload dos artifacts

Os APKs debug e release sao gerados e disponibilizados como artifacts para download.

## Requisitos

- Android Studio com suporte a NDK
- Android SDK 34
- Versao NDK conforme especificado em CMakeLists.txt (r25b)
- CMake 3.22+
- C++17
- JDK 17

## Biblioteca Nativa

O nucleo C++ expõe as seguintes funcoes JNI:

```cpp
// Executa todas as verificacoes e retorna relatorio JSON
extern "C" JNIEXPORT jstring JNICALL
Java_com_rootdetector_app_MainActivity_nativeDetectRoot(
    JNIEnv* env,
    jobject this);

// Retorna a versao da biblioteca nativa
extern "C" JNIEXPORT jstring JNICALL
Java_com_rootdetector_app_MainActivity_nativeGetVersion(
    JNIEnv* env,
    jobject this);
```

### Formato da Resposta JSON

```json
{
  "rootDetected": true,
  "checks": [
    {
      "name": "su binary",
      "result": true,
      "reason": "Found 'su' binary at: /system/xbin/su"
    },
    {
      "name": "Magisk files",
      "result": false,
      "reason": "No Magisk-related files or directories found"
    }
  ]
}
```

O campo `result` e `true` quando um indicador de root e detectado, `false` caso contrario.

## Arquitetura

```
┌─────────────────────────────────────┐
│           MainActivity.kt            │
│  (Controlador UI - Kotlin)          │
│                                     │
│  - Tratador de clique do botao      │
│  - Exibicao de resultados           │
│  - Gerenciamento de estado          │
└───────────────┬─────────────────────┘
                │ JNI
┌───────────────▼─────────────────────┐
│              JNI.cpp                │
│  (Ponte Interface Java Nativo)     │
│                                     │
│  - Chama RootDetector em C++        │
│  - Geracao de relatorio JSON        │
└───────────────┬─────────────────────┘
                │
┌───────────────▼─────────────────────┐
│          RootDetector.cpp           │
│  (Logica de Deteccao Core - C++17) │
│                                     │
│  - 14 metodos de deteccao           │
│  - Verificacoes de sistema de arq.  │
│  - Leitura de propriedades sistema  │
│  - Execucao de comandos             │
└─────────────────────────────────────┘
```

## CI/CD

Workflow do GitHub Actions configurado em `.github/workflows/android.yml`:

- **Disparo**: A cada push e PR na branch main
- **Jobs**: Build dos APKs debug e release
- **Artifacts**: Disponiveis por 7 dias

## License / Licenca

MIT
