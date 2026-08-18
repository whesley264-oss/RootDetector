# RootDetector

RootDetector é um aplicativo Android para detecção de root utilizando C++ (Android NDK) para executar as verificações e Kotlin apenas para a interface.

O objetivo do projeto é concentrar toda a lógica de detecção na camada nativa, retornando um relatório em JSON para a aplicação.

## Recursos

- C++17 + Android NDK
- Interface moderna em Kotlin com cards dinâmicos e ícone de status
- Relatório em JSON com totalizadores
- **23 verificações de root**
- Build automatizado com GitHub Actions

## Estrutura

```
app/
├── src/main/
│   ├── cpp/
│   ├── java/
│   └── res/
├── build.gradle.kts
└── .github/workflows/
```

## Verificações (23)

A lógica fica toda no core em C++. As verificações realizadas são:

**Binário su e execução**
- `su binary` — procura binário su em localizações conhecidas
- `su execution` — tenta executar `su -c id`
- `su binary permissions` — detecta binários su com SUID root
- `su in PATH` — verifica se su está no PATH do ambiente

**Magisk / KernelSU / Zygisk**
- `Magisk files` — arquivos e diretórios do Magisk
- `Magisk daemon` — daemon magiskd em execução e mount namespace
- `KernelSU` — arquivos e propriedades do KernelSU
- `Zygisk deny list` — configuração/estrutura do Zygisk
- `MagiskHide` — mounts e diretórios do MagiskHide

**Apps de root**
- `root management apps` — pacotes e binários de gerenciadores de root (SuperSU, Magisk, KingRoot etc.)

**Propriedades do sistema / build**
- `system properties` — `ro.secure`, `ro.debuggable`, `test-keys`, `verifiedbootstate`
- `build tags` — `test-keys` no `ro.build.tags`
- `custom ROM` — LineageOS, crDroid, EvolutionX, etc.

**Bootloader / boot verificado**
- `bootloader` — `ro.boot.flash.locked` e `veritymode`
- `verified boot` — `ro.boot.verifiedbootstate`

**Debug / ADB**
- `debugger` — TracerPid / ptrace anexado
- `ADB` — porta TCP do ADB, configuração USB e `settings_global.xml`
- `development settings` — `ro.debuggable=1` e opções de desenvolvedor

**Integridade do sistema**
- `SELinux status` — SELinux permissive/disabled
- `mount points` — `/system` e `/` montados RW
- `RW partitions` — partições montadas como leitura/escrita
- `system paths` — caminhos suspeitos (`/sbin`, `/system/xbin`, etc.)
- `root processes` — `magiskd`, `daemonsu`, `ksud`, etc. em execução
- `ls command access` — acesso a diretórios restritos

**Hooks / instrumentação**
- `Frida hooks` — binários/processos do frida-server e entradas em `/proc/self/maps`
- `Xposed framework` — XposedBridge, LSPosed e arquivos relacionados
- `emulator` — indicadores de QEMU/SDK/Genymotion/Nox/BlueStacks

O resultado é retornado em formato JSON contendo o status geral, o total de verificações, o número de alertas e o resultado individual de cada verificação.

## Compilação

Requisitos:

- Android Studio
- Android SDK 34
- NDK r25b
- CMake 3.22+
- JDK 17

Compilar:

```bash
./gradlew assembleDebug
```

ou

```bash
./gradlew assembleRelease
```
