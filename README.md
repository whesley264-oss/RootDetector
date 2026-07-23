# RootDetector

RootDetector é um aplicativo Android para detecção de root utilizando C++ (Android NDK) para executar as verificações e Kotlin apenas para a interface.

O objetivo do projeto é concentrar toda a lógica de detecção na camada nativa, retornando um relatório em JSON para a aplicação.

## Recursos

- C++17 + Android NDK
- Interface simples em Kotlin
- Relatório em JSON
- 14 verificações de root
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

## Verificações

Entre as verificações realizadas estão:

- binário `su`
- arquivos do Magisk
- execução de comandos privilegiados
- propriedades do sistema
- status do SELinux
- processos conhecidos
- aplicativos relacionados a root
- pontos de montagem
- permissões do `su`
- partições graváveis
- indicadores de ROM modificada

O resultado é retornado em formato JSON contendo o status geral e o resultado individual de cada verificação.

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
