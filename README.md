# Bandit Linux Solver

Interactive helpers and password refreshers for the OverTheWire Bandit wargame.

The Bash app is complete, and the Python, Go, Java, C, Kotlin, and Node.js rewrites read the level flow from a shared config file. All apps can SSH into saved levels, print the local password file, and refresh solved passwords from `bandit0` through `bandit33`.

## Layout

- `bash/bandit-helper.sh` - original Bash menu app and full solver.
- `python/bandit_helper.py` - Python rewrite of the helper and config-driven refresh flow.
- `go/cmd/bandit-helper/` - Go rewrite of the helper and config-driven refresh flow.
- `java/src/main/java/bandit/BanditHelper.java` - Java rewrite of the helper and config-driven refresh flow.
- `c/bandit-helper.c` - C rewrite of the helper and config-driven refresh flow (vendored [tomlc99](https://github.com/cktan/tomlc99) under `c/vendor/tomlc99/`).
- `kotlin/src/main/kotlin/bandit/BanditHelper.kt` - Kotlin rewrite of the helper, sharing the JVM toolchain with the Java port.
- `node/bandit-helper.mjs` - Node.js (ES module) rewrite of the helper.
- `levels/bandit-levels.toml` - level definitions, commands, key names, and git repo paths for Python, Go, Java, C, Kotlin, and Node.js.
- `test-fixtures/outputs/` - placeholder for captured command-output fixtures.
- `bandit-passwords.example` - safe template for local password state.
- `bandit-passwords.txt` - generated local password file, ignored by Git.
- `.bandit-keys/` - generated SSH key cache, ignored by Git.

## Requirements

Local tools:

- Bash
- Python 3.11+
- Go 1.26+
- Java 25+ and Maven 3.9+ (only for the Java rewrite)
- C11 compiler and `make` (only for the C rewrite)
- Kotlin 2.x (only for the Kotlin rewrite — JDK 21+ via the same Maven install as the Java port)
- Node.js 20+ (only for the Node.js rewrite)
- OpenSSH client
- `expect`
- `git`
- `perl`
- standard Unix tools: `awk`, `grep`, `mktemp`

On macOS, install the missing dependency with:

```bash
brew install expect
```

## Usage

Open the interactive menu:

```bash
./bash/bandit-helper.sh
```

Refresh all solved passwords:

```bash
./bash/bandit-helper.sh --refresh
```

Show saved passwords:

```bash
./bash/bandit-helper.sh --show
```

SSH into a saved level:

```bash
./bash/bandit-helper.sh --ssh 12
```

## Python Version

Run the Python rewrite:

```bash
python3 python/bandit_helper.py
```

Refresh through Python:

```bash
python3 python/bandit_helper.py --refresh
```

Use another level config:

```bash
python3 python/bandit_helper.py --config levels/bandit-levels.toml --refresh
```

Show saved passwords:

```bash
python3 python/bandit_helper.py --show
```

SSH into a saved level:

```bash
python3 python/bandit_helper.py --ssh 12
```

## Go Version

Run the Go rewrite:

```bash
cd go
go run ./cmd/bandit-helper
```

Refresh through Go:

```bash
cd go
go run ./cmd/bandit-helper --refresh
```

Use another level config:

```bash
cd go
go run ./cmd/bandit-helper --config ../levels/bandit-levels.toml --refresh
```

Show saved passwords:

```bash
cd go
go run ./cmd/bandit-helper --show
```

SSH into a saved level:

```bash
cd go
go run ./cmd/bandit-helper --ssh 12
```

The refresh can take a few minutes. Some levels intentionally wait for remote cron jobs, brute-force a small pin range, or interact with git repositories over SSH.

## Java Version

Build the Java rewrite:

```bash
mvn -f java/pom.xml package
```

Run the Java rewrite:

```bash
java -jar java/target/bandit-helper.jar
```

Refresh through Java:

```bash
java -jar java/target/bandit-helper.jar --refresh
```

Use another level config:

```bash
java -jar java/target/bandit-helper.jar --config levels/bandit-levels.toml --refresh
```

Show saved passwords:

```bash
java -jar java/target/bandit-helper.jar --show
```

SSH into a saved level:

```bash
java -jar java/target/bandit-helper.jar --ssh 12
```

Run the unit tests:

```bash
mvn -f java/pom.xml test
```

## C Version

Build the C rewrite:

```bash
make -C c
```

Run the C rewrite:

```bash
c/bin/bandit-helper
```

Refresh through C:

```bash
c/bin/bandit-helper --refresh
```

Use another level config:

```bash
c/bin/bandit-helper --config levels/bandit-levels.toml --refresh
```

Show saved passwords:

```bash
c/bin/bandit-helper --show
```

SSH into a saved level:

```bash
c/bin/bandit-helper --ssh 12
```

Run the unit tests:

```bash
make -C c test
```

The TOML parser ([tomlc99](https://github.com/cktan/tomlc99), MIT) is vendored under `c/vendor/tomlc99/` so there is no system dependency to install.

## Kotlin Version

Build the Kotlin rewrite (reuses the Java port's JDK + Maven setup):

```bash
mvn -f kotlin/pom.xml package
```

Run the Kotlin rewrite:

```bash
java -jar kotlin/target/bandit-helper.jar
```

Refresh through Kotlin:

```bash
java -jar kotlin/target/bandit-helper.jar --refresh
```

Show saved passwords:

```bash
java -jar kotlin/target/bandit-helper.jar --show
```

SSH into a saved level:

```bash
java -jar kotlin/target/bandit-helper.jar --ssh 12
```

Run the unit tests:

```bash
mvn -f kotlin/pom.xml test
```

The Kotlin port shares `tomlj` with the Java port and targets the JVM, so no separate runtime install is needed beyond a JDK.

## Node.js Version

Install dependencies once:

```bash
cd node && npm install
```

Run the Node.js rewrite:

```bash
node node/bandit-helper.mjs
```

Refresh through Node.js:

```bash
node node/bandit-helper.mjs --refresh
```

Show saved passwords:

```bash
node node/bandit-helper.mjs --show
```

SSH into a saved level:

```bash
node node/bandit-helper.mjs --ssh 12
```

Run the unit tests:

```bash
cd node && npm test
```

The Node.js port uses [smol-toml](https://www.npmjs.com/package/smol-toml) for parsing.

## Configuration

The default target is:

```bash
bandit.labs.overthewire.org:2220
```

Override it with environment variables:

```bash
BANDIT_HOST=bandit.labs.overthewire.org BANDIT_PORT=2220 ./bash/bandit-helper.sh --refresh
```

The Python, Go, Java, C, Kotlin, and Node.js implementations read level behavior from:

```text
levels/bandit-levels.toml
```

Each `[[steps]]` entry describes one transition and a step type, such as `ssh_command`, `path_then_command`, `private_key_then_ssh`, `git_show`, `git_push_file`, or `uppercase_shell`. The runner supplies placeholders like `{password}`, `{path}`, `{random_port}`, and `{temp_output}` where a step needs runtime values.

You can point the config-driven implementations at another config with either:

```bash
BANDIT_LEVELS_FILE=levels/bandit-levels.toml python3 python/bandit_helper.py --refresh
```

or:

```bash
python3 python/bandit_helper.py --config levels/bandit-levels.toml --refresh
```

For Go, run from `go/` and pass the config path relative to that directory:

```bash
BANDIT_LEVELS_FILE=../levels/bandit-levels.toml go run ./cmd/bandit-helper --refresh
go run ./cmd/bandit-helper --config ../levels/bandit-levels.toml --refresh
```

For Java, override the config the same way:

```bash
BANDIT_LEVELS_FILE=levels/bandit-levels.toml java -jar java/target/bandit-helper.jar --refresh
java -jar java/target/bandit-helper.jar --config levels/bandit-levels.toml --refresh
```

For C:

```bash
BANDIT_LEVELS_FILE=levels/bandit-levels.toml c/bin/bandit-helper --refresh
c/bin/bandit-helper --config levels/bandit-levels.toml --refresh
```

## Git Safety

This repo intentionally ignores generated secrets:

- `bandit-passwords.txt`
- `.bandit-keys/`

Do not commit solved passwords, private keys, terminal logs, or copied challenge output. The committed files should be enough for another user to run the solver and generate their own local state.
