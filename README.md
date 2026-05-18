# Bandit Linux Solver

Interactive helper and password refresher for the OverTheWire Bandit wargame.

The main app is `bandit-helper.sh`. It can SSH into saved levels, manually save a password, print the local password file, and refresh solved passwords from `bandit0` through `bandit33`.

## Files

- `bandit-helper.sh` - main menu app and full solver.
- `bandit-passwords.example` - safe template for local password state.
- `bandit-passwords.txt` - generated local password file, ignored by Git.
- `.bandit-keys/` - generated SSH key cache, ignored by Git.

## Requirements

Local tools:

- Bash
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
./bandit-helper.sh
```

Refresh all solved passwords:

```bash
./bandit-helper.sh --refresh
```

Show saved passwords:

```bash
./bandit-helper.sh --show
```

SSH into a saved level:

```bash
./bandit-helper.sh --ssh 12
```

The refresh can take a few minutes. Some levels intentionally wait for remote cron jobs, brute-force a small pin range, or interact with git repositories over SSH.

## Configuration

The default target is:

```bash
bandit.labs.overthewire.org:2220
```

Override it with environment variables:

```bash
BANDIT_HOST=bandit.labs.overthewire.org BANDIT_PORT=2220 ./bandit-helper.sh --refresh
```

## Git Safety

This repo intentionally ignores generated secrets:

- `bandit-passwords.txt`
- `.bandit-keys/`

Do not commit solved passwords, private keys, terminal logs, or copied challenge output. The committed files should be enough for another user to run the solver and generate their own local state.
