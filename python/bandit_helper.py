#!/usr/bin/env python3
"""Python Bandit helper and password refresher."""

from __future__ import annotations

import argparse
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path


DEFAULT_HOST = "bandit.labs.overthewire.org"
DEFAULT_PORT = "2220"
HOST = os.environ.get("BANDIT_HOST", DEFAULT_HOST)
PORT = os.environ.get("BANDIT_PORT", DEFAULT_PORT)

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
PASSFILE = REPO_ROOT / "bandit-passwords.txt"
KEY_DIR = REPO_ROOT / ".bandit-keys"
CONFIG_FILE = Path(os.environ.get("BANDIT_LEVELS_FILE", str(REPO_ROOT / "levels" / "bandit-levels.toml")))

PASSWORD_RE = re.compile(r"[A-Za-z0-9]{32}")
ANSI_RE = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]"
    r"|\x1bP.*?\x1b\\"
    r"|\x1b\].*?(?:\x07|\x1b\\)"
    r"|\x1b.",
    re.DOTALL,
)
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)


def die(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def ensure_state() -> None:
    KEY_DIR.mkdir(mode=0o700, exist_ok=True)
    PASSFILE.touch(exist_ok=True)
    KEY_DIR.chmod(0o700)
    PASSFILE.chmod(0o600)


def require_command(name: str) -> None:
    if shutil.which(name) is None:
        die(f"missing required command: {name}")


def check_dependencies() -> None:
    for command in ("expect", "ssh", "git", "awk", "grep", "mktemp"):
        require_command(command)


def load_config() -> dict:
    if not CONFIG_FILE.exists():
        die(f"missing level config: {CONFIG_FILE}")
    with CONFIG_FILE.open("rb") as config_file:
        config = tomllib.load(config_file)
    apply_connection_config(config)
    validate_config(config)
    return config


def apply_connection_config(config: dict) -> None:
    global HOST, PORT

    connection = config.get("connection", {})
    HOST = os.environ.get("BANDIT_HOST", str(connection.get("host", DEFAULT_HOST)))
    PORT = os.environ.get("BANDIT_PORT", str(connection.get("port", DEFAULT_PORT)))


def validate_config(config: dict) -> None:
    bootstrap = config.get("bootstrap")
    if not isinstance(bootstrap, dict):
        die("config is missing [bootstrap]")
    for field in ("level", "password"):
        if field not in bootstrap:
            die(f"config bootstrap is missing {field}")

    steps = config.get("steps")
    if not isinstance(steps, list) or not steps:
        die("config is missing [[steps]] entries")

    required_by_type = {
        "ssh_command": ("from", "to", "command"),
        "path_then_command": ("from", "to", "find_command", "command"),
        "private_key_then_ssh": ("from", "to", "key_command", "key_name", "next_user", "next_command"),
        "bandit26_escape": ("from", "to", "key_command", "key_name"),
        "git_read_file": ("from", "to", "git_user", "repo", "file"),
        "git_show": ("from", "to", "git_user", "repo", "object"),
        "git_push_file": ("from", "to", "git_user", "repo", "file", "content", "commit_message"),
        "uppercase_shell": ("from", "to"),
    }

    for index, step in enumerate(steps, start=1):
        step_type = step.get("type")
        if step_type not in required_by_type:
            die(f"step {index} has unsupported type: {step_type}")
        for field in required_by_type[step_type]:
            if field not in step:
                die(f"step {index} ({step_type}) is missing {field}")


def render_template(template: str, values: dict[str, object]) -> str:
    rendered = template
    for key, value in values.items():
        rendered = rendered.replace("{" + key + "}", str(value))
    return rendered


def step_context(level: int, password: str, to_level: int | None = None) -> dict[str, object]:
    target = to_level if to_level is not None else level + 1
    return {
        "password": password,
        "level": level,
        "to": target,
        "random_port": 20000 + random.randint(0, 9999),
        "temp_output": f"/tmp/bandit{target}pass.{os.getpid()}.{random.randint(1000, 9999)}",
    }


def run(
    args: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)

    result = subprocess.run(
        args,
        cwd=cwd,
        env=merged_env,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )

    if check and result.returncode != 0:
        output = result.stdout + result.stderr
        raise RuntimeError(f"command failed: {' '.join(args)}\n{output}")

    return result


def run_expect(script: str, env: dict[str, str] | None = None) -> str:
    result = run(["expect"], env=env, input_text=script, check=False)
    output = result.stdout + result.stderr
    if result.returncode != 0:
        raise RuntimeError(output)
    return output


def strip_terminal_codes(text: str) -> str:
    return ANSI_RE.sub("", text).replace("\r", "")


def extract_passwords(text: str) -> list[str]:
    return PASSWORD_RE.findall(strip_terminal_codes(text))


def extract_password(text: str) -> str:
    passwords = extract_passwords(text)
    if not passwords:
        raise ValueError(f"failed to extract a 32-character password from output:\n{text}")
    return passwords[-1]


def save_password(user: str, password: str) -> None:
    ensure_state()
    lines = []
    if PASSFILE.exists():
        lines = [
            line
            for line in PASSFILE.read_text(encoding="utf-8").splitlines()
            if not line.startswith(f"{user}:")
        ]
    lines.append(f"{user}: {password}")
    PASSFILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    PASSFILE.chmod(0o600)


def get_saved_password(user: str) -> str:
    if not PASSFILE.exists():
        return ""
    password = ""
    for line in PASSFILE.read_text(encoding="utf-8").splitlines():
        prefix = f"{user}: "
        if line.startswith(prefix):
            password = line[len(prefix) :]
    return password


def record_password(level: int, password: str) -> None:
    user = f"bandit{level}"
    if level != 0 and not PASSWORD_RE.fullmatch(password):
        die(f"refusing to save invalid password for {user}: {password}")
    save_password(user, password)
    print(f"[+] {user:<8} {password}")


def run_password_ssh_command(user: str, password: str, command_text: str) -> str:
    script = r'''
set timeout 180
spawn -noecho ssh \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o LogLevel=ERROR \
  -o PubkeyAuthentication=no \
  -o PreferredAuthentications=password \
  -o NumberOfPasswordPrompts=1 \
  -p $env(BANDIT_PORT_VALUE) \
  $env(BANDIT_USER_VALUE)@$env(BANDIT_HOST_VALUE) \
  $env(BANDIT_COMMAND_VALUE)
expect {
  "*password:" {
    send -- "$env(BANDIT_PASSWORD_VALUE)\r"
    exp_continue
  }
  timeout {
    exit 124
  }
  eof {
  }
}
catch wait result
exit [lindex $result 3]
'''
    try:
        return run_expect(
            script,
            {
                "BANDIT_HOST_VALUE": HOST,
                "BANDIT_PORT_VALUE": PORT,
                "BANDIT_USER_VALUE": user,
                "BANDIT_PASSWORD_VALUE": password,
                "BANDIT_COMMAND_VALUE": command_text,
            },
        )
    except RuntimeError as exc:
        raise RuntimeError(f"SSH command failed for {user}: {command_text}\n{exc}") from exc


def run_key_ssh_command(user: str, key_file: Path, command_text: str) -> str:
    result = run(
        [
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "BatchMode=yes",
            "-i",
            str(key_file),
            "-p",
            PORT,
            f"{user}@{HOST}",
            command_text,
        ],
        check=False,
    )
    output = result.stdout + result.stderr
    if result.returncode != 0:
        raise RuntimeError(output)
    return output


def solve_password(user: str, password: str, command_text: str) -> str:
    return extract_password(run_password_ssh_command(user, password, command_text))


def solve_path(user: str, password: str, command_text: str) -> str:
    output = strip_terminal_codes(run_password_ssh_command(user, password, command_text))
    matches = [line for line in output.splitlines() if "/inhere/" in line]
    if not matches:
        raise ValueError(f"failed to extract path from output:\n{output}")
    return matches[-1]


def save_private_key(name: str, output: str) -> Path:
    ensure_state()
    match = PRIVATE_KEY_RE.search(strip_terminal_codes(output))
    if not match:
        raise ValueError(f"failed to extract private key {name} from output:\n{output}")

    key_file = KEY_DIR / name
    key_file.write_text(match.group(0) + "\n", encoding="utf-8")
    key_file.chmod(0o600)
    return key_file


def git_env(password: str, askpass: Path) -> dict[str, str]:
    return {
        "BANDIT_GIT_PASSWORD": password,
        "GIT_SSH_COMMAND": (
            "ssh -o StrictHostKeyChecking=no "
            "-o UserKnownHostsFile=/dev/null "
            "-o LogLevel=ERROR "
            "-o PubkeyAuthentication=no "
            "-o PreferredAuthentications=password "
            "-o NumberOfPasswordPrompts=1"
        ),
        "SSH_ASKPASS": str(askpass),
        "SSH_ASKPASS_REQUIRE": "force",
        "DISPLAY": os.environ.get("DISPLAY", ":0"),
    }


def write_askpass(directory: Path) -> Path:
    askpass = directory / "askpass.sh"
    askpass.write_text(
        "#!/usr/bin/env bash\nprintf '%s\\n' \"$BANDIT_GIT_PASSWORD\"\n",
        encoding="utf-8",
    )
    askpass.chmod(0o700)
    return askpass


def git_clone_repo(user: str, password: str, remote_path: str, destination: Path) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        askpass = write_askpass(Path(tmp))
        run(
            ["git", "clone", f"ssh://{user}@{HOST}:{PORT}{remote_path}", str(destination)],
            env=git_env(password, askpass),
        )


def git_push_with_password(password: str, repo: Path) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        askpass = write_askpass(Path(tmp))
        result = run(
            ["git", "-C", str(repo), "push", "origin", "master"],
            env=git_env(password, askpass),
            check=False,
        )
        return result.stdout + result.stderr


def solve_bandit26_pair(key_file: Path) -> tuple[str, str]:
    script = r'''
set timeout 90
set stty_init "rows 5 columns 80"
spawn -noecho ssh \
  -tt \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o LogLevel=ERROR \
  -o IdentitiesOnly=yes \
  -i $env(BANDIT_KEY_VALUE) \
  -p $env(BANDIT_PORT_VALUE) \
  bandit26@$env(BANDIT_HOST_VALUE)
expect {
  -re "--More--" {
    send -- "v"
  }
  timeout {
    exit 124
  }
  eof {
    exit 1
  }
}
expect {
  -re "~" {
  }
  timeout {
    exit 124
  }
  eof {
    exit 1
  }
}
after 500
send -- "\033:set shell=/bin/bash\r"
after 500
send -- ":shell\r"
after 500
send -- "cat /etc/bandit_pass/bandit26; ./bandit27-do cat /etc/bandit_pass/bandit27; exit\r"
set password_count 0
expect {
  -re {[[:alnum:]]{32}} {
    incr password_count
    if {$password_count < 2} {
      exp_continue
    }
  }
  timeout {
    exit 124
  }
  eof {
    exit 1
  }
}
close
wait
exit 0
'''
    output = run_expect(
        script,
        {
            "BANDIT_HOST_VALUE": HOST,
            "BANDIT_PORT_VALUE": PORT,
            "BANDIT_KEY_VALUE": str(key_file),
        },
    )
    passwords = extract_passwords(output)
    if len(passwords) < 2:
        raise ValueError(f"expected two passwords from bandit26 output:\n{output}")
    return passwords[-2], passwords[-1]


def solve_uppercase_shell(password: str) -> str:
    script = r'''
set timeout 60
spawn -noecho ssh \
  -tt \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o LogLevel=ERROR \
  -o PubkeyAuthentication=no \
  -o PreferredAuthentications=password \
  -o NumberOfPasswordPrompts=1 \
  -p $env(BANDIT_PORT_VALUE) \
  bandit32@$env(BANDIT_HOST_VALUE)
expect {
  "*password:" {
    send -- "$env(BANDIT_PASSWORD_VALUE)\r"
    exp_continue
  }
  -re "WELCOME TO THE UPPERCASE SHELL|>>" {
  }
  timeout {
    exit 124
  }
}
after 500
send -- "\$0\r"
expect {
  -re {[$#] } {
  }
  timeout {
    exit 124
  }
}
send -- "cat /etc/bandit_pass/bandit33; exit\r"
expect {
  -re {[[:alnum:]]{32}} {
  }
  timeout {
    exit 124
  }
}
close
wait
exit 0
'''
    output = run_expect(
        script,
        {
            "BANDIT_HOST_VALUE": HOST,
            "BANDIT_PORT_VALUE": PORT,
            "BANDIT_PASSWORD_VALUE": password,
        },
    )
    return extract_password(output)


def solve_step(step: dict, passwords: dict[int, str]) -> None:
    step_type = step["type"]
    from_level = int(step["from"])
    from_user = str(step.get("user", f"bandit{from_level}"))
    from_password = passwords[from_level]

    if step_type == "ssh_command":
        to_level = int(step["to"])
        context = step_context(from_level, from_password, to_level)
        command = render_template(str(step["command"]), context)
        password = solve_password(from_user, from_password, command)
        passwords[to_level] = password
        record_password(to_level, password)
        return

    if step_type == "path_then_command":
        to_level = int(step["to"])
        context = step_context(from_level, from_password, to_level)
        find_command = render_template(str(step["find_command"]), context)
        path = solve_path(from_user, from_password, find_command)
        context["path"] = path
        command = render_template(str(step["command"]), context)
        password = solve_password(from_user, from_password, command)
        passwords[to_level] = password
        record_password(to_level, password)
        return

    if step_type == "private_key_then_ssh":
        to_level = int(step["to"])
        context = step_context(from_level, from_password, to_level)
        key_command = render_template(str(step["key_command"]), context)
        output = run_password_ssh_command(from_user, from_password, key_command)
        key_file = save_private_key(str(step["key_name"]), output)
        next_command = render_template(str(step["next_command"]), context)
        password = extract_password(run_key_ssh_command(str(step["next_user"]), key_file, next_command))
        passwords[to_level] = password
        record_password(to_level, password)
        return

    if step_type == "bandit26_escape":
        targets = [int(target) for target in step["to"]]
        context = step_context(from_level, from_password, targets[-1])
        key_command = render_template(str(step["key_command"]), context)
        output = run_password_ssh_command(from_user, from_password, key_command)
        key_file = save_private_key(str(step["key_name"]), output)
        solved = solve_bandit26_pair(key_file)
        if len(targets) != len(solved):
            raise ValueError(f"bandit26_escape expected {len(targets)} passwords, got {len(solved)}")
        for target, password in zip(targets, solved, strict=True):
            passwords[target] = password
            record_password(target, password)
        return

    if step_type == "git_read_file":
        to_level = int(step["to"])
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            git_clone_repo(str(step["git_user"]), from_password, str(step["repo"]), repo)
            password = extract_password((repo / str(step["file"])).read_text(encoding="utf-8"))
        passwords[to_level] = password
        record_password(to_level, password)
        return

    if step_type == "git_show":
        to_level = int(step["to"])
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            git_clone_repo(str(step["git_user"]), from_password, str(step["repo"]), repo)
            password = extract_password(run(["git", "-C", str(repo), "show", str(step["object"])]).stdout)
        passwords[to_level] = password
        record_password(to_level, password)
        return

    if step_type == "git_push_file":
        to_level = int(step["to"])
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            git_clone_repo(str(step["git_user"]), from_password, str(step["repo"]), repo)
            run(["git", "-C", str(repo), "config", "user.email", "bandit-solver@example.invalid"])
            run(["git", "-C", str(repo), "config", "user.name", "bandit-solver"])
            (repo / str(step["file"])).write_text(str(step["content"]), encoding="utf-8")
            run(["git", "-C", str(repo), "add", "-f", str(step["file"])])
            run(["git", "-C", str(repo), "commit", "-m", str(step["commit_message"])])
            password = extract_password(git_push_with_password(from_password, repo))
        passwords[to_level] = password
        record_password(to_level, password)
        return

    if step_type == "uppercase_shell":
        to_level = int(step["to"])
        password = solve_uppercase_shell(from_password)
        passwords[to_level] = password
        record_password(to_level, password)
        return

    raise ValueError(f"unsupported step type: {step_type}")


def refresh_passwords() -> None:
    config = load_config()
    check_dependencies()
    ensure_state()

    print(f"Refreshing Bandit passwords via {HOST}:{PORT}")
    print(f"Level config:  {CONFIG_FILE}")
    print(f"Password file: {PASSFILE}")
    print(f"Key cache:     {KEY_DIR}")
    print()

    bootstrap = config["bootstrap"]
    bootstrap_level = int(bootstrap["level"])
    passwords = {bootstrap_level: str(bootstrap["password"])}
    record_password(bootstrap_level, passwords[bootstrap_level])

    for step in config["steps"]:
        solve_step(step, passwords)

    print()
    print("Refresh complete.")


def show_passwords() -> None:
    ensure_state()
    if PASSFILE.stat().st_size == 0:
        print("No passwords saved yet.")
    else:
        print(PASSFILE.read_text(encoding="utf-8"), end="")


def ssh_level(level: int) -> None:
    ensure_state()
    user = f"bandit{level}"
    password = get_saved_password(user)
    if not password:
        os.execvp("ssh", ["ssh", f"{user}@{HOST}", "-p", PORT])

    script = r'''
set timeout 30
spawn ssh \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o LogLevel=ERROR \
  -o PubkeyAuthentication=no \
  -o PreferredAuthentications=password \
  -p $env(BANDIT_PORT_VALUE) \
  $env(BANDIT_USER_VALUE)@$env(BANDIT_HOST_VALUE)
expect {
  "*password:" {
    send -- "$env(BANDIT_PASSWORD_VALUE)\r"
    interact
  }
  timeout {
    interact
  }
  eof {
  }
}
'''
    subprocess.run(
        ["expect"],
        input=script,
        text=True,
        env={
            **os.environ,
            "BANDIT_HOST_VALUE": HOST,
            "BANDIT_PORT_VALUE": PORT,
            "BANDIT_USER_VALUE": user,
            "BANDIT_PASSWORD_VALUE": password,
        },
        check=False,
    )


def save_password_interactive() -> None:
    username = input("Save password for which user? Example: bandit6: ").strip()
    password = input("Password: ").strip()
    save_password(username, password)
    print(f"Saved password for {username}.")


def menu() -> None:
    ensure_state()
    while True:
        print("====================================")
        print("        OverTheWire Bandit App")
        print("====================================")
        print()
        print(f"Password file: {PASSFILE}")
        print(f"Key cache:     {KEY_DIR}")
        print()
        print("1) SSH into a Bandit level")
        print("2) Refresh all passwords")
        print("3) Save/update a password")
        print("4) Show saved passwords")
        print("5) Exit")
        print()

        choice = input("Choose an option: ").strip()
        if choice == "1":
            ssh_level(int(input("Bandit level number, e.g. 0, 1, 26, 33: ").strip()))
        elif choice == "2":
            refresh_passwords()
            input("Press Enter to continue...")
        elif choice == "3":
            save_password_interactive()
        elif choice == "4":
            show_passwords()
            input("Press Enter to continue...")
        elif choice == "5":
            return
        else:
            print("Invalid option.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Python Bandit helper")
    parser.add_argument(
        "--config",
        type=Path,
        default=CONFIG_FILE,
        help=f"level config file (default: {CONFIG_FILE})",
    )
    parser.add_argument("--refresh", action="store_true", help="solve bandit0 through bandit33")
    parser.add_argument("--show", action="store_true", help="print saved passwords")
    parser.add_argument("--ssh", type=int, metavar="LEVEL", help="SSH into banditLEVEL")
    return parser


def main(argv: list[str] | None = None) -> int:
    global CONFIG_FILE

    parser = build_parser()
    args = parser.parse_args(argv)
    CONFIG_FILE = args.config

    try:
        if args.refresh:
            refresh_passwords()
        elif args.show:
            show_passwords()
        elif args.ssh is not None:
            load_config()
            ssh_level(args.ssh)
        else:
            load_config()
            menu()
    except (RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
