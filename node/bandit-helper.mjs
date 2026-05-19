#!/usr/bin/env node

import { spawn } from "node:child_process";
import { createInterface } from "node:readline/promises";
import { stdin, stdout, stderr, env, argv, exit } from "node:process";
import * as fs from "node:fs/promises";
import * as fsSync from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { fileURLToPath } from "node:url";
import { parse as parseToml } from "smol-toml";

const DEFAULT_HOST = "bandit.labs.overthewire.org";
const DEFAULT_PORT = "2220";

const PASSWORD_RE = /[A-Za-z0-9]{32}/g;
const PRIVATE_KEY_RE = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/;
const ANSI_RE = new RegExp(
    [
        "\\x1b\\[[0-?]*[ -/]*[@-~]",
        "\\x1bP[\\s\\S]*?\\x1b\\\\",
        "\\x1b\\][\\s\\S]*?(?:\\x07|\\x1b\\\\)",
        "\\x1b.",
    ].join("|"),
    "g",
);

const REQUIRED_FIELDS = {
    ssh_command: ["from", "to", "command"],
    path_then_command: ["from", "to", "find_command", "command"],
    private_key_then_ssh: ["from", "to", "key_command", "key_name", "next_user", "next_command"],
    bandit26_escape: ["from", "to", "key_command", "key_name"],
    git_read_file: ["from", "to", "git_user", "repo", "file"],
    git_show: ["from", "to", "git_user", "repo", "object"],
    git_push_file: ["from", "to", "git_user", "repo", "file", "content", "commit_message"],
    uppercase_shell: ["from", "to"],
};

const state = {
    host: "",
    port: "",
    repoRoot: "",
    configPath: "",
    passFile: "",
    keyDir: "",
};

function envOr(name, fallback) {
    const v = env[name];
    return v && v.length > 0 ? v : fallback;
}

function die(message) {
    stderr.write(`error: ${message}\n`);
    exit(1);
}

export function findRepoRoot(start = process.cwd()) {
    let cwd = path.resolve(start);
    while (true) {
        if (fsSync.existsSync(path.join(cwd, "levels", "bandit-levels.toml"))) return cwd;
        const parent = path.dirname(cwd);
        if (parent === cwd) throw new Error("could not find repo root containing levels/bandit-levels.toml");
        cwd = parent;
    }
}

async function ensureState() {
    await fs.mkdir(state.keyDir, { recursive: true, mode: 0o700 });
    await fs.chmod(state.keyDir, 0o700);
    try {
        const fd = await fs.open(state.passFile, "a");
        await fd.close();
    } catch (e) {
        die(`create ${state.passFile}: ${e.message}`);
    }
    await fs.chmod(state.passFile, 0o600);
}

async function which(cmd) {
    const PATH = env.PATH || "";
    for (const dir of PATH.split(path.delimiter)) {
        if (!dir) continue;
        const candidate = path.join(dir, cmd);
        try {
            await fs.access(candidate, fsSync.constants.X_OK);
            return candidate;
        } catch {
            // not found
        }
    }
    return null;
}

async function checkDependencies() {
    for (const cmd of ["expect", "ssh", "git", "awk", "grep", "mktemp"]) {
        if (!(await which(cmd))) die(`missing required command: ${cmd}`);
    }
}

export function stripTerminalCodes(text) {
    return String(text).replace(ANSI_RE, "").replace(/\r/g, "");
}

export function extractPasswords(text) {
    const clean = stripTerminalCodes(text);
    return clean.match(PASSWORD_RE) || [];
}

export function extractPassword(text) {
    const list = extractPasswords(text);
    if (list.length === 0) throw new Error(`failed to extract a 32-character password from output:\n${text}`);
    return list[list.length - 1];
}

/* ---------- subprocess ---------- */

function runCommand(name, args = [], { envExtra = {}, input = null, cwd = null } = {}) {
    return new Promise((resolve, reject) => {
        const child = spawn(name, args, {
            env: { ...env, ...envExtra },
            cwd: cwd || undefined,
            stdio: [input != null ? "pipe" : "ignore", "pipe", "pipe"],
        });
        const chunks = [];
        child.stdout.on("data", (b) => chunks.push(b));
        child.stderr.on("data", (b) => chunks.push(b));
        child.on("error", reject);
        child.on("close", (code) => {
            resolve({ exitCode: code ?? -1, output: Buffer.concat(chunks).toString("utf8") });
        });
        if (input != null) {
            child.stdin.write(input);
            child.stdin.end();
        }
    });
}

async function runExpect(script, envExtra) {
    const r = await runCommand("expect", [], { envExtra, input: script });
    if (r.exitCode !== 0) throw new Error(r.output);
    return r.output;
}

/* ---------- password storage ---------- */

async function savePassword(user, password) {
    await ensureState();
    let lines = [];
    try {
        const data = await fs.readFile(state.passFile, "utf8");
        for (const line of data.split("\n")) {
            if (!line || line.startsWith(`${user}:`)) continue;
            lines.push(line);
        }
    } catch {
        // empty file is fine
    }
    lines.push(`${user}: ${password}`);
    await fs.writeFile(state.passFile, lines.join("\n") + "\n", { mode: 0o600 });
    await fs.chmod(state.passFile, 0o600);
}

async function getSavedPassword(user) {
    try {
        const data = await fs.readFile(state.passFile, "utf8");
        const prefix = `${user}: `;
        let password = "";
        for (const line of data.split("\n")) {
            if (line.startsWith(prefix)) password = line.slice(prefix.length);
        }
        return password;
    } catch {
        return "";
    }
}

async function recordPassword(level, password) {
    const user = `bandit${level}`;
    if (level !== 0 && !/^[A-Za-z0-9]{32}$/.test(password)) {
        die(`refusing to save invalid password for ${user}: ${password}`);
    }
    await savePassword(user, password);
    stdout.write(`[+] ${user.padEnd(8)} ${password}\n`);
}

/* ---------- expect scripts ---------- */

const SCRIPT_PASSWORD_SSH = `
set timeout 180
spawn -noecho ssh \\
  -o StrictHostKeyChecking=no \\
  -o UserKnownHostsFile=/dev/null \\
  -o LogLevel=ERROR \\
  -o PubkeyAuthentication=no \\
  -o PreferredAuthentications=password \\
  -o NumberOfPasswordPrompts=1 \\
  -p $env(BANDIT_PORT_VALUE) \\
  $env(BANDIT_USER_VALUE)@$env(BANDIT_HOST_VALUE) \\
  $env(BANDIT_COMMAND_VALUE)
expect {
  "*password:" {
    send -- "$env(BANDIT_PASSWORD_VALUE)\\r"
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
`;

const SCRIPT_BANDIT26 = `
set timeout 90
set stty_init "rows 5 columns 80"
spawn -noecho ssh \\
  -tt \\
  -o StrictHostKeyChecking=no \\
  -o UserKnownHostsFile=/dev/null \\
  -o LogLevel=ERROR \\
  -o IdentitiesOnly=yes \\
  -i $env(BANDIT_KEY_VALUE) \\
  -p $env(BANDIT_PORT_VALUE) \\
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
send -- "\\033:set shell=/bin/bash\\r"
after 500
send -- ":shell\\r"
after 500
send -- "cat /etc/bandit_pass/bandit26; ./bandit27-do cat /etc/bandit_pass/bandit27; exit\\r"
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
`;

const SCRIPT_UPPERCASE = `
set timeout 60
spawn -noecho ssh \\
  -tt \\
  -o StrictHostKeyChecking=no \\
  -o UserKnownHostsFile=/dev/null \\
  -o LogLevel=ERROR \\
  -o PubkeyAuthentication=no \\
  -o PreferredAuthentications=password \\
  -o NumberOfPasswordPrompts=1 \\
  -p $env(BANDIT_PORT_VALUE) \\
  bandit32@$env(BANDIT_HOST_VALUE)
expect {
  "*password:" {
    send -- "$env(BANDIT_PASSWORD_VALUE)\\r"
    exp_continue
  }
  -re "WELCOME TO THE UPPERCASE SHELL|>>" {
  }
  timeout {
    exit 124
  }
}
after 500
send -- "\\$0\\r"
expect {
  -re {[$#] } {
  }
  timeout {
    exit 124
  }
}
send -- "cat /etc/bandit_pass/bandit33; exit\\r"
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
`;

const SCRIPT_INTERACTIVE = `
set timeout 30
spawn ssh \\
  -o StrictHostKeyChecking=no \\
  -o UserKnownHostsFile=/dev/null \\
  -o LogLevel=ERROR \\
  -o PubkeyAuthentication=no \\
  -o PreferredAuthentications=password \\
  -p $env(BANDIT_PORT_VALUE) \\
  $env(BANDIT_USER_VALUE)@$env(BANDIT_HOST_VALUE)
expect {
  "*password:" {
    send -- "$env(BANDIT_PASSWORD_VALUE)\\r"
    interact
  }
  timeout {
    interact
  }
  eof {
  }
}
`;

/* ---------- ssh + git helpers ---------- */

async function runPasswordSSHCommand(user, password, commandText) {
    const envExtra = {
        BANDIT_HOST_VALUE: state.host,
        BANDIT_PORT_VALUE: state.port,
        BANDIT_USER_VALUE: user,
        BANDIT_PASSWORD_VALUE: password,
        BANDIT_COMMAND_VALUE: commandText,
    };
    try {
        return await runExpect(SCRIPT_PASSWORD_SSH, envExtra);
    } catch (e) {
        throw new Error(`SSH command failed for ${user}: ${commandText}\n${e.message}`);
    }
}

async function runKeySSHCommand(user, keyFile, commandText) {
    const args = [
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes",
        "-i", keyFile,
        "-p", state.port,
        `${user}@${state.host}`,
        commandText,
    ];
    const r = await runCommand("ssh", args);
    if (r.exitCode !== 0) throw new Error(r.output);
    return r.output;
}

async function solvePassword(user, password, commandText) {
    const out = await runPasswordSSHCommand(user, password, commandText);
    return extractPassword(out);
}

async function solvePath(user, password, commandText) {
    const out = stripTerminalCodes(await runPasswordSSHCommand(user, password, commandText));
    const lines = out.split("\n");
    for (let i = lines.length - 1; i >= 0; i--) {
        if (lines[i].includes("/inhere/")) return lines[i];
    }
    throw new Error(`failed to extract path from output:\n${out}`);
}

async function savePrivateKey(name, output) {
    const m = stripTerminalCodes(output).match(PRIVATE_KEY_RE);
    if (!m) throw new Error(`failed to extract private key ${name} from output:\n${output}`);
    await ensureState();
    const keyFile = path.join(state.keyDir, name);
    await fs.writeFile(keyFile, m[0] + "\n", { mode: 0o600 });
    await fs.chmod(keyFile, 0o600);
    return keyFile;
}

async function solveBandit26Pair(keyFile) {
    const envExtra = {
        BANDIT_HOST_VALUE: state.host,
        BANDIT_PORT_VALUE: state.port,
        BANDIT_KEY_VALUE: keyFile,
    };
    const output = await runExpect(SCRIPT_BANDIT26, envExtra);
    const passwords = extractPasswords(output);
    if (passwords.length < 2) throw new Error(`expected two passwords from bandit26 output:\n${output}`);
    return [passwords[passwords.length - 2], passwords[passwords.length - 1]];
}

async function solveUppercaseShell(password) {
    const envExtra = {
        BANDIT_HOST_VALUE: state.host,
        BANDIT_PORT_VALUE: state.port,
        BANDIT_PASSWORD_VALUE: password,
    };
    return extractPassword(await runExpect(SCRIPT_UPPERCASE, envExtra));
}

function gitEnv(password, askpass) {
    return {
        BANDIT_GIT_PASSWORD: password,
        GIT_SSH_COMMAND:
            "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR " +
            "-o PubkeyAuthentication=no -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1",
        SSH_ASKPASS: askpass,
        SSH_ASKPASS_REQUIRE: "force",
        DISPLAY: envOr("DISPLAY", ":0"),
    };
}

async function writeAskpass(dir) {
    const askpass = path.join(dir, "askpass.sh");
    await fs.writeFile(askpass, "#!/usr/bin/env bash\nprintf '%s\\n' \"$BANDIT_GIT_PASSWORD\"\n", { mode: 0o700 });
    await fs.chmod(askpass, 0o700);
    return askpass;
}

async function gitCloneRepo(user, password, remotePath, destination) {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "bandit-git-askpass."));
    try {
        const askpass = await writeAskpass(tmp);
        const remote = `ssh://${user}@${state.host}:${state.port}${remotePath}`;
        const r = await runCommand("git", ["clone", remote, destination], { envExtra: gitEnv(password, askpass) });
        if (r.exitCode !== 0) throw new Error(r.output);
    } finally {
        await fs.rm(tmp, { recursive: true, force: true });
    }
}

async function gitPushWithPassword(password, repo) {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "bandit-git-askpass."));
    try {
        const askpass = await writeAskpass(tmp);
        const r = await runCommand("git", ["-C", repo, "push", "origin", "master"], { envExtra: gitEnv(password, askpass) });
        return r.output;
    } finally {
        await fs.rm(tmp, { recursive: true, force: true });
    }
}

/* ---------- template + step solving ---------- */

export function renderTemplate(template, values) {
    let out = template;
    for (const [k, v] of Object.entries(values)) {
        out = out.split(`{${k}}`).join(String(v));
    }
    return out;
}

function stepContext(level, password, toLevel) {
    return {
        password,
        level,
        to: toLevel,
        random_port: 20000 + Math.floor(Math.random() * 10000),
        temp_output: `/tmp/bandit${toLevel}pass.${process.pid}.${1000 + Math.floor(Math.random() * 9000)}`,
    };
}

function stepToList(step) {
    const v = step.to;
    if (typeof v === "number" || typeof v === "bigint") return [Number(v)];
    if (Array.isArray(v)) return v.map((x) => Number(x));
    throw new Error("step 'to' field has unsupported type");
}

function stepToSingle(step) {
    const list = stepToList(step);
    if (list.length !== 1) throw new Error("expected single 'to' target");
    return list[0];
}

async function solveStep(step, passwords) {
    const fromLevel = Number(step.from);
    const fromUser = step.user || `bandit${fromLevel}`;
    const fromPassword = passwords[fromLevel];
    if (!fromPassword) throw new Error(`missing password for bandit${fromLevel}`);

    switch (step.type) {
        case "ssh_command": {
            const toLevel = stepToSingle(step);
            const ctx = stepContext(fromLevel, fromPassword, toLevel);
            const command = renderTemplate(step.command, ctx);
            const pw = await solvePassword(fromUser, fromPassword, command);
            passwords[toLevel] = pw;
            await recordPassword(toLevel, pw);
            return;
        }
        case "path_then_command": {
            const toLevel = stepToSingle(step);
            const ctx = stepContext(fromLevel, fromPassword, toLevel);
            const findCmd = renderTemplate(step.find_command, ctx);
            const pathVal = await solvePath(fromUser, fromPassword, findCmd);
            ctx.path = pathVal;
            const command = renderTemplate(step.command, ctx);
            const pw = await solvePassword(fromUser, fromPassword, command);
            passwords[toLevel] = pw;
            await recordPassword(toLevel, pw);
            return;
        }
        case "private_key_then_ssh": {
            const toLevel = stepToSingle(step);
            const ctx = stepContext(fromLevel, fromPassword, toLevel);
            const keyCmd = renderTemplate(step.key_command, ctx);
            const output = await runPasswordSSHCommand(fromUser, fromPassword, keyCmd);
            const keyFile = await savePrivateKey(step.key_name, output);
            const nextCmd = renderTemplate(step.next_command, ctx);
            const keyOut = await runKeySSHCommand(step.next_user, keyFile, nextCmd);
            const pw = extractPassword(keyOut);
            passwords[toLevel] = pw;
            await recordPassword(toLevel, pw);
            return;
        }
        case "bandit26_escape": {
            const targets = stepToList(step);
            const ctx = stepContext(fromLevel, fromPassword, targets[targets.length - 1]);
            const keyCmd = renderTemplate(step.key_command, ctx);
            const output = await runPasswordSSHCommand(fromUser, fromPassword, keyCmd);
            const keyFile = await savePrivateKey(step.key_name, output);
            const solved = await solveBandit26Pair(keyFile);
            if (targets.length !== solved.length) {
                throw new Error(`bandit26_escape expected ${targets.length} targets, got ${solved.length} passwords`);
            }
            for (let i = 0; i < targets.length; i++) {
                passwords[targets[i]] = solved[i];
                await recordPassword(targets[i], solved[i]);
            }
            return;
        }
        case "git_read_file": {
            const toLevel = stepToSingle(step);
            const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "bandit-repo."));
            try {
                const repo = path.join(tmp, "repo");
                await gitCloneRepo(step.git_user, fromPassword, step.repo, repo);
                const content = await fs.readFile(path.join(repo, step.file), "utf8");
                const pw = extractPassword(content);
                passwords[toLevel] = pw;
                await recordPassword(toLevel, pw);
            } finally {
                await fs.rm(tmp, { recursive: true, force: true });
            }
            return;
        }
        case "git_show": {
            const toLevel = stepToSingle(step);
            const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "bandit-repo."));
            try {
                const repo = path.join(tmp, "repo");
                await gitCloneRepo(step.git_user, fromPassword, step.repo, repo);
                const r = await runCommand("git", ["-C", repo, "show", step.object]);
                if (r.exitCode !== 0) throw new Error(r.output);
                const pw = extractPassword(r.output);
                passwords[toLevel] = pw;
                await recordPassword(toLevel, pw);
            } finally {
                await fs.rm(tmp, { recursive: true, force: true });
            }
            return;
        }
        case "git_push_file": {
            const toLevel = stepToSingle(step);
            const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "bandit-repo."));
            try {
                const repo = path.join(tmp, "repo");
                await gitCloneRepo(step.git_user, fromPassword, step.repo, repo);
                const gitRun = async (args) => {
                    const r = await runCommand("git", ["-C", repo, ...args]);
                    if (r.exitCode !== 0) throw new Error(r.output);
                };
                await gitRun(["config", "user.email", "bandit-solver@example.invalid"]);
                await gitRun(["config", "user.name", "bandit-solver"]);
                await fs.writeFile(path.join(repo, step.file), step.content);
                await gitRun(["add", "-f", step.file]);
                await gitRun(["commit", "-m", step.commit_message]);
                const pushOut = await gitPushWithPassword(fromPassword, repo);
                const pw = extractPassword(pushOut);
                passwords[toLevel] = pw;
                await recordPassword(toLevel, pw);
            } finally {
                await fs.rm(tmp, { recursive: true, force: true });
            }
            return;
        }
        case "uppercase_shell": {
            const toLevel = stepToSingle(step);
            const pw = await solveUppercaseShell(fromPassword);
            passwords[toLevel] = pw;
            await recordPassword(toLevel, pw);
            return;
        }
        default:
            throw new Error(`unsupported step type: ${step.type}`);
    }
}

/* ---------- config ---------- */

export function validateConfig(cfg) {
    if (!cfg.bootstrap || cfg.bootstrap.password === undefined) throw new Error("config bootstrap password is empty");
    if (!Array.isArray(cfg.steps) || cfg.steps.length === 0) throw new Error("config has no steps");
    cfg.steps.forEach((step, idx) => {
        const required = REQUIRED_FIELDS[step.type];
        if (!required) throw new Error(`step ${idx + 1} has unsupported type "${step.type}"`);
        for (const field of required) {
            if (!(field in step)) throw new Error(`step ${idx + 1} (${step.type}) is missing ${field}`);
        }
    });
}

async function loadConfig() {
    const text = await fs.readFile(state.configPath, "utf8");
    let cfg;
    try {
        cfg = parseToml(text);
    } catch (e) {
        die(`parse config: ${e.message}`);
    }
    validateConfig(cfg);
    return cfg;
}

function applyConnection(cfg) {
    state.host = envOr("BANDIT_HOST", cfg.connection?.host || DEFAULT_HOST);
    const envPort = env.BANDIT_PORT;
    if (envPort && envPort.length > 0) state.port = envPort;
    else if (cfg.connection?.port) state.port = String(cfg.connection.port);
    else state.port = DEFAULT_PORT;
}

/* ---------- top-level actions ---------- */

async function refresh(cfg) {
    await checkDependencies();
    await ensureState();

    stdout.write(`Refreshing Bandit passwords via ${state.host}:${state.port}\n`);
    stdout.write(`Level config:  ${state.configPath}\n`);
    stdout.write(`Password file: ${state.passFile}\n`);
    stdout.write(`Key cache:     ${state.keyDir}\n\n`);

    const passwords = {};
    passwords[cfg.bootstrap.level] = cfg.bootstrap.password;
    await recordPassword(Number(cfg.bootstrap.level), cfg.bootstrap.password);

    for (const step of cfg.steps) await solveStep(step, passwords);

    stdout.write("\nRefresh complete.\n");
}

async function showPasswords() {
    await ensureState();
    const data = await fs.readFile(state.passFile, "utf8");
    if (data.length === 0) stdout.write("No passwords saved yet.\n");
    else stdout.write(data);
}

async function sshLevel(level) {
    await ensureState();
    const user = `bandit${level}`;
    const password = await getSavedPassword(user);
    if (!password) {
        const child = spawn("ssh", [`${user}@${state.host}`, "-p", state.port], { stdio: "inherit" });
        await new Promise((res) => child.on("close", res));
        return;
    }
    const scriptFile = path.join(os.tmpdir(), `bandit-ssh.${process.pid}.${Date.now()}.exp`);
    await fs.writeFile(scriptFile, SCRIPT_INTERACTIVE);
    try {
        const child = spawn("expect", ["-f", scriptFile], {
            stdio: "inherit",
            env: {
                ...env,
                BANDIT_HOST_VALUE: state.host,
                BANDIT_PORT_VALUE: state.port,
                BANDIT_USER_VALUE: user,
                BANDIT_PASSWORD_VALUE: password,
            },
        });
        await new Promise((res) => child.on("close", res));
    } finally {
        await fs.rm(scriptFile, { force: true });
    }
}

async function savePasswordInteractive(rl) {
    const username = (await rl.question("Save password for which user? Example: bandit6: ")).trim();
    const password = (await rl.question("Password: ")).trim();
    await savePassword(username, password);
    stdout.write(`Saved password for ${username}.\n`);
}

async function menu(cfg) {
    await ensureState();
    const rl = createInterface({ input: stdin, output: stdout });
    try {
        while (true) {
            stdout.write("====================================\n");
            stdout.write("        OverTheWire Bandit App\n");
            stdout.write("====================================\n\n");
            stdout.write(`Password file: ${state.passFile}\n`);
            stdout.write(`Key cache:     ${state.keyDir}\n\n`);
            stdout.write("1) SSH into a Bandit level\n");
            stdout.write("2) Refresh all passwords\n");
            stdout.write("3) Save/update a password\n");
            stdout.write("4) Show saved passwords\n");
            stdout.write("5) Exit\n\n");
            const choice = (await rl.question("Choose an option: ")).trim();
            if (choice === "1") {
                const lvl = (await rl.question("Bandit level number, e.g. 0, 1, 26, 33: ")).trim();
                await sshLevel(parseInt(lvl, 10));
            } else if (choice === "2") {
                await refresh(cfg);
                await rl.question("Press Enter to continue...");
            } else if (choice === "3") {
                await savePasswordInteractive(rl);
            } else if (choice === "4") {
                await showPasswords();
                await rl.question("Press Enter to continue...");
            } else if (choice === "5") {
                return;
            } else {
                stdout.write("Invalid option.\n");
            }
        }
    } finally {
        rl.close();
    }
}

/* ---------- main ---------- */

async function main() {
    state.repoRoot = findRepoRoot();
    const defaultConfig = path.join(state.repoRoot, "levels", "bandit-levels.toml");
    state.configPath = envOr("BANDIT_LEVELS_FILE", defaultConfig);
    state.passFile = path.join(state.repoRoot, "bandit-passwords.txt");
    state.keyDir = path.join(state.repoRoot, ".bandit-keys");

    let refreshFlag = false;
    let showFlag = false;
    let sshLvl = -1;

    const args = argv.slice(2);
    for (let i = 0; i < args.length; i++) {
        switch (args[i]) {
            case "--config":
                if (++i >= args.length) die("--config requires a path");
                state.configPath = args[i];
                break;
            case "--refresh":
                refreshFlag = true;
                break;
            case "--show":
                showFlag = true;
                break;
            case "--ssh":
                if (++i >= args.length) die("--ssh requires a level");
                sshLvl = parseInt(args[i], 10);
                break;
            default:
                die(`unknown flag: ${args[i]}`);
        }
    }

    const cfg = await loadConfig();
    applyConnection(cfg);

    if (refreshFlag) await refresh(cfg);
    else if (showFlag) await showPasswords();
    else if (sshLvl >= 0) await sshLevel(sshLvl);
    else await menu(cfg);
}

const thisFile = fileURLToPath(import.meta.url);
if (process.argv[1] === thisFile) {
    main().catch((e) => {
        stderr.write(`error: ${e.message}\n`);
        exit(1);
    });
}
