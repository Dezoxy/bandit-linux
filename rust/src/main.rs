use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use rand::Rng;
use regex::Regex;
use toml::Value;

const DEFAULT_HOST: &str = "bandit.labs.overthewire.org";
const DEFAULT_PORT: &str = "2220";

fn password_re() -> &'static Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[A-Za-z0-9]{32}").unwrap())
}

fn private_key_re() -> &'static Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----")
            .unwrap()
    })
}

fn ansi_re() -> &'static Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?s)\x1b\[[0-?]*[ -/]*[@-~]|\x1bP.*?\x1b\\|\x1b\].*?(?:\x07|\x1b\\)|\x1b.",
        )
        .unwrap()
    })
}

const SCRIPT_PASSWORD_SSH: &str = r#"
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
"#;

const SCRIPT_BANDIT26: &str = r#"
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
"#;

const SCRIPT_UPPERCASE: &str = r#"
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
"#;

const SCRIPT_INTERACTIVE: &str = r#"
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
"#;

fn required_fields() -> HashMap<&'static str, &'static [&'static str]> {
    let mut m: HashMap<&'static str, &'static [&'static str]> = HashMap::new();
    m.insert("ssh_command", &["from", "to", "command"]);
    m.insert("path_then_command", &["from", "to", "find_command", "command"]);
    m.insert(
        "private_key_then_ssh",
        &["from", "to", "key_command", "key_name", "next_user", "next_command"],
    );
    m.insert("bandit26_escape", &["from", "to", "key_command", "key_name"]);
    m.insert("git_read_file", &["from", "to", "git_user", "repo", "file"]);
    m.insert("git_show", &["from", "to", "git_user", "repo", "object"]);
    m.insert(
        "git_push_file",
        &["from", "to", "git_user", "repo", "file", "content", "commit_message"],
    );
    m.insert("uppercase_shell", &["from", "to"]);
    m
}

#[derive(Debug)]
struct Step {
    type_: String,
    table: toml::value::Table,
}

impl Step {
    fn must_string(&self, key: &str) -> Result<String, String> {
        self.table
            .get(key)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| format!("missing string field {key}"))
    }

    fn field_string(&self, key: &str, fallback: &str) -> String {
        self.table
            .get(key)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| fallback.to_string())
    }

    fn must_int(&self, key: &str) -> Result<i64, String> {
        self.table
            .get(key)
            .and_then(|v| v.as_integer())
            .ok_or_else(|| format!("missing int field {key}"))
    }

    fn must_to_list(&self) -> Result<Vec<i64>, String> {
        match self.table.get("to") {
            Some(Value::Integer(i)) => Ok(vec![*i]),
            Some(Value::Array(arr)) => arr
                .iter()
                .map(|v| v.as_integer().ok_or_else(|| "to array contains non-int".to_string()))
                .collect(),
            None => Err("missing to field".to_string()),
            _ => Err("to field has unsupported type".to_string()),
        }
    }

    fn must_to_single(&self) -> Result<i64, String> {
        let list = self.must_to_list()?;
        if list.len() != 1 {
            return Err("expected single 'to' target".to_string());
        }
        Ok(list[0])
    }
}

#[derive(Debug)]
struct Config {
    host: String,
    port: i64,
    bootstrap_level: i64,
    bootstrap_password: String,
    steps: Vec<Step>,
}

struct App {
    host: String,
    port: String,
    #[allow(dead_code)]
    repo_root: PathBuf,
    config_path: PathBuf,
    pass_file: PathBuf,
    key_dir: PathBuf,
}

fn env_or(name: &str, fallback: &str) -> String {
    match env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => fallback.to_string(),
    }
}

fn find_repo_root() -> Result<PathBuf, String> {
    let mut cwd = env::current_dir().map_err(|e| format!("getcwd: {e}"))?;
    loop {
        if cwd.join("levels").join("bandit-levels.toml").exists() {
            return Ok(cwd);
        }
        if !cwd.pop() {
            return Err("could not find repo root containing levels/bandit-levels.toml".to_string());
        }
    }
}

fn set_perms(path: &Path, mode: u32) -> io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

fn which(cmd: &str) -> Option<PathBuf> {
    let path = env::var("PATH").ok()?;
    for dir in env::split_paths(&path) {
        let candidate = dir.join(cmd);
        if let Ok(meta) = fs::metadata(&candidate) {
            if meta.is_file() && (meta.permissions().mode() & 0o111) != 0 {
                return Some(candidate);
            }
        }
    }
    None
}

fn check_dependencies() -> Result<(), String> {
    for cmd in ["expect", "ssh", "git", "awk", "grep", "mktemp"] {
        if which(cmd).is_none() {
            return Err(format!("missing required command: {cmd}"));
        }
    }
    Ok(())
}

pub fn strip_terminal_codes(text: &str) -> String {
    let stripped = ansi_re().replace_all(text, "");
    stripped.replace('\r', "")
}

pub fn extract_passwords(text: &str) -> Vec<String> {
    let clean = strip_terminal_codes(text);
    password_re()
        .find_iter(&clean)
        .map(|m| m.as_str().to_string())
        .collect()
}

pub fn extract_password(text: &str) -> Result<String, String> {
    let ps = extract_passwords(text);
    ps.into_iter()
        .last()
        .ok_or_else(|| format!("failed to extract a 32-character password from output:\n{text}"))
}

pub fn render_template(template: &str, values: &HashMap<&str, String>) -> String {
    let mut out = template.to_string();
    for (k, v) in values {
        out = out.replace(&format!("{{{k}}}"), v);
    }
    out
}

struct ProcResult {
    exit_code: i32,
    output: String,
}

fn run_command(
    name: &str,
    args: &[&str],
    env_extra: &[(&str, &str)],
    input: Option<&str>,
    cwd: Option<&Path>,
) -> io::Result<ProcResult> {
    let mut cmd = Command::new(name);
    cmd.args(args);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    for (k, v) in env_extra {
        cmd.env(k, v);
    }
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    if input.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }

    let mut child = cmd.spawn()?;
    if let Some(text) = input {
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(text.as_bytes())?;
        }
    }
    let mut stdout_buf = String::new();
    let mut stderr_buf = String::new();
    if let Some(mut out) = child.stdout.take() {
        out.read_to_string(&mut stdout_buf)?;
    }
    if let Some(mut err) = child.stderr.take() {
        err.read_to_string(&mut stderr_buf)?;
    }
    let status = child.wait()?;
    let mut output = stdout_buf;
    output.push_str(&stderr_buf);
    Ok(ProcResult {
        exit_code: status.code().unwrap_or(-1),
        output,
    })
}

fn run_expect(script: &str, env_extra: &[(&str, &str)]) -> Result<String, String> {
    let r = run_command("expect", &[], env_extra, Some(script), None)
        .map_err(|e| format!("expect: {e}"))?;
    if r.exit_code != 0 {
        return Err(r.output);
    }
    Ok(r.output)
}

impl App {
    fn ensure_state(&self) -> io::Result<()> {
        fs::create_dir_all(&self.key_dir)?;
        set_perms(&self.key_dir, 0o700)?;
        if !self.pass_file.exists() {
            fs::write(&self.pass_file, b"")?;
        }
        set_perms(&self.pass_file, 0o600)?;
        Ok(())
    }

    fn save_password(&self, user: &str, password: &str) -> Result<(), String> {
        self.ensure_state().map_err(|e| e.to_string())?;
        let mut lines: Vec<String> = Vec::new();
        if self.pass_file.exists() {
            let content = fs::read_to_string(&self.pass_file).map_err(|e| e.to_string())?;
            for line in content.split('\n') {
                if line.is_empty() || line.starts_with(&format!("{user}:")) {
                    continue;
                }
                lines.push(line.to_string());
            }
        }
        lines.push(format!("{user}: {password}"));
        let body = format!("{}\n", lines.join("\n"));
        fs::write(&self.pass_file, body).map_err(|e| e.to_string())?;
        set_perms(&self.pass_file, 0o600).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn get_saved_password(&self, user: &str) -> String {
        if !self.pass_file.exists() {
            return String::new();
        }
        let content = match fs::read_to_string(&self.pass_file) {
            Ok(s) => s,
            Err(_) => return String::new(),
        };
        let prefix = format!("{user}: ");
        let mut password = String::new();
        for line in content.split('\n') {
            if let Some(rest) = line.strip_prefix(&prefix) {
                password = rest.to_string();
            }
        }
        password
    }

    fn record_password(&self, level: i64, password: &str) -> Result<(), String> {
        let user = format!("bandit{level}");
        if level != 0 && !password_re().is_match(password) {
            return Err(format!("refusing to save invalid password for {user}: {password}"));
        }
        self.save_password(&user, password)?;
        println!("[+] {:<8} {password}", user);
        Ok(())
    }

    fn run_password_ssh_command(
        &self,
        user: &str,
        password: &str,
        command_text: &str,
    ) -> Result<String, String> {
        let env_extra = [
            ("BANDIT_HOST_VALUE", self.host.as_str()),
            ("BANDIT_PORT_VALUE", self.port.as_str()),
            ("BANDIT_USER_VALUE", user),
            ("BANDIT_PASSWORD_VALUE", password),
            ("BANDIT_COMMAND_VALUE", command_text),
        ];
        run_expect(SCRIPT_PASSWORD_SSH, &env_extra)
            .map_err(|e| format!("SSH command failed for {user}: {command_text}\n{e}"))
    }

    fn run_key_ssh_command(
        &self,
        user: &str,
        key_file: &Path,
        command_text: &str,
    ) -> Result<String, String> {
        let target = format!("{user}@{}", self.host);
        let key_str = key_file.to_string_lossy().to_string();
        let args = [
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            "-o", "IdentitiesOnly=yes",
            "-o", "BatchMode=yes",
            "-i", key_str.as_str(),
            "-p", self.port.as_str(),
            target.as_str(),
            command_text,
        ];
        let r = run_command("ssh", &args, &[], None, None).map_err(|e| e.to_string())?;
        if r.exit_code != 0 {
            return Err(r.output);
        }
        Ok(r.output)
    }

    fn solve_password(
        &self,
        user: &str,
        password: &str,
        command_text: &str,
    ) -> Result<String, String> {
        let out = self.run_password_ssh_command(user, password, command_text)?;
        extract_password(&out)
    }

    fn solve_path(
        &self,
        user: &str,
        password: &str,
        command_text: &str,
    ) -> Result<String, String> {
        let raw = self.run_password_ssh_command(user, password, command_text)?;
        let clean = strip_terminal_codes(&raw);
        let mut found = None;
        for line in clean.split('\n') {
            if line.contains("/inhere/") {
                found = Some(line.to_string());
            }
        }
        found.ok_or_else(|| format!("failed to extract path from output:\n{clean}"))
    }

    fn save_private_key(&self, name: &str, output: &str) -> Result<PathBuf, String> {
        let clean = strip_terminal_codes(output);
        let m = private_key_re()
            .find(&clean)
            .ok_or_else(|| format!("failed to extract private key {name} from output:\n{output}"))?;
        self.ensure_state().map_err(|e| e.to_string())?;
        let key_file = self.key_dir.join(name);
        let body = format!("{}\n", m.as_str());
        fs::write(&key_file, body).map_err(|e| e.to_string())?;
        set_perms(&key_file, 0o600).map_err(|e| e.to_string())?;
        Ok(key_file)
    }

    fn solve_bandit26_pair(&self, key_file: &Path) -> Result<(String, String), String> {
        let key_str = key_file.to_string_lossy().to_string();
        let env_extra = [
            ("BANDIT_HOST_VALUE", self.host.as_str()),
            ("BANDIT_PORT_VALUE", self.port.as_str()),
            ("BANDIT_KEY_VALUE", key_str.as_str()),
        ];
        let output = run_expect(SCRIPT_BANDIT26, &env_extra)?;
        let passwords = extract_passwords(&output);
        if passwords.len() < 2 {
            return Err(format!("expected two passwords from bandit26 output:\n{output}"));
        }
        Ok((
            passwords[passwords.len() - 2].clone(),
            passwords[passwords.len() - 1].clone(),
        ))
    }

    fn solve_uppercase_shell(&self, password: &str) -> Result<String, String> {
        let env_extra = [
            ("BANDIT_HOST_VALUE", self.host.as_str()),
            ("BANDIT_PORT_VALUE", self.port.as_str()),
            ("BANDIT_PASSWORD_VALUE", password),
        ];
        extract_password(&run_expect(SCRIPT_UPPERCASE, &env_extra)?)
    }

    fn git_env<'a>(&'a self, password: &'a str, askpass: &'a str, display: &'a str) -> [(&'a str, &'a str); 5] {
        [
            ("BANDIT_GIT_PASSWORD", password),
            (
                "GIT_SSH_COMMAND",
                "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
                 -o PubkeyAuthentication=no -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1",
            ),
            ("SSH_ASKPASS", askpass),
            ("SSH_ASKPASS_REQUIRE", "force"),
            ("DISPLAY", display),
        ]
    }

    fn write_askpass(&self, dir: &Path) -> Result<PathBuf, String> {
        let askpass = dir.join("askpass.sh");
        fs::write(
            &askpass,
            "#!/usr/bin/env bash\nprintf '%s\\n' \"$BANDIT_GIT_PASSWORD\"\n",
        )
        .map_err(|e| e.to_string())?;
        set_perms(&askpass, 0o700).map_err(|e| e.to_string())?;
        Ok(askpass)
    }

    fn git_clone_repo(
        &self,
        user: &str,
        password: &str,
        remote_path: &str,
        destination: &Path,
    ) -> Result<(), String> {
        let tmp = mkdtemp("bandit-git-askpass.")?;
        let result = (|| -> Result<(), String> {
            let askpass = self.write_askpass(&tmp)?;
            let display = env_or("DISPLAY", ":0");
            let askpass_str = askpass.to_string_lossy().to_string();
            let env_extra = self.git_env(password, &askpass_str, &display);
            let remote = format!("ssh://{user}@{}:{}{remote_path}", self.host, self.port);
            let dest = destination.to_string_lossy().to_string();
            let args = ["clone", remote.as_str(), dest.as_str()];
            let r = run_command("git", &args, &env_extra, None, None)
                .map_err(|e| e.to_string())?;
            if r.exit_code != 0 {
                return Err(r.output);
            }
            Ok(())
        })();
        let _ = fs::remove_dir_all(&tmp);
        result
    }

    fn git_push_with_password(&self, password: &str, repo: &Path) -> Result<String, String> {
        let tmp = mkdtemp("bandit-git-askpass.")?;
        let result = (|| -> Result<String, String> {
            let askpass = self.write_askpass(&tmp)?;
            let display = env_or("DISPLAY", ":0");
            let askpass_str = askpass.to_string_lossy().to_string();
            let env_extra = self.git_env(password, &askpass_str, &display);
            let repo_str = repo.to_string_lossy().to_string();
            let args = ["-C", repo_str.as_str(), "push", "origin", "master"];
            let r = run_command("git", &args, &env_extra, None, None).map_err(|e| e.to_string())?;
            Ok(r.output)
        })();
        let _ = fs::remove_dir_all(&tmp);
        result
    }

    fn step_context(&self, level: i64, password: &str, to_level: i64) -> HashMap<&'static str, String> {
        let mut rng = rand::thread_rng();
        let mut m = HashMap::new();
        m.insert("password", password.to_string());
        m.insert("level", level.to_string());
        m.insert("to", to_level.to_string());
        m.insert("random_port", (20000 + rng.gen_range(0..10000)).to_string());
        m.insert(
            "temp_output",
            format!("/tmp/bandit{to_level}pass.{}.{}", std::process::id(), 1000 + rng.gen_range(0..9000)),
        );
        m
    }

    fn refresh(&self, cfg: &Config) -> Result<(), String> {
        check_dependencies()?;
        self.ensure_state().map_err(|e| e.to_string())?;

        println!("Refreshing Bandit passwords via {}:{}", self.host, self.port);
        println!("Level config:  {}", self.config_path.display());
        println!("Password file: {}", self.pass_file.display());
        println!("Key cache:     {}\n", self.key_dir.display());

        let mut passwords: HashMap<i64, String> = HashMap::new();
        passwords.insert(cfg.bootstrap_level, cfg.bootstrap_password.clone());
        self.record_password(cfg.bootstrap_level, &cfg.bootstrap_password)?;

        for step in &cfg.steps {
            self.solve_step(step, &mut passwords)?;
        }

        println!("\nRefresh complete.");
        Ok(())
    }

    fn solve_step(
        &self,
        step: &Step,
        passwords: &mut HashMap<i64, String>,
    ) -> Result<(), String> {
        let from_level = step.must_int("from")?;
        let from_user = step.field_string("user", &format!("bandit{from_level}"));
        let from_password = passwords
            .get(&from_level)
            .cloned()
            .ok_or_else(|| format!("missing password for bandit{from_level}"))?;

        match step.type_.as_str() {
            "ssh_command" => {
                let to_level = step.must_to_single()?;
                let ctx = self.step_context(from_level, &from_password, to_level);
                let ctx_borrowed: HashMap<&str, String> =
                    ctx.iter().map(|(k, v)| (*k, v.clone())).collect();
                let cmd = render_template(&step.must_string("command")?, &ctx_borrowed);
                let pw = self.solve_password(&from_user, &from_password, &cmd)?;
                passwords.insert(to_level, pw.clone());
                self.record_password(to_level, &pw)?;
            }
            "path_then_command" => {
                let to_level = step.must_to_single()?;
                let mut ctx = self.step_context(from_level, &from_password, to_level);
                let ctx_borrowed: HashMap<&str, String> =
                    ctx.iter().map(|(k, v)| (*k, v.clone())).collect();
                let find_cmd =
                    render_template(&step.must_string("find_command")?, &ctx_borrowed);
                let path = self.solve_path(&from_user, &from_password, &find_cmd)?;
                ctx.insert("path", path);
                let ctx_borrowed: HashMap<&str, String> =
                    ctx.iter().map(|(k, v)| (*k, v.clone())).collect();
                let cmd = render_template(&step.must_string("command")?, &ctx_borrowed);
                let pw = self.solve_password(&from_user, &from_password, &cmd)?;
                passwords.insert(to_level, pw.clone());
                self.record_password(to_level, &pw)?;
            }
            "private_key_then_ssh" => {
                let to_level = step.must_to_single()?;
                let ctx = self.step_context(from_level, &from_password, to_level);
                let ctx_borrowed: HashMap<&str, String> =
                    ctx.iter().map(|(k, v)| (*k, v.clone())).collect();
                let key_cmd =
                    render_template(&step.must_string("key_command")?, &ctx_borrowed);
                let output = self.run_password_ssh_command(&from_user, &from_password, &key_cmd)?;
                let key_file = self.save_private_key(&step.must_string("key_name")?, &output)?;
                let next_cmd =
                    render_template(&step.must_string("next_command")?, &ctx_borrowed);
                let next_user = step.must_string("next_user")?;
                let key_output = self.run_key_ssh_command(&next_user, &key_file, &next_cmd)?;
                let pw = extract_password(&key_output)?;
                passwords.insert(to_level, pw.clone());
                self.record_password(to_level, &pw)?;
            }
            "bandit26_escape" => {
                let targets = step.must_to_list()?;
                let last = *targets.last().unwrap();
                let ctx = self.step_context(from_level, &from_password, last);
                let ctx_borrowed: HashMap<&str, String> =
                    ctx.iter().map(|(k, v)| (*k, v.clone())).collect();
                let key_cmd =
                    render_template(&step.must_string("key_command")?, &ctx_borrowed);
                let output = self.run_password_ssh_command(&from_user, &from_password, &key_cmd)?;
                let key_file = self.save_private_key(&step.must_string("key_name")?, &output)?;
                let (pw1, pw2) = self.solve_bandit26_pair(&key_file)?;
                let solved = [pw1, pw2];
                if targets.len() != solved.len() {
                    return Err(format!(
                        "bandit26_escape expected {} targets, got {} passwords",
                        targets.len(),
                        solved.len()
                    ));
                }
                for (i, target) in targets.iter().enumerate() {
                    passwords.insert(*target, solved[i].clone());
                    self.record_password(*target, &solved[i])?;
                }
            }
            "git_read_file" => {
                let to_level = step.must_to_single()?;
                let tmp = mkdtemp("bandit-repo.")?;
                let result = (|| -> Result<(), String> {
                    let repo = tmp.join("repo");
                    self.git_clone_repo(
                        &step.must_string("git_user")?,
                        &from_password,
                        &step.must_string("repo")?,
                        &repo,
                    )?;
                    let content = fs::read_to_string(repo.join(step.must_string("file")?))
                        .map_err(|e| e.to_string())?;
                    let pw = extract_password(&content)?;
                    passwords.insert(to_level, pw.clone());
                    self.record_password(to_level, &pw)?;
                    Ok(())
                })();
                let _ = fs::remove_dir_all(&tmp);
                result?;
            }
            "git_show" => {
                let to_level = step.must_to_single()?;
                let tmp = mkdtemp("bandit-repo.")?;
                let result = (|| -> Result<(), String> {
                    let repo = tmp.join("repo");
                    self.git_clone_repo(
                        &step.must_string("git_user")?,
                        &from_password,
                        &step.must_string("repo")?,
                        &repo,
                    )?;
                    let repo_str = repo.to_string_lossy().to_string();
                    let object = step.must_string("object")?;
                    let args = ["-C", repo_str.as_str(), "show", object.as_str()];
                    let r = run_command("git", &args, &[], None, None)
                        .map_err(|e| e.to_string())?;
                    if r.exit_code != 0 {
                        return Err(r.output);
                    }
                    let pw = extract_password(&r.output)?;
                    passwords.insert(to_level, pw.clone());
                    self.record_password(to_level, &pw)?;
                    Ok(())
                })();
                let _ = fs::remove_dir_all(&tmp);
                result?;
            }
            "git_push_file" => {
                let to_level = step.must_to_single()?;
                let tmp = mkdtemp("bandit-repo.")?;
                let result = (|| -> Result<(), String> {
                    let repo = tmp.join("repo");
                    self.git_clone_repo(
                        &step.must_string("git_user")?,
                        &from_password,
                        &step.must_string("repo")?,
                        &repo,
                    )?;
                    let repo_str = repo.to_string_lossy().to_string();
                    let git_run = |args: &[&str]| -> Result<(), String> {
                        let mut full = vec!["-C", repo_str.as_str()];
                        full.extend_from_slice(args);
                        let r = run_command("git", &full, &[], None, None)
                            .map_err(|e| e.to_string())?;
                        if r.exit_code != 0 {
                            return Err(r.output);
                        }
                        Ok(())
                    };
                    git_run(&["config", "user.email", "bandit-solver@example.invalid"])?;
                    git_run(&["config", "user.name", "bandit-solver"])?;
                    let file = step.must_string("file")?;
                    let content = step.must_string("content")?;
                    fs::write(repo.join(&file), content).map_err(|e| e.to_string())?;
                    git_run(&["add", "-f", &file])?;
                    let msg = step.must_string("commit_message")?;
                    git_run(&["commit", "-m", &msg])?;
                    let push_out = self.git_push_with_password(&from_password, &repo)?;
                    let pw = extract_password(&push_out)?;
                    passwords.insert(to_level, pw.clone());
                    self.record_password(to_level, &pw)?;
                    Ok(())
                })();
                let _ = fs::remove_dir_all(&tmp);
                result?;
            }
            "uppercase_shell" => {
                let to_level = step.must_to_single()?;
                let pw = self.solve_uppercase_shell(&from_password)?;
                passwords.insert(to_level, pw.clone());
                self.record_password(to_level, &pw)?;
            }
            other => return Err(format!("unsupported step type: {other}")),
        }
        Ok(())
    }

    fn show_passwords(&self) -> Result<(), String> {
        self.ensure_state().map_err(|e| e.to_string())?;
        let data = fs::read_to_string(&self.pass_file).map_err(|e| e.to_string())?;
        if data.is_empty() {
            println!("No passwords saved yet.");
        } else {
            print!("{data}");
        }
        Ok(())
    }

    fn ssh_level(&self, level: i64) -> Result<(), String> {
        self.ensure_state().map_err(|e| e.to_string())?;
        let user = format!("bandit{level}");
        let password = self.get_saved_password(&user);
        if password.is_empty() {
            let target = format!("{user}@{}", self.host);
            let status = Command::new("ssh")
                .args([&target, "-p", &self.port])
                .status()
                .map_err(|e| e.to_string())?;
            let _ = status;
            return Ok(());
        }
        let tmp_path = env::temp_dir().join(format!("bandit-ssh.{}.exp", std::process::id()));
        fs::write(&tmp_path, SCRIPT_INTERACTIVE).map_err(|e| e.to_string())?;
        let status = Command::new("expect")
            .arg("-f")
            .arg(&tmp_path)
            .env("BANDIT_HOST_VALUE", &self.host)
            .env("BANDIT_PORT_VALUE", &self.port)
            .env("BANDIT_USER_VALUE", &user)
            .env("BANDIT_PASSWORD_VALUE", &password)
            .status()
            .map_err(|e| e.to_string())?;
        let _ = fs::remove_file(&tmp_path);
        let _ = status;
        Ok(())
    }

    fn save_password_interactive(&self) -> Result<(), String> {
        let mut user = String::new();
        let mut password = String::new();
        print!("Save password for which user? Example: bandit6: ");
        io::stdout().flush().ok();
        io::stdin().lock().read_line(&mut user).map_err(|e| e.to_string())?;
        print!("Password: ");
        io::stdout().flush().ok();
        io::stdin().lock().read_line(&mut password).map_err(|e| e.to_string())?;
        let user = user.trim();
        let password = password.trim();
        self.save_password(user, password)?;
        println!("Saved password for {user}.");
        Ok(())
    }

    fn menu(&self, cfg: &Config) -> Result<(), String> {
        self.ensure_state().map_err(|e| e.to_string())?;
        loop {
            println!("====================================");
            println!("        OverTheWire Bandit App");
            println!("====================================\n");
            println!("Password file: {}", self.pass_file.display());
            println!("Key cache:     {}\n", self.key_dir.display());
            println!("1) SSH into a Bandit level");
            println!("2) Refresh all passwords");
            println!("3) Save/update a password");
            println!("4) Show saved passwords");
            println!("5) Exit\n");
            print!("Choose an option: ");
            io::stdout().flush().ok();
            let mut choice = String::new();
            if io::stdin().lock().read_line(&mut choice).is_err() {
                return Ok(());
            }
            match choice.trim() {
                "1" => {
                    print!("Bandit level number, e.g. 0, 1, 26, 33: ");
                    io::stdout().flush().ok();
                    let mut lvl = String::new();
                    io::stdin().lock().read_line(&mut lvl).map_err(|e| e.to_string())?;
                    let level: i64 = lvl.trim().parse().map_err(|e: std::num::ParseIntError| e.to_string())?;
                    self.ssh_level(level)?;
                }
                "2" => {
                    self.refresh(cfg)?;
                    print!("Press Enter to continue...");
                    io::stdout().flush().ok();
                    let mut tmp = String::new();
                    let _ = io::stdin().lock().read_line(&mut tmp);
                }
                "3" => self.save_password_interactive()?,
                "4" => {
                    self.show_passwords()?;
                    print!("Press Enter to continue...");
                    io::stdout().flush().ok();
                    let mut tmp = String::new();
                    let _ = io::stdin().lock().read_line(&mut tmp);
                }
                "5" => return Ok(()),
                _ => println!("Invalid option."),
            }
        }
    }
}

fn mkdtemp(prefix: &str) -> Result<PathBuf, String> {
    let mut rng = rand::thread_rng();
    for _ in 0..16 {
        let candidate: String = (0..8).map(|_| {
            let idx = rng.gen_range(0..62);
            match idx {
                0..=9 => (b'0' + idx as u8) as char,
                10..=35 => (b'a' + (idx - 10) as u8) as char,
                _ => (b'A' + (idx - 36) as u8) as char,
            }
        }).collect();
        let path = env::temp_dir().join(format!("{prefix}{candidate}"));
        match fs::create_dir(&path) {
            Ok(()) => {
                set_perms(&path, 0o700).map_err(|e| e.to_string())?;
                return Ok(path);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("mkdtemp: {e}")),
        }
    }
    Err("mkdtemp: failed after 16 attempts".to_string())
}

pub fn validate_config(value: &Value) -> Result<(), String> {
    let table = value.as_table().ok_or_else(|| "config root is not a table".to_string())?;
    let bootstrap = table
        .get("bootstrap")
        .and_then(|v| v.as_table())
        .ok_or_else(|| "config is missing [bootstrap]".to_string())?;
    if !bootstrap.contains_key("level") {
        return Err("config bootstrap level is missing".to_string());
    }
    let pass = bootstrap
        .get("password")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "config bootstrap password is empty".to_string())?;
    if pass.is_empty() {
        return Err("config bootstrap password is empty".to_string());
    }
    let steps = table
        .get("steps")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "config has no steps".to_string())?;
    if steps.is_empty() {
        return Err("config has no steps".to_string());
    }
    let required = required_fields();
    for (i, step) in steps.iter().enumerate() {
        let t = step
            .as_table()
            .ok_or_else(|| format!("step {} is not a table", i + 1))?;
        let typ = t
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("step {} is missing type", i + 1))?;
        let req = required
            .get(typ)
            .ok_or_else(|| format!("step {} has unsupported type \"{}\"", i + 1, typ))?;
        for f in *req {
            if !t.contains_key(*f) {
                return Err(format!("step {} ({}) is missing {}", i + 1, typ, f));
            }
        }
    }
    Ok(())
}

fn load_config(path: &Path) -> Result<Config, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("read config: {e}"))?;
    let value: Value = toml::from_str(&text).map_err(|e| format!("parse config: {e}"))?;
    validate_config(&value)?;
    let table = value.as_table().unwrap();

    let mut host_cfg = String::new();
    let mut port_cfg: i64 = 0;
    if let Some(conn) = table.get("connection").and_then(|v| v.as_table()) {
        if let Some(h) = conn.get("host").and_then(|v| v.as_str()) {
            host_cfg = h.to_string();
        }
        if let Some(p) = conn.get("port").and_then(|v| v.as_integer()) {
            port_cfg = p;
        }
    }
    let boot = table.get("bootstrap").and_then(|v| v.as_table()).unwrap();
    let bootstrap_level = boot.get("level").and_then(|v| v.as_integer()).unwrap();
    let bootstrap_password = boot.get("password").and_then(|v| v.as_str()).unwrap().to_string();

    let mut steps = Vec::new();
    for step_value in table.get("steps").and_then(|v| v.as_array()).unwrap() {
        let table = step_value.as_table().unwrap().clone();
        let type_ = table.get("type").and_then(|v| v.as_str()).unwrap().to_string();
        steps.push(Step { type_, table });
    }

    Ok(Config {
        host: host_cfg,
        port: port_cfg,
        bootstrap_level,
        bootstrap_password,
        steps,
    })
}

fn apply_connection(cfg: &Config) -> (String, String) {
    let mut host = env_or("BANDIT_HOST", &cfg.host);
    if host.is_empty() {
        host = DEFAULT_HOST.to_string();
    }
    let env_port = env::var("BANDIT_PORT").unwrap_or_default();
    let port = if !env_port.is_empty() {
        env_port
    } else if cfg.port != 0 {
        cfg.port.to_string()
    } else {
        DEFAULT_PORT.to_string()
    };
    (host, port)
}

fn run() -> Result<(), String> {
    let repo_root = find_repo_root()?;
    let default_config = repo_root.join("levels").join("bandit-levels.toml");
    let mut config_path = PathBuf::from(env_or(
        "BANDIT_LEVELS_FILE",
        default_config.to_string_lossy().as_ref(),
    ));
    let pass_file = repo_root.join("bandit-passwords.txt");
    let key_dir = repo_root.join(".bandit-keys");

    let mut refresh = false;
    let mut show = false;
    let mut ssh_level: i64 = -1;

    let args: Vec<String> = env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                i += 1;
                if i >= args.len() {
                    return Err("--config requires a path".to_string());
                }
                config_path = PathBuf::from(&args[i]);
            }
            "--refresh" => refresh = true,
            "--show" => show = true,
            "--ssh" => {
                i += 1;
                if i >= args.len() {
                    return Err("--ssh requires a level".to_string());
                }
                ssh_level = args[i].parse().map_err(|e: std::num::ParseIntError| e.to_string())?;
            }
            other => return Err(format!("unknown flag: {other}")),
        }
        i += 1;
    }

    let cfg = load_config(&config_path)?;
    let (host, port) = apply_connection(&cfg);

    let app = App {
        host,
        port,
        repo_root,
        config_path,
        pass_file,
        key_dir,
    };

    if refresh {
        app.refresh(&cfg)
    } else if show {
        app.show_passwords()
    } else if ssh_level >= 0 {
        app.ssh_level(ssh_level)
    } else {
        app.menu(&cfg)
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn locate_repo_root() -> PathBuf {
        let mut cwd = env::current_dir().unwrap();
        loop {
            if cwd.join("levels").join("bandit-levels.toml").exists() {
                return cwd;
            }
            if !cwd.pop() {
                panic!("repo root not found");
            }
        }
    }

    #[test]
    fn load_shared_config_parity() {
        let root = locate_repo_root();
        let text = fs::read_to_string(root.join("levels").join("bandit-levels.toml")).unwrap();
        let value: Value = toml::from_str(&text).unwrap();
        validate_config(&value).unwrap();

        let table = value.as_table().unwrap();
        let conn = table["connection"].as_table().unwrap();
        assert_eq!(conn["host"].as_str().unwrap(), "bandit.labs.overthewire.org");
        assert_eq!(conn["port"].as_integer().unwrap(), 2220);

        let boot = table["bootstrap"].as_table().unwrap();
        assert_eq!(boot["level"].as_integer().unwrap(), 0);
        assert_eq!(boot["password"].as_str().unwrap(), "bandit0");

        let steps = table["steps"].as_array().unwrap();
        assert_eq!(steps.len(), 32);

        let bandit26 = steps[25].as_table().unwrap();
        assert_eq!(bandit26["type"].as_str().unwrap(), "bandit26_escape");
        let targets = bandit26["to"].as_array().unwrap();
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].as_integer().unwrap(), 26);
        assert_eq!(targets[1].as_integer().unwrap(), 27);
    }

    #[test]
    fn extract_password_returns_last_match() {
        let text =
            "noise abcdefghijklmnopqrstuvwxyz012345 then ABCDEFGHIJKLMNOPQRSTUVWXYZ012345 tail";
        assert_eq!(extract_password(text).unwrap(), "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345");
        assert_eq!(extract_passwords(text).len(), 2);
    }

    #[test]
    fn strip_terminal_codes_removes_ansi_and_cr() {
        let dirty = "hello\x1b[31mred\x1b[0m\rworld";
        assert_eq!(strip_terminal_codes(dirty), "helloredworld");
    }

    #[test]
    fn render_template_replaces_all_placeholders() {
        let mut vals = HashMap::new();
        vals.insert("level", "7".to_string());
        vals.insert("password", "abc".to_string());
        let out = render_template("level={level} pass={password} {password}", &vals);
        assert_eq!(out, "level=7 pass=abc abc");
    }

    #[test]
    fn env_or_fallback() {
        assert_eq!(env_or("BANDIT_DEFINITELY_UNSET_VARIABLE", "fallback"), "fallback");
    }
}
