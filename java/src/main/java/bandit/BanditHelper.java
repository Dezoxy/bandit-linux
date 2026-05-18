package bandit;

import org.tomlj.Toml;
import org.tomlj.TomlArray;
import org.tomlj.TomlParseResult;
import org.tomlj.TomlTable;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

public final class BanditHelper {

    static final String DEFAULT_HOST = "bandit.labs.overthewire.org";
    static final String DEFAULT_PORT = "2220";

    static final Pattern PASSWORD_PATTERN = Pattern.compile("[A-Za-z0-9]{32}");
    static final Pattern PRIVATE_KEY_PATTERN = Pattern.compile(
            "-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            Pattern.DOTALL);
    static final Pattern[] ANSI_PATTERNS = new Pattern[] {
            Pattern.compile("\\[[0-?]*[ -/]*[@-~]"),
            Pattern.compile("P.*?\\\\", Pattern.DOTALL),
            Pattern.compile("\\].*?(?:|\\\\)", Pattern.DOTALL),
            Pattern.compile(".")
    };

    static final Map<String, List<String>> REQUIRED_FIELDS = Map.of(
            "ssh_command", List.of("from", "to", "command"),
            "path_then_command", List.of("from", "to", "find_command", "command"),
            "private_key_then_ssh", List.of("from", "to", "key_command", "key_name", "next_user", "next_command"),
            "bandit26_escape", List.of("from", "to", "key_command", "key_name"),
            "git_read_file", List.of("from", "to", "git_user", "repo", "file"),
            "git_show", List.of("from", "to", "git_user", "repo", "object"),
            "git_push_file", List.of("from", "to", "git_user", "repo", "file", "content", "commit_message"),
            "uppercase_shell", List.of("from", "to"));

    static final class Step {
        final String type;
        final Map<String, Object> fields;

        Step(String type, Map<String, Object> fields) {
            this.type = type;
            this.fields = fields;
        }

        String mustString(String key) {
            Object value = fields.get(key);
            if (value instanceof String s) {
                return s;
            }
            throw new IllegalStateException("missing string field " + key);
        }

        String fieldString(String key, String fallback) {
            Object value = fields.get(key);
            return value instanceof String s ? s : fallback;
        }

        int mustInt(String key) {
            Object value = fields.get(key);
            if (value instanceof Number n) {
                return n.intValue();
            }
            throw new IllegalStateException("missing int field " + key);
        }

        List<Integer> mustToList() {
            Object value = fields.get("to");
            if (value == null) {
                throw new IllegalStateException("missing to field");
            }
            if (value instanceof Number n) {
                return List.of(n.intValue());
            }
            if (value instanceof List<?> list) {
                List<Integer> targets = new ArrayList<>(list.size());
                for (Object item : list) {
                    if (item instanceof Number n) {
                        targets.add(n.intValue());
                    } else {
                        throw new IllegalStateException("to array contains non-int");
                    }
                }
                return targets;
            }
            throw new IllegalStateException("to field has unsupported type");
        }

        int mustToSingle() {
            List<Integer> targets = mustToList();
            if (targets.size() != 1) {
                throw new IllegalStateException("expected single target");
            }
            return targets.get(0);
        }
    }

    static final class Config {
        final String host;
        final int port;
        final int bootstrapLevel;
        final String bootstrapPassword;
        final List<Step> steps;

        Config(String host, int port, int bootstrapLevel, String bootstrapPassword, List<Step> steps) {
            this.host = host;
            this.port = port;
            this.bootstrapLevel = bootstrapLevel;
            this.bootstrapPassword = bootstrapPassword;
            this.steps = steps;
        }
    }

    String host;
    String port;
    Path repoRoot;
    Path configPath;
    Path passFile;
    Path keyDir;
    final Random random = new Random();

    public static void main(String[] args) {
        try {
            new BanditHelper().runMain(args);
        } catch (Exception exc) {
            System.err.println("error: " + exc.getMessage());
            System.exit(1);
        }
    }

    void runMain(String[] args) throws Exception {
        repoRoot = findRepoRoot();
        Path defaultConfig = repoRoot.resolve("levels").resolve("bandit-levels.toml");
        String configPathStr = getenv("BANDIT_LEVELS_FILE", defaultConfig.toString());
        boolean refresh = false;
        boolean show = false;
        int sshLevel = -1;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--config" -> {
                    if (++i >= args.length) {
                        throw new IllegalArgumentException("--config requires a path");
                    }
                    configPathStr = args[i];
                }
                case "--refresh" -> refresh = true;
                case "--show" -> show = true;
                case "--ssh" -> {
                    if (++i >= args.length) {
                        throw new IllegalArgumentException("--ssh requires a level");
                    }
                    sshLevel = Integer.parseInt(args[i]);
                }
                default -> throw new IllegalArgumentException("unknown flag: " + args[i]);
            }
        }

        configPath = Paths.get(configPathStr);
        passFile = repoRoot.resolve("bandit-passwords.txt");
        keyDir = repoRoot.resolve(".bandit-keys");

        Config cfg = loadConfig();
        applyConnection(cfg);

        if (refresh) {
            refresh(cfg);
        } else if (show) {
            showPasswords();
        } else if (sshLevel >= 0) {
            sshLevel(sshLevel);
        } else {
            menu(cfg);
        }
    }

    static String getenv(String name, String fallback) {
        String value = System.getenv(name);
        return (value != null && !value.isEmpty()) ? value : fallback;
    }

    Path findRepoRoot() {
        Path cwd = Paths.get("").toAbsolutePath();
        while (true) {
            if (Files.exists(cwd.resolve("levels").resolve("bandit-levels.toml"))) {
                return cwd;
            }
            Path parent = cwd.getParent();
            if (parent == null || parent.equals(cwd)) {
                throw new RuntimeException("could not find repo root containing levels/bandit-levels.toml");
            }
            cwd = parent;
        }
    }

    Config loadConfig() throws IOException {
        TomlParseResult result = Toml.parse(configPath);
        if (result.hasErrors()) {
            StringBuilder sb = new StringBuilder("parse config:");
            result.errors().forEach(err -> sb.append("\n").append(err));
            throw new RuntimeException(sb.toString());
        }

        String hostCfg = result.getString("connection.host");
        if (hostCfg == null) {
            hostCfg = "";
        }
        long portCfg = result.contains("connection.port") ? result.getLong("connection.port") : 0L;
        Long bootLevel = result.contains("bootstrap.level") ? result.getLong("bootstrap.level") : null;
        String bootPass = result.getString("bootstrap.password");

        if (bootPass == null || bootPass.isEmpty()) {
            throw new RuntimeException("config bootstrap password is empty");
        }
        if (bootLevel == null) {
            throw new RuntimeException("config bootstrap level is missing");
        }

        TomlArray stepsArr = result.getArray("steps");
        if (stepsArr == null || stepsArr.isEmpty()) {
            throw new RuntimeException("config has no steps");
        }

        List<Step> steps = new ArrayList<>(stepsArr.size());
        for (int i = 0; i < stepsArr.size(); i++) {
            TomlTable table = stepsArr.getTable(i);
            String type = table.getString("type");
            if (type == null) {
                throw new RuntimeException("step " + (i + 1) + " is missing type");
            }
            List<String> required = REQUIRED_FIELDS.get(type);
            if (required == null) {
                throw new RuntimeException("step " + (i + 1) + " has unsupported type \"" + type + "\"");
            }
            for (String field : required) {
                if (!table.contains(field)) {
                    throw new RuntimeException("step " + (i + 1) + " (" + type + ") is missing " + field);
                }
            }
            Map<String, Object> fields = new LinkedHashMap<>();
            for (String key : table.keySet()) {
                Object raw = table.get(key);
                if (raw instanceof TomlArray array) {
                    List<Object> list = new ArrayList<>(array.size());
                    for (int j = 0; j < array.size(); j++) {
                        list.add(array.get(j));
                    }
                    fields.put(key, list);
                } else {
                    fields.put(key, raw);
                }
            }
            steps.add(new Step(type, fields));
        }

        return new Config(hostCfg, (int) portCfg, bootLevel.intValue(), bootPass, steps);
    }

    void applyConnection(Config cfg) {
        host = getenv("BANDIT_HOST", cfg.host);
        if (host.isEmpty()) {
            host = DEFAULT_HOST;
        }
        String envPort = System.getenv("BANDIT_PORT");
        if (envPort != null && !envPort.isEmpty()) {
            port = envPort;
        } else if (cfg.port != 0) {
            port = String.valueOf(cfg.port);
        } else {
            port = DEFAULT_PORT;
        }
    }

    void ensureState() throws IOException {
        Files.createDirectories(keyDir);
        if (!Files.exists(passFile)) {
            Files.createFile(passFile);
        }
        setPosix(keyDir, "rwx------");
        setPosix(passFile, "rw-------");
    }

    static void setPosix(Path path, String perms) throws IOException {
        try {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(perms));
        } catch (UnsupportedOperationException ignored) {
            // non-POSIX filesystem, skip
        }
    }

    static void checkDependencies() {
        for (String command : List.of("expect", "ssh", "git", "awk", "grep", "mktemp")) {
            if (which(command) == null) {
                throw new RuntimeException("missing required command: " + command);
            }
        }
    }

    static Path which(String command) {
        String path = System.getenv("PATH");
        if (path == null) {
            return null;
        }
        for (String dir : path.split(java.io.File.pathSeparator)) {
            if (dir.isEmpty()) {
                continue;
            }
            Path candidate = Paths.get(dir, command);
            if (Files.isExecutable(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    static final class ProcessResult {
        final int exitCode;
        final String output;

        ProcessResult(int exitCode, String output) {
            this.exitCode = exitCode;
            this.output = output;
        }
    }

    ProcessResult commandOutput(String name, List<String> args, Map<String, String> env, String input, Path dir)
            throws IOException, InterruptedException {
        List<String> command = new ArrayList<>();
        command.add(name);
        if (args != null) {
            command.addAll(args);
        }
        ProcessBuilder pb = new ProcessBuilder(command);
        if (dir != null) {
            pb.directory(dir.toFile());
        }
        if (env != null) {
            pb.environment().putAll(env);
        }
        pb.redirectErrorStream(true);

        Process process = pb.start();
        if (input != null && !input.isEmpty()) {
            try (OutputStream stdin = process.getOutputStream()) {
                stdin.write(input.getBytes(StandardCharsets.UTF_8));
            }
        } else {
            process.getOutputStream().close();
        }

        StringBuilder buffer = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            char[] chunk = new char[4096];
            int read;
            while ((read = reader.read(chunk)) >= 0) {
                buffer.append(chunk, 0, read);
            }
        }
        int code = process.waitFor();
        return new ProcessResult(code, buffer.toString());
    }

    String runExpect(String script, Map<String, String> env) throws IOException, InterruptedException {
        ProcessResult result = commandOutput("expect", List.of(), env, script, null);
        if (result.exitCode != 0) {
            throw new RuntimeException(result.output);
        }
        return result.output;
    }

    static String stripTerminalCodes(String text) {
        String cleaned = text;
        for (Pattern pattern : ANSI_PATTERNS) {
            cleaned = pattern.matcher(cleaned).replaceAll("");
        }
        return cleaned.replace("\r", "");
    }

    static List<String> extractPasswords(String text) {
        List<String> matches = new ArrayList<>();
        Matcher matcher = PASSWORD_PATTERN.matcher(stripTerminalCodes(text));
        while (matcher.find()) {
            matches.add(matcher.group());
        }
        return matches;
    }

    static String extractPassword(String text) {
        List<String> passwords = extractPasswords(text);
        if (passwords.isEmpty()) {
            throw new RuntimeException("failed to extract a 32-character password from output:\n" + text);
        }
        return passwords.get(passwords.size() - 1);
    }

    void savePassword(String user, String password) throws IOException {
        ensureState();
        List<String> lines = new ArrayList<>();
        if (Files.exists(passFile)) {
            String existing = Files.readString(passFile, StandardCharsets.UTF_8);
            for (String line : existing.split("\n", -1)) {
                if (line.isEmpty() || line.startsWith(user + ":")) {
                    continue;
                }
                lines.add(line);
            }
        }
        lines.add(user + ": " + password);
        Files.writeString(passFile, String.join("\n", lines) + "\n", StandardCharsets.UTF_8);
        setPosix(passFile, "rw-------");
    }

    String getSavedPassword(String user) throws IOException {
        if (!Files.exists(passFile)) {
            return "";
        }
        String password = "";
        String prefix = user + ": ";
        for (String line : Files.readString(passFile, StandardCharsets.UTF_8).split("\n", -1)) {
            if (line.startsWith(prefix)) {
                password = line.substring(prefix.length());
            }
        }
        return password;
    }

    void recordPassword(int level, String password) throws IOException {
        String user = "bandit" + level;
        if (level != 0 && !PASSWORD_PATTERN.matcher(password).matches()) {
            throw new RuntimeException("refusing to save invalid password for " + user + ": " + password);
        }
        savePassword(user, password);
        System.out.printf("[+] %-8s %s%n", user, password);
    }

    String runPasswordSSHCommand(String user, String password, String commandText)
            throws IOException, InterruptedException {
        String script = """
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
                """;
        Map<String, String> env = new HashMap<>();
        env.put("BANDIT_HOST_VALUE", host);
        env.put("BANDIT_PORT_VALUE", port);
        env.put("BANDIT_USER_VALUE", user);
        env.put("BANDIT_PASSWORD_VALUE", password);
        env.put("BANDIT_COMMAND_VALUE", commandText);
        try {
            return runExpect(script, env);
        } catch (RuntimeException exc) {
            throw new RuntimeException("SSH command failed for " + user + ": " + commandText + "\n" + exc.getMessage(), exc);
        }
    }

    String runKeySSHCommand(String user, Path keyFile, String commandText)
            throws IOException, InterruptedException {
        List<String> args = List.of(
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "LogLevel=ERROR",
                "-o", "IdentitiesOnly=yes",
                "-o", "BatchMode=yes",
                "-i", keyFile.toString(),
                "-p", port,
                user + "@" + host,
                commandText);
        ProcessResult result = commandOutput("ssh", args, null, null, null);
        if (result.exitCode != 0) {
            throw new RuntimeException(result.output);
        }
        return result.output;
    }

    String solvePassword(String user, String password, String commandText)
            throws IOException, InterruptedException {
        return extractPassword(runPasswordSSHCommand(user, password, commandText));
    }

    String solvePath(String user, String password, String commandText)
            throws IOException, InterruptedException {
        String output = stripTerminalCodes(runPasswordSSHCommand(user, password, commandText));
        String[] lines = output.split("\n", -1);
        for (int i = lines.length - 1; i >= 0; i--) {
            if (lines[i].contains("/inhere/")) {
                return lines[i];
            }
        }
        throw new RuntimeException("failed to extract path from output:\n" + output);
    }

    Path savePrivateKey(String name, String output) throws IOException {
        Matcher matcher = PRIVATE_KEY_PATTERN.matcher(stripTerminalCodes(output));
        if (!matcher.find()) {
            throw new RuntimeException("failed to extract private key " + name + " from output:\n" + output);
        }
        ensureState();
        Path keyFile = keyDir.resolve(name);
        Files.writeString(keyFile, matcher.group() + "\n", StandardCharsets.UTF_8);
        setPosix(keyFile, "rw-------");
        return keyFile;
    }

    String[] solveBandit26Pair(Path keyFile) throws IOException, InterruptedException {
        String script = """
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
                """;
        Map<String, String> env = new HashMap<>();
        env.put("BANDIT_HOST_VALUE", host);
        env.put("BANDIT_PORT_VALUE", port);
        env.put("BANDIT_KEY_VALUE", keyFile.toString());
        String output = runExpect(script, env);
        List<String> passwords = extractPasswords(output);
        if (passwords.size() < 2) {
            throw new RuntimeException("expected two passwords from bandit26 output:\n" + output);
        }
        return new String[] { passwords.get(passwords.size() - 2), passwords.get(passwords.size() - 1) };
    }

    String solveUppercaseShell(String password) throws IOException, InterruptedException {
        String script = """
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
                """;
        Map<String, String> env = new HashMap<>();
        env.put("BANDIT_HOST_VALUE", host);
        env.put("BANDIT_PORT_VALUE", port);
        env.put("BANDIT_PASSWORD_VALUE", password);
        return extractPassword(runExpect(script, env));
    }

    Map<String, String> gitEnv(String password, Path askpass) {
        String sshCommand = "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "
                + "-o PubkeyAuthentication=no -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1";
        String display = getenv("DISPLAY", ":0");
        Map<String, String> env = new HashMap<>();
        env.put("BANDIT_GIT_PASSWORD", password);
        env.put("GIT_SSH_COMMAND", sshCommand);
        env.put("SSH_ASKPASS", askpass.toString());
        env.put("SSH_ASKPASS_REQUIRE", "force");
        env.put("DISPLAY", display);
        return env;
    }

    Path writeAskpass(Path dir) throws IOException {
        Path askpass = dir.resolve("askpass.sh");
        Files.writeString(askpass,
                "#!/usr/bin/env bash\nprintf '%s\\n' \"$BANDIT_GIT_PASSWORD\"\n",
                StandardCharsets.UTF_8);
        setPosix(askpass, "rwx------");
        return askpass;
    }

    void gitCloneRepo(String user, String password, String remotePath, Path destination)
            throws IOException, InterruptedException {
        Path tmp = Files.createTempDirectory("bandit-git-askpass.");
        try {
            Path askpass = writeAskpass(tmp);
            String remote = "ssh://" + user + "@" + host + ":" + port + remotePath;
            ProcessResult result = commandOutput("git",
                    List.of("clone", remote, destination.toString()),
                    gitEnv(password, askpass), null, null);
            if (result.exitCode != 0) {
                throw new RuntimeException(result.output);
            }
        } finally {
            deleteRecursive(tmp);
        }
    }

    String gitPushWithPassword(String password, Path repo) throws IOException, InterruptedException {
        Path tmp = Files.createTempDirectory("bandit-git-askpass.");
        try {
            Path askpass = writeAskpass(tmp);
            ProcessResult result = commandOutput("git",
                    List.of("-C", repo.toString(), "push", "origin", "master"),
                    gitEnv(password, askpass), null, null);
            return result.output;
        } finally {
            deleteRecursive(tmp);
        }
    }

    static void deleteRecursive(Path root) throws IOException {
        if (!Files.exists(root)) {
            return;
        }
        try (Stream<Path> stream = Files.walk(root)) {
            stream.sorted(Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException ignored) {
                    // best-effort cleanup
                }
            });
        }
    }

    String renderTemplate(String template, Map<String, String> values) {
        String rendered = template;
        for (Map.Entry<String, String> entry : values.entrySet()) {
            rendered = rendered.replace("{" + entry.getKey() + "}", entry.getValue());
        }
        return rendered;
    }

    Map<String, String> stepContext(int level, String password, int toLevel) {
        Map<String, String> ctx = new HashMap<>();
        ctx.put("password", password);
        ctx.put("level", String.valueOf(level));
        ctx.put("to", String.valueOf(toLevel));
        ctx.put("random_port", String.valueOf(20000 + random.nextInt(10000)));
        long pid = ProcessHandle.current().pid();
        ctx.put("temp_output", "/tmp/bandit" + toLevel + "pass." + pid + "." + (1000 + random.nextInt(9000)));
        return ctx;
    }

    void refresh(Config cfg) throws Exception {
        checkDependencies();
        ensureState();

        System.out.printf("Refreshing Bandit passwords via %s:%s%n", host, port);
        System.out.printf("Level config:  %s%n", configPath);
        System.out.printf("Password file: %s%n", passFile);
        System.out.printf("Key cache:     %s%n%n", keyDir);

        Map<Integer, String> passwords = new HashMap<>();
        passwords.put(cfg.bootstrapLevel, cfg.bootstrapPassword);
        recordPassword(cfg.bootstrapLevel, cfg.bootstrapPassword);

        for (Step step : cfg.steps) {
            solveStep(step, passwords);
        }

        System.out.println();
        System.out.println("Refresh complete.");
    }

    void solveStep(Step step, Map<Integer, String> passwords) throws Exception {
        int fromLevel = step.mustInt("from");
        String fromUser = step.fieldString("user", "bandit" + fromLevel);
        String fromPassword = passwords.get(fromLevel);
        if (fromPassword == null) {
            throw new RuntimeException("missing password for bandit" + fromLevel);
        }

        switch (step.type) {
            case "ssh_command" -> {
                int toLevel = step.mustToSingle();
                Map<String, String> ctx = stepContext(fromLevel, fromPassword, toLevel);
                String command = renderTemplate(step.mustString("command"), ctx);
                String password = solvePassword(fromUser, fromPassword, command);
                passwords.put(toLevel, password);
                recordPassword(toLevel, password);
            }
            case "path_then_command" -> {
                int toLevel = step.mustToSingle();
                Map<String, String> ctx = stepContext(fromLevel, fromPassword, toLevel);
                String findCommand = renderTemplate(step.mustString("find_command"), ctx);
                String path = solvePath(fromUser, fromPassword, findCommand);
                ctx.put("path", path);
                String command = renderTemplate(step.mustString("command"), ctx);
                String password = solvePassword(fromUser, fromPassword, command);
                passwords.put(toLevel, password);
                recordPassword(toLevel, password);
            }
            case "private_key_then_ssh" -> {
                int toLevel = step.mustToSingle();
                Map<String, String> ctx = stepContext(fromLevel, fromPassword, toLevel);
                String keyCommand = renderTemplate(step.mustString("key_command"), ctx);
                String output = runPasswordSSHCommand(fromUser, fromPassword, keyCommand);
                Path keyFile = savePrivateKey(step.mustString("key_name"), output);
                String nextCommand = renderTemplate(step.mustString("next_command"), ctx);
                String keyOutput = runKeySSHCommand(step.mustString("next_user"), keyFile, nextCommand);
                String password = extractPassword(keyOutput);
                passwords.put(toLevel, password);
                recordPassword(toLevel, password);
            }
            case "bandit26_escape" -> {
                List<Integer> targets = step.mustToList();
                Map<String, String> ctx = stepContext(fromLevel, fromPassword, targets.get(targets.size() - 1));
                String keyCommand = renderTemplate(step.mustString("key_command"), ctx);
                String output = runPasswordSSHCommand(fromUser, fromPassword, keyCommand);
                Path keyFile = savePrivateKey(step.mustString("key_name"), output);
                String[] solved = solveBandit26Pair(keyFile);
                if (targets.size() != solved.length) {
                    throw new RuntimeException("bandit26_escape expected " + targets.size()
                            + " targets, got " + solved.length + " passwords");
                }
                for (int i = 0; i < targets.size(); i++) {
                    passwords.put(targets.get(i), solved[i]);
                    recordPassword(targets.get(i), solved[i]);
                }
            }
            case "git_read_file" -> {
                int toLevel = step.mustToSingle();
                Path tmp = Files.createTempDirectory("bandit-repo.");
                try {
                    Path repo = tmp.resolve("repo");
                    gitCloneRepo(step.mustString("git_user"), fromPassword, step.mustString("repo"), repo);
                    String content = Files.readString(repo.resolve(step.mustString("file")), StandardCharsets.UTF_8);
                    String password = extractPassword(content);
                    passwords.put(toLevel, password);
                    recordPassword(toLevel, password);
                } finally {
                    deleteRecursive(tmp);
                }
            }
            case "git_show" -> {
                int toLevel = step.mustToSingle();
                Path tmp = Files.createTempDirectory("bandit-repo.");
                try {
                    Path repo = tmp.resolve("repo");
                    gitCloneRepo(step.mustString("git_user"), fromPassword, step.mustString("repo"), repo);
                    ProcessResult result = commandOutput("git",
                            List.of("-C", repo.toString(), "show", step.mustString("object")),
                            null, null, null);
                    if (result.exitCode != 0) {
                        throw new RuntimeException(result.output);
                    }
                    String password = extractPassword(result.output);
                    passwords.put(toLevel, password);
                    recordPassword(toLevel, password);
                } finally {
                    deleteRecursive(tmp);
                }
            }
            case "git_push_file" -> {
                int toLevel = step.mustToSingle();
                Path tmp = Files.createTempDirectory("bandit-repo.");
                try {
                    Path repo = tmp.resolve("repo");
                    gitCloneRepo(step.mustString("git_user"), fromPassword, step.mustString("repo"), repo);
                    runOrThrow("git", List.of("-C", repo.toString(), "config", "user.email",
                            "bandit-solver@example.invalid"));
                    runOrThrow("git", List.of("-C", repo.toString(), "config", "user.name", "bandit-solver"));
                    Files.writeString(repo.resolve(step.mustString("file")),
                            step.mustString("content"), StandardCharsets.UTF_8);
                    runOrThrow("git", List.of("-C", repo.toString(), "add", "-f", step.mustString("file")));
                    runOrThrow("git", List.of("-C", repo.toString(), "commit", "-m", step.mustString("commit_message")));
                    String pushOutput = gitPushWithPassword(fromPassword, repo);
                    String password = extractPassword(pushOutput);
                    passwords.put(toLevel, password);
                    recordPassword(toLevel, password);
                } finally {
                    deleteRecursive(tmp);
                }
            }
            case "uppercase_shell" -> {
                int toLevel = step.mustToSingle();
                String password = solveUppercaseShell(fromPassword);
                passwords.put(toLevel, password);
                recordPassword(toLevel, password);
            }
            default -> throw new RuntimeException("unsupported step type: " + step.type);
        }
    }

    void runOrThrow(String name, List<String> args) throws IOException, InterruptedException {
        ProcessResult result = commandOutput(name, args, null, null, null);
        if (result.exitCode != 0) {
            throw new RuntimeException(result.output);
        }
    }

    void showPasswords() throws IOException {
        ensureState();
        byte[] data = Files.readAllBytes(passFile);
        if (data.length == 0) {
            System.out.println("No passwords saved yet.");
        } else {
            System.out.print(new String(data, StandardCharsets.UTF_8));
        }
    }

    void sshLevel(int level) throws IOException, InterruptedException {
        ensureState();
        String user = "bandit" + level;
        String password = getSavedPassword(user);
        if (password.isEmpty()) {
            ProcessBuilder pb = new ProcessBuilder("ssh", user + "@" + host, "-p", port).inheritIO();
            pb.start().waitFor();
            return;
        }

        String script = """
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
                """;

        Path scriptFile = Files.createTempFile("bandit-ssh.", ".exp");
        try {
            Files.writeString(scriptFile, script, StandardCharsets.UTF_8);
            ProcessBuilder pb = new ProcessBuilder("expect", "-f", scriptFile.toString()).inheritIO();
            pb.environment().put("BANDIT_HOST_VALUE", host);
            pb.environment().put("BANDIT_PORT_VALUE", port);
            pb.environment().put("BANDIT_USER_VALUE", user);
            pb.environment().put("BANDIT_PASSWORD_VALUE", password);
            pb.start().waitFor();
        } finally {
            Files.deleteIfExists(scriptFile);
        }
    }

    void savePasswordInteractive(Scanner scanner) throws IOException {
        System.out.print("Save password for which user? Example: bandit6: ");
        String username = scanner.nextLine().trim();
        System.out.print("Password: ");
        String password = scanner.nextLine().trim();
        savePassword(username, password);
        System.out.println("Saved password for " + username + ".");
    }

    void menu(Config cfg) throws Exception {
        ensureState();
        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.println("====================================");
            System.out.println("        OverTheWire Bandit App");
            System.out.println("====================================");
            System.out.println();
            System.out.println("Password file: " + passFile);
            System.out.println("Key cache:     " + keyDir);
            System.out.println();
            System.out.println("1) SSH into a Bandit level");
            System.out.println("2) Refresh all passwords");
            System.out.println("3) Save/update a password");
            System.out.println("4) Show saved passwords");
            System.out.println("5) Exit");
            System.out.println();
            System.out.print("Choose an option: ");

            String choice = scanner.nextLine().trim();
            switch (choice) {
                case "1" -> {
                    System.out.print("Bandit level number, e.g. 0, 1, 26, 33: ");
                    int level = Integer.parseInt(scanner.nextLine().trim());
                    sshLevel(level);
                }
                case "2" -> {
                    refresh(cfg);
                    System.out.print("Press Enter to continue...");
                    scanner.nextLine();
                }
                case "3" -> savePasswordInteractive(scanner);
                case "4" -> {
                    showPasswords();
                    System.out.print("Press Enter to continue...");
                    scanner.nextLine();
                }
                case "5" -> {
                    return;
                }
                default -> System.out.println("Invalid option.");
            }
        }
    }
}
