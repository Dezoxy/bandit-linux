#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
require "open3"
require "tmpdir"
require "toml-rb"

module Bandit
  DEFAULT_HOST = "bandit.labs.overthewire.org"
  DEFAULT_PORT = "2220"

  PASSWORD_RE = /[A-Za-z0-9]{32}/.freeze
  PRIVATE_KEY_RE = /-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----/m.freeze
  ANSI_RE = /
    \e\[[0-?]*[ -\/]*[@-~] |
    \eP.*?\e\\ |
    \e\].*?(?:\a|\e\\) |
    \e.
  /xm.freeze

  REQUIRED_FIELDS = {
    "ssh_command"          => %w[from to command],
    "path_then_command"    => %w[from to find_command command],
    "private_key_then_ssh" => %w[from to key_command key_name next_user next_command],
    "bandit26_escape"      => %w[from to key_command key_name],
    "git_read_file"        => %w[from to git_user repo file],
    "git_show"             => %w[from to git_user repo object],
    "git_push_file"        => %w[from to git_user repo file content commit_message],
    "uppercase_shell"      => %w[from to],
  }.freeze

  SCRIPT_PASSWORD_SSH = <<~SCRIPT
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
  SCRIPT

  SCRIPT_BANDIT26 = <<~'SCRIPT'
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
  SCRIPT

  SCRIPT_UPPERCASE = <<~'SCRIPT'
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
  SCRIPT

  SCRIPT_INTERACTIVE = <<~'SCRIPT'
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
  SCRIPT

  module_function

  def env_or(name, fallback)
    v = ENV[name]
    v && !v.empty? ? v : fallback
  end

  def find_repo_root
    cwd = Dir.pwd
    loop do
      return cwd if File.exist?(File.join(cwd, "levels", "bandit-levels.toml"))

      parent = File.dirname(cwd)
      raise "could not find repo root containing levels/bandit-levels.toml" if parent == cwd

      cwd = parent
    end
  end

  def strip_terminal_codes(text)
    text.to_s.gsub(ANSI_RE, "").tr("\r", "")
  end

  def extract_passwords(text)
    strip_terminal_codes(text).scan(PASSWORD_RE)
  end

  def extract_password(text)
    matches = extract_passwords(text)
    raise "failed to extract a 32-character password from output:\n#{text}" if matches.empty?

    matches.last
  end

  def render_template(template, values)
    out = template.dup
    values.each { |k, v| out.gsub!("{#{k}}", v.to_s) }
    out
  end

  def validate_config(cfg)
    boot = cfg["bootstrap"]
    raise "config is missing [bootstrap]" unless boot.is_a?(Hash)
    raise "config bootstrap level is missing" unless boot.key?("level")

    pass = boot["password"]
    raise "config bootstrap password is empty" if pass.nil? || pass.to_s.empty?

    steps = cfg["steps"]
    raise "config has no steps" unless steps.is_a?(Array) && !steps.empty?

    steps.each_with_index do |step, idx|
      type = step["type"]
      required = REQUIRED_FIELDS[type]
      raise "step #{idx + 1} has unsupported type \"#{type}\"" unless required

      required.each do |field|
        raise "step #{idx + 1} (#{type}) is missing #{field}" unless step.key?(field)
      end
    end
  end

  class App
    attr_reader :host, :port, :repo_root, :config_path, :pass_file, :key_dir

    def initialize(args)
      @repo_root = Bandit.find_repo_root
      default_config = File.join(@repo_root, "levels", "bandit-levels.toml")
      @config_path = Bandit.env_or("BANDIT_LEVELS_FILE", default_config)
      @pass_file = File.join(@repo_root, "bandit-passwords.txt")
      @key_dir = File.join(@repo_root, ".bandit-keys")

      @refresh_flag = false
      @show_flag = false
      @ssh_level_arg = -1
      parse_args(args)
    end

    def parse_args(args)
      i = 0
      while i < args.length
        case args[i]
        when "--config"
          raise "--config requires a path" if i + 1 >= args.length

          @config_path = args[i + 1]
          i += 1
        when "--refresh" then @refresh_flag = true
        when "--show"    then @show_flag = true
        when "--ssh"
          raise "--ssh requires a level" if i + 1 >= args.length

          @ssh_level_arg = Integer(args[i + 1])
          i += 1
        else
          raise "unknown flag: #{args[i]}"
        end
        i += 1
      end
    end

    def run
      cfg = load_config
      apply_connection(cfg)
      if @refresh_flag then refresh(cfg)
      elsif @show_flag then show_passwords
      elsif @ssh_level_arg >= 0 then ssh_level(@ssh_level_arg)
      else menu(cfg)
      end
    end

    def load_config
      raise "missing level config: #{@config_path}" unless File.exist?(@config_path)

      cfg = TomlRB.load_file(@config_path)
      Bandit.validate_config(cfg)
      cfg
    end

    def apply_connection(cfg)
      conn = cfg["connection"] || {}
      @host = Bandit.env_or("BANDIT_HOST", conn["host"] || DEFAULT_HOST)
      env_port = ENV["BANDIT_PORT"]
      @port = if env_port && !env_port.empty?
                env_port
              elsif conn["port"]
                conn["port"].to_s
              else
                DEFAULT_PORT
              end
    end

    def ensure_state
      FileUtils.mkdir_p(@key_dir, mode: 0o700)
      File.chmod(0o700, @key_dir)
      FileUtils.touch(@pass_file) unless File.exist?(@pass_file)
      File.chmod(0o600, @pass_file)
    end

    def check_dependencies
      %w[expect ssh git awk grep mktemp].each do |cmd|
        raise "missing required command: #{cmd}" unless which(cmd)
      end
    end

    def which(cmd)
      ENV.fetch("PATH", "").split(File::PATH_SEPARATOR).find do |dir|
        next false if dir.empty?

        candidate = File.join(dir, cmd)
        File.executable?(candidate) && File.file?(candidate)
      end
    end

    def run_command(name, args = [], env: {}, input: nil, cwd: nil)
      opts = {}
      opts[:chdir] = cwd if cwd
      argv = [env, name, *args, opts]
      if input
        out_str, status = Open3.capture2e(*argv, stdin_data: input)
      else
        out_str, status = Open3.capture2e(*argv)
      end
      [status.exitstatus, out_str]
    rescue Errno::ENOENT => e
      raise "spawn #{name}: #{e.message}"
    end

    def run_expect(script, env)
      code, output = run_command("expect", [], env: env, input: script)
      raise output if code != 0

      output
    end

    def save_password(user, password)
      ensure_state
      existing = File.exist?(@pass_file) ? File.read(@pass_file) : ""
      lines = existing.split("\n").reject do |line|
        line.empty? || line.start_with?("#{user}:")
      end
      lines << "#{user}: #{password}"
      File.write(@pass_file, "#{lines.join("\n")}\n")
      File.chmod(0o600, @pass_file)
    end

    def get_saved_password(user)
      return "" unless File.exist?(@pass_file)

      prefix = "#{user}: "
      password = ""
      File.read(@pass_file).split("\n").each do |line|
        password = line[prefix.length..] if line.start_with?(prefix)
      end
      password
    end

    PASSWORD_FULL_RE = /\A[A-Za-z0-9]{32}\z/.freeze

    def record_password(level, password)
      user = "bandit#{level}"
      if level != 0 && !PASSWORD_FULL_RE.match?(password)
        raise "refusing to save invalid password for #{user}: #{password}"
      end

      save_password(user, password)
      printf("[+] %-8s %s\n", user, password)
    end

    def run_password_ssh_command(user, password, command_text)
      env = {
        "BANDIT_HOST_VALUE" => @host,
        "BANDIT_PORT_VALUE" => @port,
        "BANDIT_USER_VALUE" => user,
        "BANDIT_PASSWORD_VALUE" => password,
        "BANDIT_COMMAND_VALUE" => command_text,
      }
      run_expect(SCRIPT_PASSWORD_SSH, env)
    rescue RuntimeError => e
      raise "SSH command failed for #{user}: #{command_text}\n#{e.message}"
    end

    def run_key_ssh_command(user, key_file, command_text)
      args = [
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes",
        "-i", key_file.to_s,
        "-p", @port,
        "#{user}@#{@host}",
        command_text,
      ]
      code, output = run_command("ssh", args)
      raise output if code != 0

      output
    end

    def solve_password(user, password, command_text)
      Bandit.extract_password(run_password_ssh_command(user, password, command_text))
    end

    def solve_path(user, password, command_text)
      output = Bandit.strip_terminal_codes(run_password_ssh_command(user, password, command_text))
      match = output.split("\n").reverse.find { |line| line.include?("/inhere/") }
      raise "failed to extract path from output:\n#{output}" unless match

      match
    end

    def save_private_key(name, output)
      m = PRIVATE_KEY_RE.match(Bandit.strip_terminal_codes(output))
      raise "failed to extract private key #{name} from output:\n#{output}" unless m

      ensure_state
      key_file = File.join(@key_dir, name)
      File.write(key_file, "#{m[0]}\n")
      File.chmod(0o600, key_file)
      key_file
    end

    def solve_bandit26_pair(key_file)
      env = {
        "BANDIT_HOST_VALUE" => @host,
        "BANDIT_PORT_VALUE" => @port,
        "BANDIT_KEY_VALUE" => key_file.to_s,
      }
      output = run_expect(SCRIPT_BANDIT26, env)
      passwords = Bandit.extract_passwords(output)
      raise "expected two passwords from bandit26 output:\n#{output}" if passwords.length < 2

      [passwords[-2], passwords[-1]]
    end

    def solve_uppercase_shell(password)
      env = {
        "BANDIT_HOST_VALUE" => @host,
        "BANDIT_PORT_VALUE" => @port,
        "BANDIT_PASSWORD_VALUE" => password,
      }
      Bandit.extract_password(run_expect(SCRIPT_UPPERCASE, env))
    end

    def git_env(password, askpass)
      ssh_cmd = "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
                "-o LogLevel=ERROR -o PubkeyAuthentication=no " \
                "-o PreferredAuthentications=password -o NumberOfPasswordPrompts=1"
      {
        "BANDIT_GIT_PASSWORD" => password,
        "GIT_SSH_COMMAND" => ssh_cmd,
        "SSH_ASKPASS" => askpass.to_s,
        "SSH_ASKPASS_REQUIRE" => "force",
        "DISPLAY" => Bandit.env_or("DISPLAY", ":0"),
      }
    end

    def write_askpass(dir)
      askpass = File.join(dir, "askpass.sh")
      File.write(askpass, "#!/usr/bin/env bash\nprintf '%s\\n' \"$BANDIT_GIT_PASSWORD\"\n")
      File.chmod(0o700, askpass)
      askpass
    end

    def git_clone_repo(user, password, remote_path, destination)
      Dir.mktmpdir("bandit-git-askpass.") do |tmp|
        askpass = write_askpass(tmp)
        remote = "ssh://#{user}@#{@host}:#{@port}#{remote_path}"
        code, output = run_command("git", ["clone", remote, destination.to_s], env: git_env(password, askpass))
        raise output if code != 0
      end
    end

    def git_push_with_password(password, repo)
      Dir.mktmpdir("bandit-git-askpass.") do |tmp|
        askpass = write_askpass(tmp)
        _code, output = run_command(
          "git",
          ["-C", repo.to_s, "push", "origin", "master"],
          env: git_env(password, askpass),
        )
        return output
      end
    end

    def step_context(level, password, to_level)
      {
        "password" => password,
        "level" => level,
        "to" => to_level,
        "random_port" => 20_000 + rand(10_000),
        "temp_output" => "/tmp/bandit#{to_level}pass.#{Process.pid}.#{1_000 + rand(9_000)}",
      }
    end

    def refresh(cfg)
      check_dependencies
      ensure_state

      puts "Refreshing Bandit passwords via #{@host}:#{@port}"
      puts "Level config:  #{@config_path}"
      puts "Password file: #{@pass_file}"
      puts "Key cache:     #{@key_dir}"
      puts

      boot_level = cfg["bootstrap"]["level"]
      boot_pass = cfg["bootstrap"]["password"]
      passwords = { boot_level => boot_pass }
      record_password(boot_level, boot_pass)

      cfg["steps"].each { |step| solve_step(step, passwords) }

      puts
      puts "Refresh complete."
    end

    def solve_step(step, passwords)
      type = step["type"]
      from_level = step["from"].to_i
      from_user = step["user"] || "bandit#{from_level}"
      from_password = passwords[from_level] or raise "missing password for bandit#{from_level}"

      case type
      when "ssh_command"
        to_level = step_to_single(step)
        ctx = step_context(from_level, from_password, to_level)
        cmd = Bandit.render_template(step["command"], ctx)
        pw = solve_password(from_user, from_password, cmd)
        passwords[to_level] = pw
        record_password(to_level, pw)
      when "path_then_command"
        to_level = step_to_single(step)
        ctx = step_context(from_level, from_password, to_level)
        find_cmd = Bandit.render_template(step["find_command"], ctx)
        path = solve_path(from_user, from_password, find_cmd)
        ctx["path"] = path
        cmd = Bandit.render_template(step["command"], ctx)
        pw = solve_password(from_user, from_password, cmd)
        passwords[to_level] = pw
        record_password(to_level, pw)
      when "private_key_then_ssh"
        to_level = step_to_single(step)
        ctx = step_context(from_level, from_password, to_level)
        key_cmd = Bandit.render_template(step["key_command"], ctx)
        output = run_password_ssh_command(from_user, from_password, key_cmd)
        key_file = save_private_key(step["key_name"], output)
        next_cmd = Bandit.render_template(step["next_command"], ctx)
        key_output = run_key_ssh_command(step["next_user"], key_file, next_cmd)
        pw = Bandit.extract_password(key_output)
        passwords[to_level] = pw
        record_password(to_level, pw)
      when "bandit26_escape"
        targets = step_to_list(step)
        ctx = step_context(from_level, from_password, targets.last)
        key_cmd = Bandit.render_template(step["key_command"], ctx)
        output = run_password_ssh_command(from_user, from_password, key_cmd)
        key_file = save_private_key(step["key_name"], output)
        solved = solve_bandit26_pair(key_file)
        raise "bandit26_escape expected #{targets.length} targets, got #{solved.length}" if targets.length != solved.length

        targets.zip(solved).each do |target, pw|
          passwords[target] = pw
          record_password(target, pw)
        end
      when "git_read_file"
        to_level = step_to_single(step)
        Dir.mktmpdir("bandit-repo.") do |tmp|
          repo = File.join(tmp, "repo")
          git_clone_repo(step["git_user"], from_password, step["repo"], repo)
          content = File.read(File.join(repo, step["file"]))
          pw = Bandit.extract_password(content)
          passwords[to_level] = pw
          record_password(to_level, pw)
        end
      when "git_show"
        to_level = step_to_single(step)
        Dir.mktmpdir("bandit-repo.") do |tmp|
          repo = File.join(tmp, "repo")
          git_clone_repo(step["git_user"], from_password, step["repo"], repo)
          code, output = run_command("git", ["-C", repo, "show", step["object"]])
          raise output if code != 0

          pw = Bandit.extract_password(output)
          passwords[to_level] = pw
          record_password(to_level, pw)
        end
      when "git_push_file"
        to_level = step_to_single(step)
        Dir.mktmpdir("bandit-repo.") do |tmp|
          repo = File.join(tmp, "repo")
          git_clone_repo(step["git_user"], from_password, step["repo"], repo)
          git_run = lambda do |args|
            code, output = run_command("git", ["-C", repo, *args])
            raise output if code != 0
          end
          git_run.call(["config", "user.email", "bandit-solver@example.invalid"])
          git_run.call(["config", "user.name", "bandit-solver"])
          File.write(File.join(repo, step["file"]), step["content"])
          git_run.call(["add", "-f", step["file"]])
          git_run.call(["commit", "-m", step["commit_message"]])
          push_out = git_push_with_password(from_password, repo)
          pw = Bandit.extract_password(push_out)
          passwords[to_level] = pw
          record_password(to_level, pw)
        end
      when "uppercase_shell"
        to_level = step_to_single(step)
        pw = solve_uppercase_shell(from_password)
        passwords[to_level] = pw
        record_password(to_level, pw)
      else
        raise "unsupported step type: #{type}"
      end
    end

    def step_to_list(step)
      v = step["to"]
      case v
      when Integer then [v]
      when Array then v.map(&:to_i)
      else raise "to field has unsupported type"
      end
    end

    def step_to_single(step)
      list = step_to_list(step)
      raise "expected single 'to' target" unless list.length == 1

      list.first
    end

    def show_passwords
      ensure_state
      data = File.read(@pass_file)
      if data.empty?
        puts "No passwords saved yet."
      else
        print data
      end
    end

    def ssh_level(level)
      ensure_state
      user = "bandit#{level}"
      password = get_saved_password(user)
      if password.empty?
        exec("ssh", "#{user}@#{@host}", "-p", @port)
        return
      end

      script_file = File.join(Dir.tmpdir, "bandit-ssh.#{Process.pid}.exp")
      File.write(script_file, SCRIPT_INTERACTIVE)
      begin
        env = {
          "BANDIT_HOST_VALUE" => @host,
          "BANDIT_PORT_VALUE" => @port,
          "BANDIT_USER_VALUE" => user,
          "BANDIT_PASSWORD_VALUE" => password,
        }
        system(env, "expect", "-f", script_file)
      ensure
        File.delete(script_file) if File.exist?(script_file)
      end
    end

    def save_password_interactive
      print "Save password for which user? Example: bandit6: "
      user = gets.to_s.strip
      print "Password: "
      password = gets.to_s.strip
      save_password(user, password)
      puts "Saved password for #{user}."
    end

    def menu(cfg)
      ensure_state
      loop do
        puts "===================================="
        puts "        OverTheWire Bandit App"
        puts "===================================="
        puts
        puts "Password file: #{@pass_file}"
        puts "Key cache:     #{@key_dir}"
        puts
        puts "1) SSH into a Bandit level"
        puts "2) Refresh all passwords"
        puts "3) Save/update a password"
        puts "4) Show saved passwords"
        puts "5) Exit"
        puts
        print "Choose an option: "
        choice = gets.to_s.strip

        case choice
        when "1"
          print "Bandit level number, e.g. 0, 1, 26, 33: "
          ssh_level(gets.to_s.strip.to_i)
        when "2"
          refresh(cfg)
          print "Press Enter to continue..."
          gets
        when "3" then save_password_interactive
        when "4"
          show_passwords
          print "Press Enter to continue..."
          gets
        when "5" then return
        else puts "Invalid option."
        end
      end
    end
  end
end

if $PROGRAM_NAME == __FILE__
  begin
    Bandit::App.new(ARGV).run
  rescue StandardError => e
    warn "error: #{e.message}"
    exit 1
  end
end
