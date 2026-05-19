#!/usr/bin/env perl
use strict;
use warnings;
use feature qw(say);

package Bandit;
use strict;
use warnings;
use Cwd qw(getcwd);
use Exporter qw(import);
use File::Spec;

our @EXPORT_OK = qw(
    DEFAULT_HOST DEFAULT_PORT PASSWORD_RE
    env_or find_repo_root parse_toml_file validate_config
    strip_terminal_codes extract_passwords extract_password
    render_template
);

use constant DEFAULT_HOST => "bandit.labs.overthewire.org";
use constant DEFAULT_PORT => "2220";

our $PASSWORD_RE = qr/[A-Za-z0-9]{32}/;
our $PRIVATE_KEY_RE = qr/-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----/s;

my %REQUIRED_FIELDS = (
    ssh_command          => [qw(from to command)],
    path_then_command    => [qw(from to find_command command)],
    private_key_then_ssh => [qw(from to key_command key_name next_user next_command)],
    bandit26_escape      => [qw(from to key_command key_name)],
    git_read_file        => [qw(from to git_user repo file)],
    git_show             => [qw(from to git_user repo object)],
    git_push_file        => [qw(from to git_user repo file content commit_message)],
    uppercase_shell      => [qw(from to)],
);

sub env_or {
    my ($name, $fallback) = @_;
    return exists $ENV{$name} && length $ENV{$name} ? $ENV{$name} : $fallback;
}

sub find_repo_root {
    my $cwd = getcwd();
    while (1) {
        return $cwd if -e File::Spec->catfile($cwd, "levels", "bandit-levels.toml");
        my $parent = File::Spec->rel2abs(File::Spec->catdir($cwd, ".."));
        die "could not find repo root containing levels/bandit-levels.toml" if $parent eq $cwd;
        $cwd = $parent;
    }
}

sub parse_toml_file {
    my ($path) = @_;
    open my $fh, "<", $path or die "read config: $!";
    local $/;
    my $text = <$fh>;
    close $fh;

    my $doc = {};
    my $current = $doc;
    my @lines = split /\n/, $text, -1;

    for (my $i = 0; $i < @lines; $i++) {
        my $line = $lines[$i];
        $line =~ s/\r\z//;
        next if $line =~ /^\s*(?:#.*)?\z/;

        if ($line =~ /^\s*\[\[([A-Za-z0-9_-]+)\]\]\s*(?:#.*)?\z/) {
            my $name = $1;
            $doc->{$name} ||= [];
            die "$name must be an array table" if ref($doc->{$name}) ne "ARRAY";
            my $entry = {};
            push @{ $doc->{$name} }, $entry;
            $current = $entry;
            next;
        }

        if ($line =~ /^\s*\[([A-Za-z0-9_-]+)\]\s*(?:#.*)?\z/) {
            my $name = $1;
            $doc->{$name} ||= {};
            die "$name must be a table" if ref($doc->{$name}) ne "HASH";
            $current = $doc->{$name};
            next;
        }

        if ($line =~ /^\s*([A-Za-z0-9_-]+)\s*=\s*(.*?)\s*(?:#.*)?\z/) {
            my ($key, $raw) = ($1, $2);
            if ($raw eq "'''") {
                my @body;
                $i++;
                while ($i < @lines && $lines[$i] !~ /^\s*'''\s*(?:#.*)?\z/) {
                    my $body_line = $lines[$i];
                    $body_line =~ s/\r\z//;
                    push @body, $body_line;
                    $i++;
                }
                die "unterminated literal string for $key" if $i >= @lines;
                $current->{$key} = join("\n", @body);
            } else {
                $current->{$key} = _parse_toml_value($raw);
            }
            next;
        }

        die "unsupported TOML line: $line";
    }

    return $doc;
}

sub _parse_toml_value {
    my ($raw) = @_;
    $raw =~ s/^\s+|\s+\z//g;

    if ($raw =~ /^"(.*)"\z/s) {
        return _parse_basic_string($1);
    }
    if ($raw =~ /^'(.*)'\z/s) {
        return $1;
    }
    if ($raw =~ /^\[(.*)\]\z/s) {
        my $inside = $1;
        my @items = grep { length } map {
            my $v = $_;
            $v =~ s/^\s+|\s+\z//g;
            $v;
        } split /,/, $inside;
        return [map { _parse_toml_value($_) } @items];
    }
    if ($raw =~ /^[+-]?\d+\z/) {
        return 0 + $raw;
    }

    die "unsupported TOML value: $raw";
}

sub _parse_basic_string {
    my ($raw) = @_;
    my $out = "";
    my @chars = split //, $raw;
    for (my $i = 0; $i < @chars; $i++) {
        my $c = $chars[$i];
        if ($c ne "\\") {
            $out .= $c;
            next;
        }
        die "unterminated escape in string" if ++$i >= @chars;
        my $esc = $chars[$i];
        if ($esc eq "n") {
            $out .= "\n";
        } elsif ($esc eq "t") {
            $out .= "\t";
        } elsif ($esc eq "r") {
            $out .= "\r";
        } elsif ($esc eq "b") {
            $out .= "\b";
        } elsif ($esc eq "f") {
            $out .= "\f";
        } elsif ($esc eq '"' || $esc eq "\\" || $esc eq "/") {
            $out .= $esc;
        } else {
            die "unsupported escape in string: \\$esc";
        }
    }
    return $out;
}

sub validate_config {
    my ($cfg) = @_;
    die "config is missing [bootstrap]" unless ref($cfg->{bootstrap}) eq "HASH";
    die "config bootstrap level is missing" unless exists $cfg->{bootstrap}{level};
    die "config bootstrap password is empty"
        unless exists $cfg->{bootstrap}{password} && length $cfg->{bootstrap}{password};

    die "config has no steps" unless ref($cfg->{steps}) eq "ARRAY" && @{ $cfg->{steps} };

    for my $idx (0 .. $#{ $cfg->{steps} }) {
        my $step = $cfg->{steps}[$idx];
        my $type = $step->{type};
        my $required = $REQUIRED_FIELDS{$type};
        die sprintf('step %d has unsupported type "%s"', $idx + 1, defined $type ? $type : "")
            unless $required;
        for my $field (@$required) {
            die "step " . ($idx + 1) . " ($type) is missing $field"
                unless exists $step->{$field};
        }
    }
}

sub strip_terminal_codes {
    my ($text) = @_;
    $text = "" unless defined $text;
    $text =~ s/\e\[[0-?]*[ -\/]*[@-~]//g;
    $text =~ s/\eP.*?\e\\//gs;
    $text =~ s/\e\].*?(?:\a|\e\\)//gs;
    $text =~ s/\e.//gs;
    $text =~ tr/\r//d;
    return $text;
}

sub extract_passwords {
    my ($text) = @_;
    my $clean = strip_terminal_codes($text);
    my @matches = $clean =~ /($PASSWORD_RE)/g;
    return @matches;
}

sub extract_password {
    my ($text) = @_;
    my @matches = extract_passwords($text);
    die "failed to extract a 32-character password from output:\n$text" unless @matches;
    return $matches[-1];
}

sub render_template {
    my ($template, $values) = @_;
    my $out = $template;
    for my $key (keys %$values) {
        my $value = $values->{$key};
        $out =~ s/\{\Q$key\E\}/$value/g;
    }
    return $out;
}

package Bandit::App;
use strict;
use warnings;
use Cwd qw(getcwd);
use File::Path qw(make_path);
use File::Spec;
use File::Temp qw(tempdir);
use IO::Select;
use IPC::Open3;
use Symbol qw(gensym);

my $SCRIPT_PASSWORD_SSH = <<'SCRIPT';
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
SCRIPT

my $SCRIPT_BANDIT26 = <<'SCRIPT';
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

my $SCRIPT_UPPERCASE = <<'SCRIPT';
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

my $SCRIPT_INTERACTIVE = <<'SCRIPT';
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

sub new {
    my ($class, $args) = @_;
    my $repo_root = Bandit::find_repo_root();
    my $default_config = File::Spec->catfile($repo_root, "levels", "bandit-levels.toml");
    my $self = bless {
        repo_root => $repo_root,
        config_path => Bandit::env_or("BANDIT_LEVELS_FILE", $default_config),
        pass_file => File::Spec->catfile($repo_root, "bandit-passwords.txt"),
        key_dir => File::Spec->catdir($repo_root, ".bandit-keys"),
        host => Bandit::DEFAULT_HOST(),
        port => Bandit::DEFAULT_PORT(),
        refresh_flag => 0,
        show_flag => 0,
        ssh_level_arg => -1,
    }, $class;
    $self->parse_args($args);
    return $self;
}

sub parse_args {
    my ($self, $args) = @_;
    for (my $i = 0; $i < @$args; $i++) {
        my $arg = $args->[$i];
        if ($arg eq "--config") {
            die "--config requires a path" if $i + 1 >= @$args;
            $self->{config_path} = $args->[++$i];
        } elsif ($arg eq "--refresh") {
            $self->{refresh_flag} = 1;
        } elsif ($arg eq "--show") {
            $self->{show_flag} = 1;
        } elsif ($arg eq "--ssh") {
            die "--ssh requires a level" if $i + 1 >= @$args;
            $self->{ssh_level_arg} = 0 + $args->[++$i];
        } else {
            die "unknown flag: $arg";
        }
    }
}

sub run {
    my ($self) = @_;
    my $cfg = $self->load_config();
    $self->apply_connection($cfg);

    if ($self->{refresh_flag}) {
        return $self->refresh($cfg);
    }
    if ($self->{show_flag}) {
        return $self->show_passwords();
    }
    if ($self->{ssh_level_arg} >= 0) {
        return $self->ssh_level($self->{ssh_level_arg});
    }
    return $self->menu($cfg);
}

sub load_config {
    my ($self) = @_;
    die "missing level config: $self->{config_path}" unless -e $self->{config_path};
    my $cfg = Bandit::parse_toml_file($self->{config_path});
    Bandit::validate_config($cfg);
    return $cfg;
}

sub apply_connection {
    my ($self, $cfg) = @_;
    my $connection = ref($cfg->{connection}) eq "HASH" ? $cfg->{connection} : {};
    $self->{host} = Bandit::env_or("BANDIT_HOST", $connection->{host} || Bandit::DEFAULT_HOST());
    $self->{port} = Bandit::env_or("BANDIT_PORT", defined $connection->{port} ? "$connection->{port}" : Bandit::DEFAULT_PORT());
}

sub ensure_state {
    my ($self) = @_;
    make_path($self->{key_dir}, { mode => 0700 });
    chmod 0700, $self->{key_dir};
    open my $fh, ">>", $self->{pass_file} or die "open password file: $!";
    close $fh;
    chmod 0600, $self->{pass_file};
}

sub check_dependencies {
    for my $cmd (qw(expect ssh git awk grep mktemp)) {
        die "missing required command: $cmd" unless _which($cmd);
    }
}

sub _which {
    my ($cmd) = @_;
    for my $dir (split /:/, $ENV{PATH} || "") {
        next unless length $dir;
        my $candidate = File::Spec->catfile($dir, $cmd);
        return $candidate if -f $candidate && -x $candidate;
    }
    return;
}

sub run_command {
    my ($self, $name, $args, %opts) = @_;
    $args ||= [];
    my $env = $opts{env} || {};
    my $input = $opts{input};
    my $cwd = $opts{cwd};
    my $old_cwd = getcwd();
    my ($in, $out, $err);
    $err = gensym;
    my $pid;

    {
        local %ENV = (%ENV, %$env);
        chdir $cwd or die "chdir $cwd: $!" if defined $cwd;
        eval { $pid = open3($in, $out, $err, $name, @$args); 1 } or do {
            my $e = $@ || $!;
            chdir $old_cwd if defined $cwd;
            die "spawn $name: $e";
        };
        chdir $old_cwd if defined $cwd;
    }

    if (defined $input) {
        print {$in} $input;
    }
    close $in;

    my $selector = IO::Select->new($out, $err);
    my $output = "";
    while (my @ready = $selector->can_read) {
        for my $fh (@ready) {
            my $buffer = "";
            my $bytes = sysread($fh, $buffer, 4096);
            if ($bytes) {
                $output .= $buffer;
            } else {
                $selector->remove($fh);
                close $fh;
            }
        }
    }

    waitpid($pid, 0);
    my $code = $? >> 8;
    return ($code, $output);
}

sub run_expect {
    my ($self, $script, $env) = @_;
    my ($code, $output) = $self->run_command("expect", [], env => $env, input => $script);
    die $output if $code != 0;
    return $output;
}

sub save_password {
    my ($self, $user, $password) = @_;
    $self->ensure_state();
    my @lines;
    if (-e $self->{pass_file}) {
        open my $in, "<", $self->{pass_file} or die "read password file: $!";
        while (my $line = <$in>) {
            chomp $line;
            next if $line eq "" || index($line, "$user:") == 0;
            push @lines, $line;
        }
        close $in;
    }
    push @lines, "$user: $password";
    open my $out, ">", $self->{pass_file} or die "write password file: $!";
    print {$out} join("\n", @lines), "\n";
    close $out;
    chmod 0600, $self->{pass_file};
}

sub get_saved_password {
    my ($self, $user) = @_;
    return "" unless -e $self->{pass_file};
    my $prefix = "$user: ";
    my $password = "";
    open my $fh, "<", $self->{pass_file} or die "read password file: $!";
    while (my $line = <$fh>) {
        chomp $line;
        $password = substr($line, length($prefix)) if index($line, $prefix) == 0;
    }
    close $fh;
    return $password;
}

sub record_password {
    my ($self, $level, $password) = @_;
    my $user = "bandit$level";
    die "refusing to save invalid password for $user: $password"
        if $level != 0 && $password !~ /\A$Bandit::PASSWORD_RE\z/;
    $self->save_password($user, $password);
    printf "[+] %-8s %s\n", $user, $password;
}

sub run_password_ssh_command {
    my ($self, $user, $password, $command_text) = @_;
    my $env = {
        BANDIT_HOST_VALUE => $self->{host},
        BANDIT_PORT_VALUE => $self->{port},
        BANDIT_USER_VALUE => $user,
        BANDIT_PASSWORD_VALUE => $password,
        BANDIT_COMMAND_VALUE => $command_text,
    };
    my $output = eval { $self->run_expect($SCRIPT_PASSWORD_SSH, $env) };
    die "SSH command failed for $user: $command_text\n$@" if $@;
    return $output;
}

sub run_key_ssh_command {
    my ($self, $user, $key_file, $command_text) = @_;
    my @args = (
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes",
        "-i", $key_file,
        "-p", $self->{port},
        "$user\@$self->{host}",
        $command_text,
    );
    my ($code, $output) = $self->run_command("ssh", \@args);
    die $output if $code != 0;
    return $output;
}

sub solve_password {
    my ($self, $user, $password, $command_text) = @_;
    return Bandit::extract_password($self->run_password_ssh_command($user, $password, $command_text));
}

sub solve_path {
    my ($self, $user, $password, $command_text) = @_;
    my $output = Bandit::strip_terminal_codes($self->run_password_ssh_command($user, $password, $command_text));
    my @lines = split /\n/, $output;
    for (my $i = $#lines; $i >= 0; $i--) {
        return $lines[$i] if index($lines[$i], "/inhere/") >= 0;
    }
    die "failed to extract path from output:\n$output";
}

sub save_private_key {
    my ($self, $name, $output) = @_;
    my $clean = Bandit::strip_terminal_codes($output);
    my ($key) = $clean =~ /($Bandit::PRIVATE_KEY_RE)/;
    die "failed to extract private key $name from output:\n$output" unless defined $key;
    $self->ensure_state();
    my $key_file = File::Spec->catfile($self->{key_dir}, $name);
    open my $fh, ">", $key_file or die "write private key: $!";
    print {$fh} $key, "\n";
    close $fh;
    chmod 0600, $key_file;
    return $key_file;
}

sub solve_bandit26_pair {
    my ($self, $key_file) = @_;
    my $output = $self->run_expect($SCRIPT_BANDIT26, {
        BANDIT_HOST_VALUE => $self->{host},
        BANDIT_PORT_VALUE => $self->{port},
        BANDIT_KEY_VALUE => $key_file,
    });
    my @passwords = Bandit::extract_passwords($output);
    die "expected two passwords from bandit26 output:\n$output" if @passwords < 2;
    return ($passwords[-2], $passwords[-1]);
}

sub solve_uppercase_shell {
    my ($self, $password) = @_;
    my $output = $self->run_expect($SCRIPT_UPPERCASE, {
        BANDIT_HOST_VALUE => $self->{host},
        BANDIT_PORT_VALUE => $self->{port},
        BANDIT_PASSWORD_VALUE => $password,
    });
    return Bandit::extract_password($output);
}

sub git_env {
    my ($self, $password, $askpass) = @_;
    my $ssh_cmd = "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        . "-o LogLevel=ERROR -o PubkeyAuthentication=no "
        . "-o PreferredAuthentications=password -o NumberOfPasswordPrompts=1";
    return {
        BANDIT_GIT_PASSWORD => $password,
        GIT_SSH_COMMAND => $ssh_cmd,
        SSH_ASKPASS => $askpass,
        SSH_ASKPASS_REQUIRE => "force",
        DISPLAY => Bandit::env_or("DISPLAY", ":0"),
    };
}

sub write_askpass {
    my ($self, $dir) = @_;
    my $askpass = File::Spec->catfile($dir, "askpass.sh");
    open my $fh, ">", $askpass or die "write askpass: $!";
    print {$fh} "#!/usr/bin/env bash\nprintf '%s\\n' \"\$BANDIT_GIT_PASSWORD\"\n";
    close $fh;
    chmod 0700, $askpass;
    return $askpass;
}

sub git_clone_repo {
    my ($self, $user, $password, $remote_path, $destination) = @_;
    my $tmp = tempdir("bandit-git-askpass.XXXXXX", TMPDIR => 1, CLEANUP => 1);
    my $askpass = $self->write_askpass($tmp);
    my $remote = "ssh://$user\@$self->{host}:$self->{port}$remote_path";
    my ($code, $output) = $self->run_command(
        "git",
        ["clone", $remote, $destination],
        env => $self->git_env($password, $askpass),
    );
    die $output if $code != 0;
}

sub git_push_with_password {
    my ($self, $password, $repo) = @_;
    my $tmp = tempdir("bandit-git-askpass.XXXXXX", TMPDIR => 1, CLEANUP => 1);
    my $askpass = $self->write_askpass($tmp);
    my (undef, $output) = $self->run_command(
        "git",
        ["-C", $repo, "push", "origin", "master"],
        env => $self->git_env($password, $askpass),
    );
    return $output;
}

sub step_context {
    my ($level, $password, $to_level) = @_;
    return {
        password => $password,
        level => $level,
        to => $to_level,
        random_port => 20000 + int(rand(10000)),
        temp_output => "/tmp/bandit${to_level}pass.$$." . (1000 + int(rand(9000))),
    };
}

sub refresh {
    my ($self, $cfg) = @_;
    check_dependencies();
    $self->ensure_state();

    say "Refreshing Bandit passwords via $self->{host}:$self->{port}";
    say "Level config:  $self->{config_path}";
    say "Password file: $self->{pass_file}";
    say "Key cache:     $self->{key_dir}";
    say "";

    my $boot_level = $cfg->{bootstrap}{level};
    my $boot_pass = $cfg->{bootstrap}{password};
    my %passwords = ($boot_level => $boot_pass);
    $self->record_password($boot_level, $boot_pass);

    for my $step (@{ $cfg->{steps} }) {
        $self->solve_step($step, \%passwords);
    }

    say "";
    say "Refresh complete.";
}

sub solve_step {
    my ($self, $step, $passwords) = @_;
    my $type = $step->{type};
    my $from_level = 0 + $step->{from};
    my $from_user = $step->{user} || "bandit$from_level";
    my $from_password = $passwords->{$from_level}
        or die "missing password for bandit$from_level";

    if ($type eq "ssh_command") {
        my $to_level = step_to_single($step);
        my $ctx = step_context($from_level, $from_password, $to_level);
        my $cmd = Bandit::render_template($step->{command}, $ctx);
        my $pw = $self->solve_password($from_user, $from_password, $cmd);
        $passwords->{$to_level} = $pw;
        return $self->record_password($to_level, $pw);
    }
    if ($type eq "path_then_command") {
        my $to_level = step_to_single($step);
        my $ctx = step_context($from_level, $from_password, $to_level);
        my $find_cmd = Bandit::render_template($step->{find_command}, $ctx);
        $ctx->{path} = $self->solve_path($from_user, $from_password, $find_cmd);
        my $cmd = Bandit::render_template($step->{command}, $ctx);
        my $pw = $self->solve_password($from_user, $from_password, $cmd);
        $passwords->{$to_level} = $pw;
        return $self->record_password($to_level, $pw);
    }
    if ($type eq "private_key_then_ssh") {
        my $to_level = step_to_single($step);
        my $ctx = step_context($from_level, $from_password, $to_level);
        my $key_cmd = Bandit::render_template($step->{key_command}, $ctx);
        my $output = $self->run_password_ssh_command($from_user, $from_password, $key_cmd);
        my $key_file = $self->save_private_key($step->{key_name}, $output);
        my $next_cmd = Bandit::render_template($step->{next_command}, $ctx);
        my $key_output = $self->run_key_ssh_command($step->{next_user}, $key_file, $next_cmd);
        my $pw = Bandit::extract_password($key_output);
        $passwords->{$to_level} = $pw;
        return $self->record_password($to_level, $pw);
    }
    if ($type eq "bandit26_escape") {
        my @targets = step_to_list($step);
        my $ctx = step_context($from_level, $from_password, $targets[-1]);
        my $key_cmd = Bandit::render_template($step->{key_command}, $ctx);
        my $output = $self->run_password_ssh_command($from_user, $from_password, $key_cmd);
        my $key_file = $self->save_private_key($step->{key_name}, $output);
        my @solved = $self->solve_bandit26_pair($key_file);
        die "bandit26_escape expected " . @targets . " targets, got " . @solved
            if @targets != @solved;
        for my $i (0 .. $#targets) {
            $passwords->{$targets[$i]} = $solved[$i];
            $self->record_password($targets[$i], $solved[$i]);
        }
        return;
    }
    if ($type eq "git_read_file") {
        my $to_level = step_to_single($step);
        my $tmp = tempdir("bandit-repo.XXXXXX", TMPDIR => 1, CLEANUP => 1);
        my $repo = File::Spec->catdir($tmp, "repo");
        $self->git_clone_repo($step->{git_user}, $from_password, $step->{repo}, $repo);
        open my $fh, "<", File::Spec->catfile($repo, $step->{file}) or die "read repo file: $!";
        local $/;
        my $content = <$fh>;
        close $fh;
        my $pw = Bandit::extract_password($content);
        $passwords->{$to_level} = $pw;
        return $self->record_password($to_level, $pw);
    }
    if ($type eq "git_show") {
        my $to_level = step_to_single($step);
        my $tmp = tempdir("bandit-repo.XXXXXX", TMPDIR => 1, CLEANUP => 1);
        my $repo = File::Spec->catdir($tmp, "repo");
        $self->git_clone_repo($step->{git_user}, $from_password, $step->{repo}, $repo);
        my ($code, $output) = $self->run_command("git", ["-C", $repo, "show", $step->{object}]);
        die $output if $code != 0;
        my $pw = Bandit::extract_password($output);
        $passwords->{$to_level} = $pw;
        return $self->record_password($to_level, $pw);
    }
    if ($type eq "git_push_file") {
        my $to_level = step_to_single($step);
        my $tmp = tempdir("bandit-repo.XXXXXX", TMPDIR => 1, CLEANUP => 1);
        my $repo = File::Spec->catdir($tmp, "repo");
        $self->git_clone_repo($step->{git_user}, $from_password, $step->{repo}, $repo);
        $self->git_run($repo, ["config", "user.email", "bandit-solver\@example.invalid"]);
        $self->git_run($repo, ["config", "user.name", "bandit-solver"]);
        open my $out, ">", File::Spec->catfile($repo, $step->{file}) or die "write repo file: $!";
        print {$out} $step->{content};
        close $out;
        $self->git_run($repo, ["add", "-f", $step->{file}]);
        $self->git_run($repo, ["commit", "-m", $step->{commit_message}]);
        my $push_out = $self->git_push_with_password($from_password, $repo);
        my $pw = Bandit::extract_password($push_out);
        $passwords->{$to_level} = $pw;
        return $self->record_password($to_level, $pw);
    }
    if ($type eq "uppercase_shell") {
        my $to_level = step_to_single($step);
        my $pw = $self->solve_uppercase_shell($from_password);
        $passwords->{$to_level} = $pw;
        return $self->record_password($to_level, $pw);
    }

    die "unsupported step type: $type";
}

sub git_run {
    my ($self, $repo, $args) = @_;
    my ($code, $output) = $self->run_command("git", ["-C", $repo, @$args]);
    die $output if $code != 0;
    return $output;
}

sub step_to_list {
    my ($step) = @_;
    my $value = $step->{to};
    return ($value) if !ref $value;
    return map { 0 + $_ } @$value if ref($value) eq "ARRAY";
    die "to field has unsupported type";
}

sub step_to_single {
    my ($step) = @_;
    my @list = step_to_list($step);
    die "expected single 'to' target" unless @list == 1;
    return $list[0];
}

sub show_passwords {
    my ($self) = @_;
    $self->ensure_state();
    open my $fh, "<", $self->{pass_file} or die "read password file: $!";
    local $/;
    my $data = <$fh>;
    close $fh;
    if (!defined($data) || $data eq "") {
        say "No passwords saved yet.";
    } else {
        print $data;
    }
}

sub ssh_level {
    my ($self, $level) = @_;
    $self->ensure_state();
    my $user = "bandit$level";
    my $password = $self->get_saved_password($user);
    if ($password eq "") {
        exec "ssh", "$user\@$self->{host}", "-p", $self->{port};
    }

    my $tmp = tempdir("bandit-ssh.XXXXXX", TMPDIR => 1, CLEANUP => 1);
    my $script_file = File::Spec->catfile($tmp, "ssh.exp");
    open my $fh, ">", $script_file or die "write expect script: $!";
    print {$fh} $SCRIPT_INTERACTIVE;
    close $fh;

    local %ENV = (
        %ENV,
        BANDIT_HOST_VALUE => $self->{host},
        BANDIT_PORT_VALUE => $self->{port},
        BANDIT_USER_VALUE => $user,
        BANDIT_PASSWORD_VALUE => $password,
    );
    system "expect", "-f", $script_file;
}

sub save_password_interactive {
    my ($self) = @_;
    print "Save password for which user? Example: bandit6: ";
    chomp(my $user = <STDIN>);
    print "Password: ";
    chomp(my $password = <STDIN>);
    $self->save_password($user, $password);
    say "Saved password for $user.";
}

sub menu {
    my ($self, $cfg) = @_;
    $self->ensure_state();
    while (1) {
        say "====================================";
        say "        OverTheWire Bandit App";
        say "====================================";
        say "";
        say "Password file: $self->{pass_file}";
        say "Key cache:     $self->{key_dir}";
        say "";
        say "1) SSH into a Bandit level";
        say "2) Refresh all passwords";
        say "3) Save/update a password";
        say "4) Show saved passwords";
        say "5) Exit";
        say "";
        print "Choose an option: ";
        chomp(my $choice = <STDIN>);

        if ($choice eq "1") {
            print "Bandit level number, e.g. 0, 1, 26, 33: ";
            chomp(my $level = <STDIN>);
            $self->ssh_level(0 + $level);
        } elsif ($choice eq "2") {
            $self->refresh($cfg);
            print "Press Enter to continue...";
            scalar <STDIN>;
        } elsif ($choice eq "3") {
            $self->save_password_interactive();
        } elsif ($choice eq "4") {
            $self->show_passwords();
            print "Press Enter to continue...";
            scalar <STDIN>;
        } elsif ($choice eq "5") {
            return;
        } else {
            say "Invalid option.";
        }
    }
}

package main;
use strict;
use warnings;

unless (caller) {
    eval {
        Bandit::App->new(\@ARGV)->run();
        1;
    } or do {
        my $err = $@ || "unknown error";
        chomp $err;
        warn "error: $err\n";
        exit 1;
    };
}

1;
