use strict;
use warnings;
use Test::More;
use Cwd qw(getcwd abs_path);
use File::Spec;

sub repo_root {
    my $cwd = getcwd();
    while (1) {
        return $cwd if -e File::Spec->catfile($cwd, "levels", "bandit-levels.toml");
        my $parent = abs_path(File::Spec->catdir($cwd, ".."));
        die "repo root not found" if !defined($parent) || $parent eq $cwd;
        $cwd = $parent;
    }
}

my $root = repo_root();
require File::Spec->catfile($root, "perl", "bandit_helper.pl");

my $cfg = Bandit::parse_toml_file(File::Spec->catfile($root, "levels", "bandit-levels.toml"));
Bandit::validate_config($cfg);

is($cfg->{connection}{host}, "bandit.labs.overthewire.org", "loads host");
is($cfg->{connection}{port}, 2220, "loads port");
is($cfg->{bootstrap}{level}, 0, "loads bootstrap level");
is($cfg->{bootstrap}{password}, "bandit0", "loads bootstrap password");
is(scalar @{ $cfg->{steps} }, 32, "loads all steps");

my $bandit26 = $cfg->{steps}[25];
is($bandit26->{type}, "bandit26_escape", "loads bandit26 escape step");
is_deeply($bandit26->{to}, [26, 27], "loads array target");

my $text = "noise abcdefghijklmnopqrstuvwxyz012345 then ABCDEFGHIJKLMNOPQRSTUVWXYZ012345 tail";
is(Bandit::extract_password($text), "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", "extracts last password");
is(scalar Bandit::extract_passwords($text), 2, "extracts all passwords");

is(Bandit::strip_terminal_codes("hello\e[31mred\e[0m\rworld"), "helloredworld", "strips ansi and carriage return");
is(
    Bandit::render_template("level={level} pass={password} {password}", { level => 7, password => "abc" }),
    "level=7 pass=abc abc",
    "renders placeholders",
);
is(Bandit::env_or("BANDIT_DEFINITELY_UNSET_VARIABLE", "fallback"), "fallback", "env fallback works");

done_testing();
