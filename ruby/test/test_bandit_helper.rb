# frozen_string_literal: true

require "minitest/autorun"
require "toml-rb"

$LOAD_PATH.unshift File.expand_path("..", __dir__)
require "bandit_helper"

class BanditHelperTest < Minitest::Test
  def repo_root
    @repo_root ||= begin
      cwd = Dir.pwd
      loop do
        path = File.join(cwd, "levels", "bandit-levels.toml")
        break cwd if File.exist?(path)

        parent = File.dirname(cwd)
        raise "repo root not found" if parent == cwd

        cwd = parent
      end
    end
  end

  def test_load_shared_config_parity
    path = File.join(repo_root, "levels", "bandit-levels.toml")
    cfg = TomlRB.load_file(path)
    Bandit.validate_config(cfg)

    assert_equal "bandit.labs.overthewire.org", cfg["connection"]["host"]
    assert_equal 2220, cfg["connection"]["port"]
    assert_equal 0, cfg["bootstrap"]["level"]
    assert_equal "bandit0", cfg["bootstrap"]["password"]
    assert_equal 32, cfg["steps"].length

    bandit26 = cfg["steps"][25]
    assert_equal "bandit26_escape", bandit26["type"]
    assert_equal [26, 27], bandit26["to"]
  end

  def test_extract_password_returns_last_match
    text = "noise abcdefghijklmnopqrstuvwxyz012345 then ABCDEFGHIJKLMNOPQRSTUVWXYZ012345 tail"
    assert_equal "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", Bandit.extract_password(text)
    assert_equal 2, Bandit.extract_passwords(text).length
  end

  def test_strip_terminal_codes_removes_ansi_and_cr
    dirty = "hello\e[31mred\e[0m\rworld"
    assert_equal "helloredworld", Bandit.strip_terminal_codes(dirty)
  end

  def test_render_template_replaces_all_placeholders
    out = Bandit.render_template("level={level} pass={password} {password}",
                                 "level" => 7, "password" => "abc")
    assert_equal "level=7 pass=abc abc", out
  end

  def test_env_or_falls_back
    assert_equal "fallback", Bandit.env_or("BANDIT_DEFINITELY_UNSET_VARIABLE", "fallback")
  end
end
