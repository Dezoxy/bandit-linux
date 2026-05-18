package main

import (
	"path/filepath"
	"testing"
)

func TestLoadSharedConfig(t *testing.T) {
	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Fatal(err)
	}

	helper := &app{
		repoRoot:   repoRoot,
		configPath: filepath.Join(repoRoot, "levels", "bandit-levels.toml"),
	}

	cfg, err := helper.loadConfig()
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Connection.Host != defaultHost {
		t.Fatalf("host = %q, want %q", cfg.Connection.Host, defaultHost)
	}
	if cfg.Connection.Port != 2220 {
		t.Fatalf("port = %d, want 2220", cfg.Connection.Port)
	}
	if cfg.Bootstrap.Level != 0 || cfg.Bootstrap.Password != "bandit0" {
		t.Fatalf("bootstrap = (%d, %q), want (0, bandit0)", cfg.Bootstrap.Level, cfg.Bootstrap.Password)
	}
	if len(cfg.Steps) != 32 {
		t.Fatalf("steps = %d, want 32", len(cfg.Steps))
	}

	bandit26Step := cfg.Steps[25]
	if got := mustString(bandit26Step, "type"); got != "bandit26_escape" {
		t.Fatalf("step 26 type = %q, want bandit26_escape", got)
	}
	targets := mustToList(bandit26Step)
	if len(targets) != 2 || targets[0] != 26 || targets[1] != 27 {
		t.Fatalf("bandit26 targets = %v, want [26 27]", targets)
	}
}
