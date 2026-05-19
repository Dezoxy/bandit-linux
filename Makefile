SHELL := /bin/bash
.DEFAULT_GOAL := help

ifeq ($(origin LANG), environment)
LANG := python
endif
LANG ?= python
unexport LANG
LEVEL ?=

PYTHON ?= python3
GO ?= go
MAVEN ?= mvn
CC ?= cc
NODE ?= node
NPM ?= npm
DOTNET ?= dotnet
CARGO ?= cargo
BUNDLE ?= $(shell if [ -x /opt/homebrew/opt/ruby/bin/bundle ]; then printf '%s\n' /opt/homebrew/opt/ruby/bin/bundle; elif command -v bundle >/dev/null 2>&1; then command -v bundle; else printf '%s\n' bundle; fi)
RUBY ?= $(shell if [ -x /opt/homebrew/opt/ruby/bin/ruby ]; then printf '%s\n' /opt/homebrew/opt/ruby/bin/ruby; elif command -v ruby >/dev/null 2>&1; then command -v ruby; else printf '%s\n' ruby; fi)
PERL ?= perl
SWIFT ?= swift
JAVA_HOME_FOR_MAVEN ?= $(shell if [ -d /opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home ]; then printf '%s\n' /opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home; elif [ -d /opt/homebrew/opt/openjdk@25/libexec/openjdk.jdk/Contents/Home ]; then printf '%s\n' /opt/homebrew/opt/openjdk@25/libexec/openjdk.jdk/Contents/Home; elif [ -n "$$JAVA_HOME" ]; then printf '%s\n' "$$JAVA_HOME"; else printf '%s\n' ""; fi)
JAVA ?= $(shell if [ -n "$(JAVA_HOME_FOR_MAVEN)" ] && [ -x "$(JAVA_HOME_FOR_MAVEN)/bin/java" ]; then printf '%s\n' "$(JAVA_HOME_FOR_MAVEN)/bin/java"; elif command -v java >/dev/null 2>&1; then command -v java; else printf '%s\n' java; fi)
MAVEN_WITH_JAVA = JAVA_HOME="$(JAVA_HOME_FOR_MAVEN)" PATH="$(JAVA_HOME_FOR_MAVEN)/bin:$$PATH" $(MAVEN)
ZIG ?= $(shell if [ -x /opt/homebrew/opt/zig@0.15/bin/zig ]; then printf '%s\n' /opt/homebrew/opt/zig@0.15/bin/zig; elif command -v zig >/dev/null 2>&1; then command -v zig; else printf '%s\n' zig; fi)

LANGUAGES := bash python go java c kotlin node csharp rust ruby perl swift typescript zig
INTERPRETED_LANGUAGES := bash python node ruby perl
BUILD_LANGUAGES := go java c kotlin csharp rust swift typescript zig

.PHONY: help list all deps lint test build smoke check verify diff-check clean clean-deps
.PHONY: run show refresh ssh
.PHONY: deps-node deps-typescript deps-ruby deps-java deps-kotlin deps-csharp deps-rust deps-swift
.PHONY: lint-bash lint-python lint-go lint-node lint-ruby lint-perl lint-typescript lint-zig
.PHONY: test-bash test-python test-go test-java test-c test-kotlin test-node test-csharp test-rust test-ruby test-perl test-swift test-typescript test-zig
.PHONY: build-bash build-python build-go build-java build-c build-kotlin build-node build-csharp build-rust build-ruby build-perl build-swift build-typescript build-zig
.PHONY: smoke-bash smoke-python smoke-go smoke-java smoke-c smoke-kotlin smoke-node smoke-csharp smoke-rust smoke-ruby smoke-perl smoke-swift smoke-typescript smoke-zig
.PHONY: run-bash run-python run-go run-java run-c run-kotlin run-node run-csharp run-rust run-ruby run-perl run-swift run-typescript run-zig
.PHONY: show-bash show-python show-go show-java show-c show-kotlin show-node show-csharp show-rust show-ruby show-perl show-swift show-typescript show-zig
.PHONY: refresh-bash refresh-python refresh-go refresh-java refresh-c refresh-kotlin refresh-node refresh-csharp refresh-rust refresh-ruby refresh-perl refresh-swift refresh-typescript refresh-zig
.PHONY: ssh-bash ssh-python ssh-go ssh-java ssh-c ssh-kotlin ssh-node ssh-csharp ssh-rust ssh-ruby ssh-perl ssh-swift ssh-typescript ssh-zig

help:
	@printf '%s\n' 'Bandit solver orchestration'
	@printf '%s\n' ''
	@printf '%s\n' 'Common targets:'
	@printf '%s\n' '  make list                 Show languages and groups'
	@printf '%s\n' '  make deps                 Install package dependencies where applicable'
	@printf '%s\n' '  make lint                 Syntax/format checks only'
	@printf '%s\n' '  make test                 Offline tests only; no Bandit SSH refresh'
	@printf '%s\n' '  make build                Build/compile every port that has a build step'
	@printf '%s\n' '  make smoke                Start each CLI with --show and discard output'
	@printf '%s\n' '  make verify               Pre-commit check: lint + test + build + smoke'
	@printf '%s\n' '  make clean                Remove build artifacts, keep deps and secrets'
	@printf '%s\n' '  make clean-deps           Remove installed local package dependencies'
	@printf '%s\n' ''
	@printf '%s\n' 'Language-scoped commands:'
	@printf '%s\n' '  make run LANG=go'
	@printf '%s\n' '  make show LANG=python'
	@printf '%s\n' '  make refresh LANG=perl    Live OverTheWire run'
	@printf '%s\n' '  make ssh LANG=rust LEVEL=12'
	@printf '%s\n' ''
	@printf '%s\n' 'Explicit targets also exist, e.g. make test-go, make build-java, make refresh-zig.'

list:
	@printf 'Languages: %s\n' "$(LANGUAGES)"
	@printf 'Interpreted/no-build-first ports: %s\n' "$(INTERPRETED_LANGUAGES)"
	@printf 'Build-first ports: %s\n' "$(BUILD_LANGUAGES)"
	@printf 'Default LANG: %s\n' "$(LANG)"
	@printf 'Zig command: %s\n' "$(ZIG)"
	@printf 'Java command: %s\n' "$(JAVA)"
	@printf 'Maven JAVA_HOME: %s\n' "$(JAVA_HOME_FOR_MAVEN)"

all: build

deps: deps-node deps-typescript deps-ruby deps-java deps-kotlin deps-csharp deps-rust deps-swift

deps-node:
	cd node && $(NPM) ci

deps-typescript:
	cd typescript && $(NPM) ci

deps-ruby:
	cd ruby && $(BUNDLE) install

deps-java:
	$(MAVEN_WITH_JAVA) -q -f java/pom.xml dependency:go-offline

deps-kotlin:
	$(MAVEN_WITH_JAVA) -q -f kotlin/pom.xml dependency:go-offline

deps-csharp:
	$(DOTNET) restore csharp/test/BanditHelper.Tests.csproj

deps-rust:
	$(CARGO) fetch --manifest-path rust/Cargo.toml

deps-swift:
	cd swift && $(SWIFT) package resolve

lint: diff-check lint-bash lint-python lint-go lint-node lint-ruby lint-perl lint-typescript lint-zig

diff-check:
	git diff --check

test: test-bash test-python test-go test-java test-c test-kotlin test-node test-csharp test-rust test-ruby test-perl test-swift test-typescript test-zig

build: build-bash build-python build-go build-java build-c build-kotlin build-node build-csharp build-rust build-ruby build-perl build-swift build-typescript build-zig

smoke: smoke-bash smoke-python smoke-go smoke-java smoke-c smoke-kotlin smoke-node smoke-csharp smoke-rust smoke-ruby smoke-perl smoke-swift smoke-typescript smoke-zig

check: lint test build smoke

verify: check

run:
	@$(MAKE) --no-print-directory run-$(LANG)

show:
	@$(MAKE) --no-print-directory show-$(LANG)

refresh:
	@$(MAKE) --no-print-directory refresh-$(LANG)

ssh:
	@[ -n "$(LEVEL)" ] || { printf '%s\n' 'LEVEL is required, e.g. make ssh LANG=python LEVEL=12'; exit 2; }
	@$(MAKE) --no-print-directory ssh-$(LANG) LEVEL=$(LEVEL)

lint-bash:
	bash -n bash/bandit-helper.sh
	@if command -v shellcheck >/dev/null 2>&1; then shellcheck bash/bandit-helper.sh; else printf '%s\n' 'shellcheck not found; skipping bash lint'; fi

lint-python:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m py_compile python/bandit_helper.py

lint-go:
	@test -z "$$(gofmt -l go/cmd/bandit-helper/*.go)" || { gofmt -l go/cmd/bandit-helper/*.go; exit 1; }

lint-node:
	$(NODE) --check node/bandit-helper.mjs

lint-ruby:
	$(RUBY) -c ruby/bandit_helper.rb

lint-perl:
	$(PERL) -c perl/bandit_helper.pl

lint-typescript:
	cd typescript && $(NPM) run typecheck

lint-zig:
	cd zig && $(ZIG) fmt --check build.zig src/main.zig

test-bash: lint-bash

test-python: lint-python

test-go:
	cd go && $(GO) test ./...

test-java:
	$(MAVEN_WITH_JAVA) -q -f java/pom.xml test

test-c:
	$(MAKE) -C c test

test-kotlin:
	$(MAVEN_WITH_JAVA) -q -f kotlin/pom.xml test

test-node:
	cd node && $(NPM) test

test-csharp:
	$(DOTNET) test csharp/test/BanditHelper.Tests.csproj

test-rust:
	$(CARGO) test --manifest-path rust/Cargo.toml

test-ruby:
	cd ruby && $(BUNDLE) exec $(RUBY) test/test_bandit_helper.rb

test-perl:
	$(PERL) perl/test/test_bandit_helper.t

test-swift:
	cd swift && $(SWIFT) run bandit-test

test-typescript:
	cd typescript && $(NPM) test

test-zig:
	cd zig && $(ZIG) build test --summary all

build-bash: lint-bash

build-python: lint-python

build-go:
	cd go && $(GO) build ./cmd/bandit-helper

build-java:
	$(MAVEN_WITH_JAVA) -q -f java/pom.xml package

build-c:
	$(MAKE) -C c

build-kotlin:
	$(MAVEN_WITH_JAVA) -q -f kotlin/pom.xml package

build-node: lint-node

build-csharp:
	$(DOTNET) build csharp/src/BanditHelper.csproj -c Release

build-rust:
	$(CARGO) build --manifest-path rust/Cargo.toml

build-ruby: lint-ruby

build-perl: lint-perl

build-swift:
	cd swift && $(SWIFT) build

build-typescript:
	cd typescript && $(NPM) run build

build-zig:
	cd zig && $(ZIG) build

smoke-bash:
	@./bash/bandit-helper.sh --show >/dev/null

smoke-python:
	@$(PYTHON) python/bandit_helper.py --show >/dev/null

smoke-go:
	@cd go && $(GO) run ./cmd/bandit-helper --show >/dev/null

smoke-java: build-java
	@$(JAVA) -jar java/target/bandit-helper.jar --show >/dev/null

smoke-c: build-c
	@c/bin/bandit-helper --show >/dev/null

smoke-kotlin: build-kotlin
	@$(JAVA) -jar kotlin/target/bandit-helper.jar --show >/dev/null

smoke-node:
	@$(NODE) node/bandit-helper.mjs --show >/dev/null

smoke-csharp:
	@$(DOTNET) run --project csharp/src/BanditHelper.csproj -- --show >/dev/null

smoke-rust:
	@$(CARGO) run --quiet --manifest-path rust/Cargo.toml -- --show >/dev/null

smoke-ruby:
	@cd ruby && $(BUNDLE) exec $(RUBY) bandit_helper.rb --show >/dev/null

smoke-perl:
	@$(PERL) perl/bandit_helper.pl --show >/dev/null

smoke-swift:
	@cd swift && $(SWIFT) run bandit-helper --show >/dev/null

smoke-typescript: build-typescript
	@$(NODE) typescript/dist/src/bandit-helper.js --show >/dev/null

smoke-zig:
	@cd zig && $(ZIG) build run -- --show >/dev/null

run-bash:
	./bash/bandit-helper.sh

run-python:
	$(PYTHON) python/bandit_helper.py

run-go:
	cd go && $(GO) run ./cmd/bandit-helper

run-java: build-java
	$(JAVA) -jar java/target/bandit-helper.jar

run-c: build-c
	c/bin/bandit-helper

run-kotlin: build-kotlin
	$(JAVA) -jar kotlin/target/bandit-helper.jar

run-node:
	$(NODE) node/bandit-helper.mjs

run-csharp:
	$(DOTNET) run --project csharp/src/BanditHelper.csproj --

run-rust:
	$(CARGO) run --manifest-path rust/Cargo.toml --

run-ruby:
	cd ruby && $(BUNDLE) exec $(RUBY) bandit_helper.rb

run-perl:
	$(PERL) perl/bandit_helper.pl

run-swift:
	cd swift && $(SWIFT) run bandit-helper

run-typescript: build-typescript
	$(NODE) typescript/dist/src/bandit-helper.js

run-zig:
	cd zig && $(ZIG) build run

show-bash:
	./bash/bandit-helper.sh --show

show-python:
	$(PYTHON) python/bandit_helper.py --show

show-go:
	cd go && $(GO) run ./cmd/bandit-helper --show

show-java: build-java
	$(JAVA) -jar java/target/bandit-helper.jar --show

show-c: build-c
	c/bin/bandit-helper --show

show-kotlin: build-kotlin
	$(JAVA) -jar kotlin/target/bandit-helper.jar --show

show-node:
	$(NODE) node/bandit-helper.mjs --show

show-csharp:
	$(DOTNET) run --project csharp/src/BanditHelper.csproj -- --show

show-rust:
	$(CARGO) run --manifest-path rust/Cargo.toml -- --show

show-ruby:
	cd ruby && $(BUNDLE) exec $(RUBY) bandit_helper.rb --show

show-perl:
	$(PERL) perl/bandit_helper.pl --show

show-swift:
	cd swift && $(SWIFT) run bandit-helper --show

show-typescript: build-typescript
	$(NODE) typescript/dist/src/bandit-helper.js --show

show-zig:
	cd zig && $(ZIG) build run -- --show

refresh-bash:
	./bash/bandit-helper.sh --refresh

refresh-python:
	$(PYTHON) python/bandit_helper.py --refresh

refresh-go:
	cd go && $(GO) run ./cmd/bandit-helper --refresh

refresh-java: build-java
	$(JAVA) -jar java/target/bandit-helper.jar --refresh

refresh-c: build-c
	c/bin/bandit-helper --refresh

refresh-kotlin: build-kotlin
	$(JAVA) -jar kotlin/target/bandit-helper.jar --refresh

refresh-node:
	$(NODE) node/bandit-helper.mjs --refresh

refresh-csharp:
	$(DOTNET) run --project csharp/src/BanditHelper.csproj -- --refresh

refresh-rust:
	$(CARGO) run --manifest-path rust/Cargo.toml -- --refresh

refresh-ruby:
	cd ruby && $(BUNDLE) exec $(RUBY) bandit_helper.rb --refresh

refresh-perl:
	$(PERL) perl/bandit_helper.pl --refresh

refresh-swift:
	cd swift && $(SWIFT) run bandit-helper --refresh

refresh-typescript: build-typescript
	$(NODE) typescript/dist/src/bandit-helper.js --refresh

refresh-zig:
	cd zig && $(ZIG) build run -- --refresh

ssh-bash:
	./bash/bandit-helper.sh --ssh $(LEVEL)

ssh-python:
	$(PYTHON) python/bandit_helper.py --ssh $(LEVEL)

ssh-go:
	cd go && $(GO) run ./cmd/bandit-helper --ssh $(LEVEL)

ssh-java: build-java
	$(JAVA) -jar java/target/bandit-helper.jar --ssh $(LEVEL)

ssh-c: build-c
	c/bin/bandit-helper --ssh $(LEVEL)

ssh-kotlin: build-kotlin
	$(JAVA) -jar kotlin/target/bandit-helper.jar --ssh $(LEVEL)

ssh-node:
	$(NODE) node/bandit-helper.mjs --ssh $(LEVEL)

ssh-csharp:
	$(DOTNET) run --project csharp/src/BanditHelper.csproj -- --ssh $(LEVEL)

ssh-rust:
	$(CARGO) run --manifest-path rust/Cargo.toml -- --ssh $(LEVEL)

ssh-ruby:
	cd ruby && $(BUNDLE) exec $(RUBY) bandit_helper.rb --ssh $(LEVEL)

ssh-perl:
	$(PERL) perl/bandit_helper.pl --ssh $(LEVEL)

ssh-swift:
	cd swift && $(SWIFT) run bandit-helper --ssh $(LEVEL)

ssh-typescript: build-typescript
	$(NODE) typescript/dist/src/bandit-helper.js --ssh $(LEVEL)

ssh-zig:
	cd zig && $(ZIG) build run -- --ssh $(LEVEL)

clean:
	rm -f go/bandit-helper
	rm -rf java/target kotlin/target c/bin rust/target swift/.build swift/.swiftpm typescript/dist typescript/*.tsbuildinfo zig/.zig-cache zig/zig-cache zig/zig-out
	find csharp -type d \( -name bin -o -name obj \) -prune -exec rm -rf {} +
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +

clean-deps:
	rm -rf node/node_modules typescript/node_modules ruby/vendor/bundle ruby/vendor/cache ruby/.bundle
