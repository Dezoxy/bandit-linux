import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import { existsSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseToml } from "smol-toml";

import {
    findRepoRoot,
    stripTerminalCodes,
    extractPassword,
    extractPasswords,
    renderTemplate,
    validateConfig,
    type Step,
} from "../src/bandit-helper.js";

const here = path.dirname(fileURLToPath(import.meta.url));

test("findRepoRoot locates the levels directory", () => {
    const root = findRepoRoot(here);
    assert.ok(root);
    assert.ok(existsSync(path.join(root, "levels", "bandit-levels.toml")));
});

test("shared TOML config parses and validates", async () => {
    const root = findRepoRoot(here);
    const text = await fs.readFile(path.join(root, "levels", "bandit-levels.toml"), "utf8");
    const cfg = parseToml(text) as unknown;
    validateConfig(cfg);

    assert.equal(cfg.connection?.host, "bandit.labs.overthewire.org");
    assert.equal(Number(cfg.connection?.port), 2220);
    assert.equal(Number(cfg.bootstrap.level), 0);
    assert.equal(cfg.bootstrap.password, "bandit0");
    assert.equal(cfg.steps.length, 32);

    const bandit26 = cfg.steps[25] as Step;
    assert.equal(bandit26.type, "bandit26_escape");
    assert.ok(Array.isArray(bandit26.to));
    assert.deepEqual((bandit26.to as number[]).map(Number), [26, 27]);
});

test("extractPassword returns the last 32-char alphanumeric match", () => {
    const text =
        "noise abcdefghijklmnopqrstuvwxyz012345 then ABCDEFGHIJKLMNOPQRSTUVWXYZ012345 tail";
    assert.equal(extractPassword(text), "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345");
    assert.equal(extractPasswords(text).length, 2);
});

test("stripTerminalCodes removes ANSI sequences and carriage returns", () => {
    const dirty = "hello[31mred[0m\rworld";
    assert.equal(stripTerminalCodes(dirty), "helloredworld");
});

test("renderTemplate replaces all placeholders", () => {
    const out = renderTemplate("level={level} pass={password} {password}", {
        level: 7,
        password: "abc",
    });
    assert.equal(out, "level=7 pass=abc abc");
});
