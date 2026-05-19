import Foundation
import TOMLKit
import BanditCore

var failures = 0
var passed = 0

func check(_ ok: Bool, _ name: String, _ detail: String = "") {
    if ok {
        passed += 1
        print("✓ \(name)")
    } else {
        failures += 1
        print("✗ \(name) \(detail)")
    }
}

func locateRepoRoot() -> URL? {
    var cwd = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
    while true {
        if FileManager.default.fileExists(atPath: cwd.appendingPathComponent("levels")
            .appendingPathComponent("bandit-levels.toml").path) {
            return cwd
        }
        let parent = cwd.deletingLastPathComponent()
        if parent.path == cwd.path { return nil }
        cwd = parent
    }
}

func testLoadSharedConfigParity() {
    guard let root = locateRepoRoot() else {
        check(false, "load_shared_config_parity", "repo root not found")
        return
    }
    do {
        let path = root.appendingPathComponent("levels").appendingPathComponent("bandit-levels.toml")
        let text = try String(contentsOf: path, encoding: .utf8)
        let table = try TOMLTable(string: text)
        check(table["connection"]?.table?["host"]?.string == "bandit.labs.overthewire.org", "host")
        check(table["connection"]?.table?["port"]?.int == 2220, "port")
        check(table["bootstrap"]?.table?["level"]?.int == 0, "bootstrap.level")
        check(table["bootstrap"]?.table?["password"]?.string == "bandit0", "bootstrap.password")
        let steps = table["steps"]?.array
        check(steps?.count == 32, "32 steps", "got \(steps?.count ?? -1)")
        let bandit26 = steps?[25].table
        check(bandit26?["type"]?.string == "bandit26_escape", "step 26 type")
        let targets = bandit26?["to"]?.array
        check(targets?.count == 2, "step 26 targets count")
        check(targets?[0].int == 26 && targets?[1].int == 27, "step 26 targets [26, 27]")
        try validateConfig(table)
        check(true, "validateConfig succeeds")
    } catch {
        check(false, "load_shared_config_parity", "\(error)")
    }
}

func testExtractPasswordReturnsLastMatch() {
    let text = "noise abcdefghijklmnopqrstuvwxyz012345 then ABCDEFGHIJKLMNOPQRSTUVWXYZ012345 tail"
    do {
        let pw = try extractPassword(text)
        check(pw == "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", "extract_password last match", "got \(pw)")
    } catch {
        check(false, "extract_password last match", "\(error)")
    }
    check(extractPasswords(text).count == 2, "extract_passwords count")
}

func testStripTerminalCodes() {
    let dirty = "hello\u{001b}[31mred\u{001b}[0m\rworld"
    let cleaned = stripTerminalCodes(dirty)
    check(cleaned == "helloredworld", "strip_terminal_codes", "got \(cleaned)")
}

func testRenderTemplate() {
    let out = renderTemplate("level={level} pass={password} {password}",
                             ["level": "7", "password": "abc"])
    check(out == "level=7 pass=abc abc", "render_template", "got \(out)")
}

func testEnvOrFallback() {
    let v = envOr("BANDIT_DEFINITELY_UNSET_VARIABLE", fallback: "fallback")
    check(v == "fallback", "env_or fallback")
}

testLoadSharedConfigParity()
testExtractPasswordReturnsLastMatch()
testStripTerminalCodes()
testRenderTemplate()
testEnvOrFallback()

print()
print("\(passed) passed, \(failures) failed")
exit(failures == 0 ? 0 : 1)
