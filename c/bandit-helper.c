#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <regex.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "toml.h"

#define DEFAULT_HOST "bandit.labs.overthewire.org"
#define DEFAULT_PORT "2220"

static char *g_host = NULL;
static char *g_port = NULL;
static char *g_repo_root = NULL;
static char *g_config_path = NULL;
static char *g_pass_file = NULL;
static char *g_key_dir = NULL;

/* ---------- memory and error helpers ---------- */

static void die(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));

static void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs("error: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(1);
}

static void *xmalloc(size_t n) {
    void *p = malloc(n);
    if (!p) die("out of memory");
    return p;
}

static void *xrealloc(void *p, size_t n) {
    void *r = realloc(p, n);
    if (!r) die("out of memory");
    return r;
}

static char *xstrdup(const char *s) {
    if (!s) return NULL;
    char *r = strdup(s);
    if (!r) die("out of memory");
    return r;
}

static char *xasprintf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static char *xasprintf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    va_list copy;
    va_copy(copy, ap);
    int n = vsnprintf(NULL, 0, fmt, copy);
    va_end(copy);
    if (n < 0) die("vsnprintf failed");
    char *buf = xmalloc((size_t)n + 1);
    vsnprintf(buf, (size_t)n + 1, fmt, ap);
    va_end(ap);
    return buf;
}

/* ---------- string builder ---------- */

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} sb_t;

static void sb_init(sb_t *s) {
    s->data = NULL;
    s->len = 0;
    s->cap = 0;
}

static void sb_reserve(sb_t *s, size_t extra) {
    if (s->len + extra + 1 > s->cap) {
        size_t cap = s->cap ? s->cap * 2 : 256;
        while (cap < s->len + extra + 1) cap *= 2;
        s->data = xrealloc(s->data, cap);
        s->cap = cap;
    }
}

static void sb_append(sb_t *s, const char *src, size_t n) {
    sb_reserve(s, n);
    memcpy(s->data + s->len, src, n);
    s->len += n;
    s->data[s->len] = '\0';
}

static void sb_append_cstr(sb_t *s, const char *src) {
    sb_append(s, src, strlen(src));
}

static char *sb_steal(sb_t *s) {
    char *out = s->data ? s->data : xstrdup("");
    s->data = NULL;
    s->len = 0;
    s->cap = 0;
    return out;
}

static void sb_free(sb_t *s) {
    free(s->data);
    s->data = NULL;
    s->len = 0;
    s->cap = 0;
}

/* ---------- file utilities ---------- */

static bool file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static bool is_executable(const char *path) {
    return access(path, X_OK) == 0;
}

static int mkpath(const char *path, mode_t mode) {
    if (mkdir(path, mode) == 0 || errno == EEXIST) return 0;
    return -1;
}

static char *read_file(const char *path, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return NULL; }
    long size = ftell(fp);
    if (size < 0) { fclose(fp); return NULL; }
    rewind(fp);
    char *buf = xmalloc((size_t)size + 1);
    size_t got = fread(buf, 1, (size_t)size, fp);
    fclose(fp);
    buf[got] = '\0';
    if (out_len) *out_len = got;
    return buf;
}

static int write_file(const char *path, const char *data, size_t len, mode_t mode) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) return -1;
    size_t written = 0;
    while (written < len) {
        ssize_t n = write(fd, data + written, len - written);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        written += (size_t)n;
    }
    close(fd);
    chmod(path, mode);
    return 0;
}

static int touch_file(const char *path, mode_t mode) {
    if (!file_exists(path)) {
        int fd = open(path, O_WRONLY | O_CREAT, mode);
        if (fd < 0) return -1;
        close(fd);
    }
    chmod(path, mode);
    return 0;
}

static int remove_recursive(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;
    if (S_ISDIR(st.st_mode)) {
        char cmd[PATH_MAX + 16];
        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
        return system(cmd);
    }
    return unlink(path);
}

/* ---------- env and repo root ---------- */

static const char *env_or(const char *name, const char *fallback) {
    const char *v = getenv(name);
    return (v && *v) ? v : fallback;
}

static char *find_repo_root(void) {
    char buf[PATH_MAX];
    if (!getcwd(buf, sizeof(buf))) die("getcwd: %s", strerror(errno));
    char cur[PATH_MAX];
    strncpy(cur, buf, sizeof(cur) - 1);
    cur[sizeof(cur) - 1] = '\0';
    for (;;) {
        char probe[PATH_MAX];
        snprintf(probe, sizeof(probe), "%s/levels/bandit-levels.toml", cur);
        if (file_exists(probe)) return xstrdup(cur);
        char *slash = strrchr(cur, '/');
        if (!slash || slash == cur) {
            die("could not find repo root containing levels/bandit-levels.toml");
        }
        *slash = '\0';
    }
}

/* ---------- ANSI stripping (state machine) ---------- */

static void strip_terminal_codes(const char *src, sb_t *out) {
    sb_init(out);
    size_t i = 0;
    size_t n = strlen(src);
    while (i < n) {
        unsigned char c = (unsigned char)src[i];
        if (c == '\r') { i++; continue; }
        if (c != 0x1B) {
            sb_append(out, (const char *)&c, 1);
            i++;
            continue;
        }
        /* ESC seen */
        i++;
        if (i >= n) break;
        unsigned char next = (unsigned char)src[i];
        if (next == '[') {
            /* CSI: ESC [ params final-byte */
            i++;
            while (i < n) {
                unsigned char ch = (unsigned char)src[i];
                if (ch >= 0x40 && ch <= 0x7E) { i++; break; }
                i++;
            }
        } else if (next == ']') {
            /* OSC: ESC ] ... BEL or ESC \ */
            i++;
            while (i < n) {
                unsigned char ch = (unsigned char)src[i];
                if (ch == 0x07) { i++; break; }
                if (ch == 0x1B && i + 1 < n && (unsigned char)src[i + 1] == '\\') { i += 2; break; }
                i++;
            }
        } else if (next == 'P') {
            /* DCS: ESC P ... ESC \ */
            i++;
            while (i < n) {
                if ((unsigned char)src[i] == 0x1B && i + 1 < n && (unsigned char)src[i + 1] == '\\') { i += 2; break; }
                i++;
            }
        } else {
            /* single-byte escape: skip next char */
            i++;
        }
    }
}

/* ---------- password extraction ---------- */

static regex_t g_password_re;
static bool g_password_re_inited = false;

static void password_re_init(void) {
    if (g_password_re_inited) return;
    if (regcomp(&g_password_re, "[A-Za-z0-9]{32}", REG_EXTENDED) != 0) {
        die("regcomp failed for password pattern");
    }
    g_password_re_inited = true;
}

/* extract_passwords: returns vector of owned strings. caller must free each + the vector */
static char **extract_passwords(const char *text, size_t *out_count) {
    password_re_init();
    sb_t clean;
    strip_terminal_codes(text, &clean);
    const char *p = clean.data ? clean.data : "";
    size_t cap = 8, cnt = 0;
    char **arr = xmalloc(cap * sizeof(char *));
    regmatch_t m;
    while (regexec(&g_password_re, p, 1, &m, 0) == 0) {
        size_t len = (size_t)(m.rm_eo - m.rm_so);
        char *pw = xmalloc(len + 1);
        memcpy(pw, p + m.rm_so, len);
        pw[len] = '\0';
        if (cnt == cap) {
            cap *= 2;
            arr = xrealloc(arr, cap * sizeof(char *));
        }
        arr[cnt++] = pw;
        p += m.rm_eo;
    }
    sb_free(&clean);
    *out_count = cnt;
    return arr;
}

static void free_password_list(char **arr, size_t count) {
    for (size_t i = 0; i < count; i++) free(arr[i]);
    free(arr);
}

static char *extract_password_or_die(const char *text) {
    size_t n = 0;
    char **arr = extract_passwords(text, &n);
    if (n == 0) {
        free(arr);
        die("failed to extract a 32-character password from output:\n%s", text);
    }
    char *last = xstrdup(arr[n - 1]);
    free_password_list(arr, n);
    return last;
}

/* ---------- private key extraction ---------- */

static char *extract_private_key(const char *text) {
    sb_t clean;
    strip_terminal_codes(text, &clean);
    const char *p = clean.data ? clean.data : "";
    const char *begin = strstr(p, "-----BEGIN ");
    if (!begin) { sb_free(&clean); return NULL; }
    const char *end_marker = strstr(begin, "-----END ");
    if (!end_marker) { sb_free(&clean); return NULL; }
    const char *terminator = strstr(end_marker, "PRIVATE KEY-----");
    if (!terminator) { sb_free(&clean); return NULL; }
    const char *stop = terminator + strlen("PRIVATE KEY-----");
    size_t len = (size_t)(stop - begin);
    char *result = xmalloc(len + 1);
    memcpy(result, begin, len);
    result[len] = '\0';
    sb_free(&clean);
    return result;
}

/* ---------- process running ---------- */

typedef struct {
    int exit_code;
    char *output;     /* NUL-terminated, owned */
    size_t output_len;
} proc_result_t;

static int find_in_path(const char *name) {
    const char *path = getenv("PATH");
    if (!path) return -1;
    const char *p = path;
    while (*p) {
        const char *colon = strchr(p, ':');
        size_t segn = colon ? (size_t)(colon - p) : strlen(p);
        if (segn > 0 && segn < PATH_MAX - strlen(name) - 2) {
            char buf[PATH_MAX];
            memcpy(buf, p, segn);
            buf[segn] = '/';
            strcpy(buf + segn + 1, name);
            if (is_executable(buf)) return 0;
        }
        if (!colon) break;
        p = colon + 1;
    }
    return -1;
}

static void check_dependencies(void) {
    const char *deps[] = {"expect", "ssh", "git", "awk", "grep", "mktemp"};
    for (size_t i = 0; i < sizeof(deps) / sizeof(*deps); i++) {
        if (find_in_path(deps[i]) != 0) die("missing required command: %s", deps[i]);
    }
}

/* run_command: name + argv (NULL-terminated, excludes argv[0]), optional env array of "KEY=VAL"
 * (NULL-terminated), optional stdin input, optional cwd. Captures stdout+stderr merged. */
static int run_command(const char *name, char *const argv_extra[],
                       char *const env_extra[], const char *stdin_input,
                       const char *cwd, proc_result_t *result) {
    int stdout_pipe[2];
    int stdin_pipe[2] = {-1, -1};
    if (pipe(stdout_pipe) != 0) die("pipe: %s", strerror(errno));
    if (stdin_input) {
        if (pipe(stdin_pipe) != 0) die("pipe: %s", strerror(errno));
    }

    /* Build argv */
    size_t argc = 0;
    if (argv_extra) {
        while (argv_extra[argc]) argc++;
    }
    char **argv = xmalloc((argc + 2) * sizeof(char *));
    argv[0] = (char *)name;
    for (size_t i = 0; i < argc; i++) argv[i + 1] = argv_extra[i];
    argv[argc + 1] = NULL;

    pid_t pid = fork();
    if (pid < 0) die("fork: %s", strerror(errno));
    if (pid == 0) {
        /* child */
        if (cwd && chdir(cwd) != 0) {
            fprintf(stderr, "chdir %s: %s\n", cwd, strerror(errno));
            _exit(127);
        }
        if (env_extra) {
            for (size_t i = 0; env_extra[i]; i++) {
                char *eq = strchr(env_extra[i], '=');
                if (!eq) continue;
                *eq = '\0';
                setenv(env_extra[i], eq + 1, 1);
                *eq = '=';
            }
        }
        if (stdin_input) {
            dup2(stdin_pipe[0], STDIN_FILENO);
            close(stdin_pipe[0]);
            close(stdin_pipe[1]);
        } else {
            int devnull = open("/dev/null", O_RDONLY);
            if (devnull >= 0) {
                dup2(devnull, STDIN_FILENO);
                close(devnull);
            }
        }
        dup2(stdout_pipe[1], STDOUT_FILENO);
        dup2(stdout_pipe[1], STDERR_FILENO);
        close(stdout_pipe[0]);
        close(stdout_pipe[1]);
        execvp(name, argv);
        fprintf(stderr, "execvp %s: %s\n", name, strerror(errno));
        _exit(127);
    }

    /* parent */
    free(argv);
    close(stdout_pipe[1]);
    if (stdin_input) {
        close(stdin_pipe[0]);
        size_t total = strlen(stdin_input);
        size_t written = 0;
        while (written < total) {
            ssize_t n = write(stdin_pipe[1], stdin_input + written, total - written);
            if (n < 0) {
                if (errno == EINTR) continue;
                if (errno == EPIPE) break;
                break;
            }
            written += (size_t)n;
        }
        close(stdin_pipe[1]);
    }

    sb_t out;
    sb_init(&out);
    char buf[4096];
    for (;;) {
        ssize_t n = read(stdout_pipe[0], buf, sizeof(buf));
        if (n > 0) sb_append(&out, buf, (size_t)n);
        else if (n == 0) break;
        else if (errno == EINTR) continue;
        else break;
    }
    close(stdout_pipe[0]);

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) break;
    }

    result->output_len = out.len;
    result->output = sb_steal(&out);
    result->exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    return 0;
}

static void proc_result_free(proc_result_t *r) {
    free(r->output);
    r->output = NULL;
    r->output_len = 0;
}

static char *run_expect_or_die(const char *script, char *const env_extra[]) {
    proc_result_t res;
    run_command("expect", NULL, env_extra, script, NULL, &res);
    if (res.exit_code != 0) {
        char *msg = xstrdup(res.output ? res.output : "expect failed");
        proc_result_free(&res);
        die("%s", msg);
    }
    return res.output;
}

/* ---------- password storage ---------- */

static void ensure_state(void) {
    if (mkpath(g_key_dir, 0700) != 0) die("mkdir %s: %s", g_key_dir, strerror(errno));
    chmod(g_key_dir, 0700);
    if (touch_file(g_pass_file, 0600) != 0) die("create %s: %s", g_pass_file, strerror(errno));
}

static void save_password(const char *user, const char *password) {
    ensure_state();
    size_t len = 0;
    char *content = read_file(g_pass_file, &len);
    sb_t out;
    sb_init(&out);
    if (content) {
        char *saveptr = NULL;
        char *line = strtok_r(content, "\n", &saveptr);
        size_t userlen = strlen(user);
        while (line) {
            bool skip = (line[0] == '\0') ||
                        (strncmp(line, user, userlen) == 0 && line[userlen] == ':');
            if (!skip) {
                sb_append_cstr(&out, line);
                sb_append_cstr(&out, "\n");
            }
            line = strtok_r(NULL, "\n", &saveptr);
        }
    }
    free(content);
    sb_append_cstr(&out, user);
    sb_append_cstr(&out, ": ");
    sb_append_cstr(&out, password);
    sb_append_cstr(&out, "\n");
    if (write_file(g_pass_file, out.data ? out.data : "", out.len, 0600) != 0) {
        die("write %s: %s", g_pass_file, strerror(errno));
    }
    sb_free(&out);
}

static char *get_saved_password(const char *user) {
    if (!file_exists(g_pass_file)) return xstrdup("");
    char *content = read_file(g_pass_file, NULL);
    if (!content) return xstrdup("");
    char *result = xstrdup("");
    char *prefix = xasprintf("%s: ", user);
    size_t prefix_len = strlen(prefix);
    char *saveptr = NULL;
    char *line = strtok_r(content, "\n", &saveptr);
    while (line) {
        if (strncmp(line, prefix, prefix_len) == 0) {
            free(result);
            result = xstrdup(line + prefix_len);
        }
        line = strtok_r(NULL, "\n", &saveptr);
    }
    free(prefix);
    free(content);
    return result;
}

static void record_password(int level, const char *password) {
    char *user = xasprintf("bandit%d", level);
    if (level != 0) {
        if (strlen(password) != 32) die("refusing to save invalid password for %s: %s", user, password);
        for (const char *p = password; *p; p++) {
            if (!((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9'))) {
                die("refusing to save invalid password for %s: %s", user, password);
            }
        }
    }
    save_password(user, password);
    printf("[+] %-8s %s\n", user, password);
    free(user);
}

/* ---------- expect scripts ---------- */

static const char *script_password_ssh =
    "set timeout 180\n"
    "spawn -noecho ssh \\\n"
    "  -o StrictHostKeyChecking=no \\\n"
    "  -o UserKnownHostsFile=/dev/null \\\n"
    "  -o LogLevel=ERROR \\\n"
    "  -o PubkeyAuthentication=no \\\n"
    "  -o PreferredAuthentications=password \\\n"
    "  -o NumberOfPasswordPrompts=1 \\\n"
    "  -p $env(BANDIT_PORT_VALUE) \\\n"
    "  $env(BANDIT_USER_VALUE)@$env(BANDIT_HOST_VALUE) \\\n"
    "  $env(BANDIT_COMMAND_VALUE)\n"
    "expect {\n"
    "  \"*password:\" {\n"
    "    send -- \"$env(BANDIT_PASSWORD_VALUE)\\r\"\n"
    "    exp_continue\n"
    "  }\n"
    "  timeout {\n"
    "    exit 124\n"
    "  }\n"
    "  eof {\n"
    "  }\n"
    "}\n"
    "catch wait result\n"
    "exit [lindex $result 3]\n";

static const char *script_bandit26 =
    "set timeout 90\n"
    "set stty_init \"rows 5 columns 80\"\n"
    "spawn -noecho ssh \\\n"
    "  -tt \\\n"
    "  -o StrictHostKeyChecking=no \\\n"
    "  -o UserKnownHostsFile=/dev/null \\\n"
    "  -o LogLevel=ERROR \\\n"
    "  -o IdentitiesOnly=yes \\\n"
    "  -i $env(BANDIT_KEY_VALUE) \\\n"
    "  -p $env(BANDIT_PORT_VALUE) \\\n"
    "  bandit26@$env(BANDIT_HOST_VALUE)\n"
    "expect {\n"
    "  -re \"--More--\" {\n"
    "    send -- \"v\"\n"
    "  }\n"
    "  timeout {\n"
    "    exit 124\n"
    "  }\n"
    "  eof {\n"
    "    exit 1\n"
    "  }\n"
    "}\n"
    "expect {\n"
    "  -re \"~\" {\n"
    "  }\n"
    "  timeout {\n"
    "    exit 124\n"
    "  }\n"
    "  eof {\n"
    "    exit 1\n"
    "  }\n"
    "}\n"
    "after 500\n"
    "send -- \"\\033:set shell=/bin/bash\\r\"\n"
    "after 500\n"
    "send -- \":shell\\r\"\n"
    "after 500\n"
    "send -- \"cat /etc/bandit_pass/bandit26; ./bandit27-do cat /etc/bandit_pass/bandit27; exit\\r\"\n"
    "set password_count 0\n"
    "expect {\n"
    "  -re {[[:alnum:]]{32}} {\n"
    "    incr password_count\n"
    "    if {$password_count < 2} {\n"
    "      exp_continue\n"
    "    }\n"
    "  }\n"
    "  timeout {\n"
    "    exit 124\n"
    "  }\n"
    "  eof {\n"
    "    exit 1\n"
    "  }\n"
    "}\n"
    "close\n"
    "wait\n"
    "exit 0\n";

static const char *script_uppercase =
    "set timeout 60\n"
    "spawn -noecho ssh \\\n"
    "  -tt \\\n"
    "  -o StrictHostKeyChecking=no \\\n"
    "  -o UserKnownHostsFile=/dev/null \\\n"
    "  -o LogLevel=ERROR \\\n"
    "  -o PubkeyAuthentication=no \\\n"
    "  -o PreferredAuthentications=password \\\n"
    "  -o NumberOfPasswordPrompts=1 \\\n"
    "  -p $env(BANDIT_PORT_VALUE) \\\n"
    "  bandit32@$env(BANDIT_HOST_VALUE)\n"
    "expect {\n"
    "  \"*password:\" {\n"
    "    send -- \"$env(BANDIT_PASSWORD_VALUE)\\r\"\n"
    "    exp_continue\n"
    "  }\n"
    "  -re \"WELCOME TO THE UPPERCASE SHELL|>>\" {\n"
    "  }\n"
    "  timeout {\n"
    "    exit 124\n"
    "  }\n"
    "}\n"
    "after 500\n"
    "send -- \"\\$0\\r\"\n"
    "expect {\n"
    "  -re {[$#] } {\n"
    "  }\n"
    "  timeout {\n"
    "    exit 124\n"
    "  }\n"
    "}\n"
    "send -- \"cat /etc/bandit_pass/bandit33; exit\\r\"\n"
    "expect {\n"
    "  -re {[[:alnum:]]{32}} {\n"
    "  }\n"
    "  timeout {\n"
    "    exit 124\n"
    "  }\n"
    "}\n"
    "close\n"
    "wait\n"
    "exit 0\n";

static const char *script_interactive_ssh =
    "set timeout 30\n"
    "spawn ssh \\\n"
    "  -o StrictHostKeyChecking=no \\\n"
    "  -o UserKnownHostsFile=/dev/null \\\n"
    "  -o LogLevel=ERROR \\\n"
    "  -o PubkeyAuthentication=no \\\n"
    "  -o PreferredAuthentications=password \\\n"
    "  -p $env(BANDIT_PORT_VALUE) \\\n"
    "  $env(BANDIT_USER_VALUE)@$env(BANDIT_HOST_VALUE)\n"
    "expect {\n"
    "  \"*password:\" {\n"
    "    send -- \"$env(BANDIT_PASSWORD_VALUE)\\r\"\n"
    "    interact\n"
    "  }\n"
    "  timeout {\n"
    "    interact\n"
    "  }\n"
    "  eof {\n"
    "  }\n"
    "}\n";

/* ---------- SSH and key commands ---------- */

static char *run_password_ssh_command(const char *user, const char *password, const char *command_text) {
    char *env[] = {
        xasprintf("BANDIT_HOST_VALUE=%s", g_host),
        xasprintf("BANDIT_PORT_VALUE=%s", g_port),
        xasprintf("BANDIT_USER_VALUE=%s", user),
        xasprintf("BANDIT_PASSWORD_VALUE=%s", password),
        xasprintf("BANDIT_COMMAND_VALUE=%s", command_text),
        NULL
    };
    proc_result_t res;
    run_command("expect", NULL, env, script_password_ssh, NULL, &res);
    for (size_t i = 0; env[i]; i++) free(env[i]);
    if (res.exit_code != 0) {
        char *msg = xasprintf("SSH command failed for %s: %s\n%s", user, command_text,
                              res.output ? res.output : "");
        proc_result_free(&res);
        die("%s", msg);
    }
    return res.output;
}

static char *run_key_ssh_command(const char *user, const char *key_file, const char *command_text) {
    char *target = xasprintf("%s@%s", user, g_host);
    char *args[] = {
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes",
        "-i", (char *)key_file,
        "-p", g_port,
        target,
        (char *)command_text,
        NULL
    };
    proc_result_t res;
    run_command("ssh", args, NULL, NULL, NULL, &res);
    free(target);
    if (res.exit_code != 0) {
        char *msg = xstrdup(res.output ? res.output : "ssh failed");
        proc_result_free(&res);
        die("%s", msg);
    }
    return res.output;
}

static char *solve_password(const char *user, const char *password, const char *command_text) {
    char *out = run_password_ssh_command(user, password, command_text);
    char *pw = extract_password_or_die(out);
    free(out);
    return pw;
}

static char *solve_path(const char *user, const char *password, const char *command_text) {
    char *raw = run_password_ssh_command(user, password, command_text);
    sb_t clean;
    strip_terminal_codes(raw, &clean);
    free(raw);
    char *match = NULL;
    char *saveptr = NULL;
    char *line = strtok_r(clean.data ? clean.data : "", "\n", &saveptr);
    while (line) {
        if (strstr(line, "/inhere/")) {
            free(match);
            match = xstrdup(line);
        }
        line = strtok_r(NULL, "\n", &saveptr);
    }
    if (!match) {
        char *err = xstrdup(clean.data ? clean.data : "");
        sb_free(&clean);
        die("failed to extract path from output:\n%s", err);
    }
    sb_free(&clean);
    return match;
}

static char *save_private_key(const char *name, const char *output) {
    char *key = extract_private_key(output);
    if (!key) die("failed to extract private key %s from output:\n%s", name, output);
    ensure_state();
    char *path = xasprintf("%s/%s", g_key_dir, name);
    size_t klen = strlen(key);
    char *blob = xmalloc(klen + 2);
    memcpy(blob, key, klen);
    blob[klen] = '\n';
    blob[klen + 1] = '\0';
    if (write_file(path, blob, klen + 1, 0600) != 0) die("write %s: %s", path, strerror(errno));
    free(blob);
    free(key);
    return path;
}

static void solve_bandit26_pair(const char *key_file, char **pw1, char **pw2) {
    char *env[] = {
        xasprintf("BANDIT_HOST_VALUE=%s", g_host),
        xasprintf("BANDIT_PORT_VALUE=%s", g_port),
        xasprintf("BANDIT_KEY_VALUE=%s", key_file),
        NULL
    };
    char *output = run_expect_or_die(script_bandit26, env);
    for (size_t i = 0; env[i]; i++) free(env[i]);
    size_t n = 0;
    char **passwords = extract_passwords(output, &n);
    if (n < 2) {
        char *msg = xasprintf("expected two passwords from bandit26 output:\n%s", output);
        free(output);
        free_password_list(passwords, n);
        die("%s", msg);
    }
    *pw1 = xstrdup(passwords[n - 2]);
    *pw2 = xstrdup(passwords[n - 1]);
    free_password_list(passwords, n);
    free(output);
}

static char *solve_uppercase_shell(const char *password) {
    char *env[] = {
        xasprintf("BANDIT_HOST_VALUE=%s", g_host),
        xasprintf("BANDIT_PORT_VALUE=%s", g_port),
        xasprintf("BANDIT_PASSWORD_VALUE=%s", password),
        NULL
    };
    char *output = run_expect_or_die(script_uppercase, env);
    for (size_t i = 0; env[i]; i++) free(env[i]);
    char *pw = extract_password_or_die(output);
    free(output);
    return pw;
}

/* ---------- git ---------- */

static char *write_askpass(const char *dir) {
    char *path = xasprintf("%s/askpass.sh", dir);
    const char *content = "#!/usr/bin/env bash\nprintf '%s\\n' \"$BANDIT_GIT_PASSWORD\"\n";
    if (write_file(path, content, strlen(content), 0700) != 0) die("write %s: %s", path, strerror(errno));
    return path;
}

static char **git_env(const char *password, const char *askpass) {
    const char *ssh_cmd = "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                          "-o LogLevel=ERROR -o PubkeyAuthentication=no "
                          "-o PreferredAuthentications=password -o NumberOfPasswordPrompts=1";
    const char *display = env_or("DISPLAY", ":0");
    char **env = xmalloc(6 * sizeof(char *));
    env[0] = xasprintf("BANDIT_GIT_PASSWORD=%s", password);
    env[1] = xasprintf("GIT_SSH_COMMAND=%s", ssh_cmd);
    env[2] = xasprintf("SSH_ASKPASS=%s", askpass);
    env[3] = xstrdup("SSH_ASKPASS_REQUIRE=force");
    env[4] = xasprintf("DISPLAY=%s", display);
    env[5] = NULL;
    return env;
}

static void free_env(char **env) {
    for (size_t i = 0; env[i]; i++) free(env[i]);
    free(env);
}

static char *mkdtemp_or_die(const char *prefix) {
    char *tmpl = xasprintf("/tmp/%sXXXXXX", prefix);
    if (!mkdtemp(tmpl)) die("mkdtemp: %s", strerror(errno));
    return tmpl;
}

static void git_clone_repo(const char *user, const char *password, const char *remote_path, const char *destination) {
    char *tmp = mkdtemp_or_die("bandit-git-askpass.");
    char *askpass = write_askpass(tmp);
    char *remote = xasprintf("ssh://%s@%s:%s%s", user, g_host, g_port, remote_path);
    char **env = git_env(password, askpass);
    char *args[] = {"clone", remote, (char *)destination, NULL};
    proc_result_t res;
    run_command("git", args, env, NULL, NULL, &res);
    int code = res.exit_code;
    char *out_copy = xstrdup(res.output ? res.output : "");
    proc_result_free(&res);
    free_env(env);
    free(remote);
    free(askpass);
    remove_recursive(tmp);
    free(tmp);
    if (code != 0) {
        char *msg = xstrdup(out_copy);
        free(out_copy);
        die("git clone failed: %s", msg);
    }
    free(out_copy);
}

static char *git_push_with_password(const char *password, const char *repo) {
    char *tmp = mkdtemp_or_die("bandit-git-askpass.");
    char *askpass = write_askpass(tmp);
    char **env = git_env(password, askpass);
    char *args[] = {"-C", (char *)repo, "push", "origin", "master", NULL};
    proc_result_t res;
    run_command("git", args, env, NULL, NULL, &res);
    char *out = res.output ? res.output : xstrdup("");
    res.output = NULL;
    proc_result_free(&res);
    free_env(env);
    free(askpass);
    remove_recursive(tmp);
    free(tmp);
    return out;
}

/* ---------- template rendering ---------- */

typedef struct {
    char *password;
    int level;
    int to_level;
    int random_port;
    char *temp_output;
    char *path; /* optional */
} ctx_t;

static ctx_t *ctx_new(int level, const char *password, int to_level) {
    ctx_t *c = xmalloc(sizeof(*c));
    c->password = xstrdup(password);
    c->level = level;
    c->to_level = to_level;
    c->random_port = 20000 + (rand() % 10000);
    c->temp_output = xasprintf("/tmp/bandit%dpass.%d.%d", to_level, (int)getpid(), 1000 + (rand() % 9000));
    c->path = NULL;
    return c;
}

static void ctx_free(ctx_t *c) {
    if (!c) return;
    free(c->password);
    free(c->temp_output);
    free(c->path);
    free(c);
}

static void replace_all(sb_t *out, const char *src, const char *needle, const char *replacement) {
    size_t needle_len = strlen(needle);
    size_t replace_len = strlen(replacement);
    const char *p = src;
    while (*p) {
        const char *hit = strstr(p, needle);
        if (!hit) {
            sb_append_cstr(out, p);
            return;
        }
        sb_append(out, p, (size_t)(hit - p));
        sb_append(out, replacement, replace_len);
        p = hit + needle_len;
    }
    (void)replace_len;
}

static char *render_template(const char *template_str, const ctx_t *ctx) {
    sb_t a, b;
    sb_init(&a);
    sb_init(&b);

    char *level_s = xasprintf("%d", ctx->level);
    char *to_s = xasprintf("%d", ctx->to_level);
    char *port_s = xasprintf("%d", ctx->random_port);

    replace_all(&a, template_str, "{password}", ctx->password);

    sb_t c;
    sb_init(&c);
    replace_all(&c, a.data ? a.data : "", "{level}", level_s);
    sb_free(&a);

    sb_init(&b);
    replace_all(&b, c.data ? c.data : "", "{to}", to_s);
    sb_free(&c);

    sb_init(&a);
    replace_all(&a, b.data ? b.data : "", "{random_port}", port_s);
    sb_free(&b);

    sb_init(&b);
    replace_all(&b, a.data ? a.data : "", "{temp_output}", ctx->temp_output);
    sb_free(&a);

    if (ctx->path) {
        sb_init(&c);
        replace_all(&c, b.data ? b.data : "", "{path}", ctx->path);
        sb_free(&b);
        free(level_s); free(to_s); free(port_s);
        return sb_steal(&c);
    }
    free(level_s); free(to_s); free(port_s);
    return sb_steal(&b);
}

/* ---------- TOML helpers ---------- */

static char *toml_string_dup(toml_table_t *t, const char *key) {
    toml_datum_t d = toml_string_in(t, key);
    if (!d.ok) return NULL;
    char *s = xstrdup(d.u.s);
    free(d.u.s);
    return s;
}

static bool toml_int_get(toml_table_t *t, const char *key, int64_t *out) {
    toml_datum_t d = toml_int_in(t, key);
    if (!d.ok) return false;
    *out = d.u.i;
    return true;
}

/* ---------- step solving ---------- */

typedef struct {
    int *items;
    size_t count;
} int_list_t;

static int_list_t step_to_list(toml_table_t *step) {
    int_list_t list = {0};
    int64_t single = 0;
    if (toml_int_get(step, "to", &single)) {
        list.items = xmalloc(sizeof(int));
        list.items[0] = (int)single;
        list.count = 1;
        return list;
    }
    toml_array_t *arr = toml_array_in(step, "to");
    if (!arr) die("step missing 'to' field");
    int n = toml_array_nelem(arr);
    list.items = xmalloc((size_t)n * sizeof(int));
    list.count = (size_t)n;
    for (int i = 0; i < n; i++) {
        toml_datum_t d = toml_int_at(arr, i);
        if (!d.ok) die("step 'to' array contains non-int");
        list.items[i] = (int)d.u.i;
    }
    return list;
}

static int step_to_single(toml_table_t *step) {
    int_list_t list = step_to_list(step);
    if (list.count != 1) {
        free(list.items);
        die("expected single 'to' target");
    }
    int v = list.items[0];
    free(list.items);
    return v;
}

static char *step_must_string(toml_table_t *step, const char *key) {
    char *v = toml_string_dup(step, key);
    if (!v) die("step missing string field %s", key);
    return v;
}

static int step_must_int(toml_table_t *step, const char *key) {
    int64_t v = 0;
    if (!toml_int_get(step, key, &v)) die("step missing int field %s", key);
    return (int)v;
}

static char *step_user(toml_table_t *step, int from_level) {
    char *u = toml_string_dup(step, "user");
    if (u) return u;
    return xasprintf("bandit%d", from_level);
}

/* passwords map: simple array indexed by level (0..33) */
static char *g_passwords[64];

static void set_password(int level, const char *password) {
    if (level < 0 || level >= 64) die("invalid level: %d", level);
    free(g_passwords[level]);
    g_passwords[level] = xstrdup(password);
}

static const char *get_password_or_die(int level) {
    if (level < 0 || level >= 64 || !g_passwords[level]) die("missing password for bandit%d", level);
    return g_passwords[level];
}

static void solve_step(toml_table_t *step) {
    char *type = step_must_string(step, "type");
    int from_level = step_must_int(step, "from");
    char *from_user = step_user(step, from_level);
    const char *from_password = get_password_or_die(from_level);

    if (strcmp(type, "ssh_command") == 0) {
        int to_level = step_to_single(step);
        ctx_t *c = ctx_new(from_level, from_password, to_level);
        char *cmd_raw = step_must_string(step, "command");
        char *cmd = render_template(cmd_raw, c);
        char *pw = solve_password(from_user, from_password, cmd);
        set_password(to_level, pw);
        record_password(to_level, pw);
        free(pw); free(cmd); free(cmd_raw);
        ctx_free(c);
    } else if (strcmp(type, "path_then_command") == 0) {
        int to_level = step_to_single(step);
        ctx_t *c = ctx_new(from_level, from_password, to_level);
        char *find_raw = step_must_string(step, "find_command");
        char *find_cmd = render_template(find_raw, c);
        char *path = solve_path(from_user, from_password, find_cmd);
        c->path = xstrdup(path);
        char *cmd_raw = step_must_string(step, "command");
        char *cmd = render_template(cmd_raw, c);
        char *pw = solve_password(from_user, from_password, cmd);
        set_password(to_level, pw);
        record_password(to_level, pw);
        free(pw); free(cmd); free(cmd_raw); free(path); free(find_cmd); free(find_raw);
        ctx_free(c);
    } else if (strcmp(type, "private_key_then_ssh") == 0) {
        int to_level = step_to_single(step);
        ctx_t *c = ctx_new(from_level, from_password, to_level);
        char *key_cmd_raw = step_must_string(step, "key_command");
        char *key_cmd = render_template(key_cmd_raw, c);
        char *out = run_password_ssh_command(from_user, from_password, key_cmd);
        char *key_name = step_must_string(step, "key_name");
        char *key_file = save_private_key(key_name, out);
        char *next_cmd_raw = step_must_string(step, "next_command");
        char *next_cmd = render_template(next_cmd_raw, c);
        char *next_user = step_must_string(step, "next_user");
        char *key_out = run_key_ssh_command(next_user, key_file, next_cmd);
        char *pw = extract_password_or_die(key_out);
        set_password(to_level, pw);
        record_password(to_level, pw);
        free(pw); free(key_out); free(next_user); free(next_cmd); free(next_cmd_raw);
        free(key_file); free(key_name); free(out); free(key_cmd); free(key_cmd_raw);
        ctx_free(c);
    } else if (strcmp(type, "bandit26_escape") == 0) {
        int_list_t targets = step_to_list(step);
        ctx_t *c = ctx_new(from_level, from_password, targets.items[targets.count - 1]);
        char *key_cmd_raw = step_must_string(step, "key_command");
        char *key_cmd = render_template(key_cmd_raw, c);
        char *out = run_password_ssh_command(from_user, from_password, key_cmd);
        char *key_name = step_must_string(step, "key_name");
        char *key_file = save_private_key(key_name, out);
        char *pw1 = NULL;
        char *pw2 = NULL;
        solve_bandit26_pair(key_file, &pw1, &pw2);
        if (targets.count != 2) {
            die("bandit26_escape expected 2 targets, got %zu", targets.count);
        }
        set_password(targets.items[0], pw1);
        record_password(targets.items[0], pw1);
        set_password(targets.items[1], pw2);
        record_password(targets.items[1], pw2);
        free(pw1); free(pw2); free(key_file); free(key_name); free(out);
        free(key_cmd); free(key_cmd_raw);
        free(targets.items);
        ctx_free(c);
    } else if (strcmp(type, "git_read_file") == 0) {
        int to_level = step_to_single(step);
        char *tmp = mkdtemp_or_die("bandit-repo.");
        char *repo = xasprintf("%s/repo", tmp);
        char *git_user = step_must_string(step, "git_user");
        char *remote_path = step_must_string(step, "repo");
        git_clone_repo(git_user, from_password, remote_path, repo);
        char *file = step_must_string(step, "file");
        char *file_path = xasprintf("%s/%s", repo, file);
        char *content = read_file(file_path, NULL);
        if (!content) die("failed to read %s", file_path);
        char *pw = extract_password_or_die(content);
        set_password(to_level, pw);
        record_password(to_level, pw);
        free(pw); free(content); free(file_path); free(file); free(remote_path); free(git_user);
        remove_recursive(tmp);
        free(repo); free(tmp);
    } else if (strcmp(type, "git_show") == 0) {
        int to_level = step_to_single(step);
        char *tmp = mkdtemp_or_die("bandit-repo.");
        char *repo = xasprintf("%s/repo", tmp);
        char *git_user = step_must_string(step, "git_user");
        char *remote_path = step_must_string(step, "repo");
        git_clone_repo(git_user, from_password, remote_path, repo);
        char *object = step_must_string(step, "object");
        char *args[] = {"-C", repo, "show", object, NULL};
        proc_result_t res;
        run_command("git", args, NULL, NULL, NULL, &res);
        if (res.exit_code != 0) {
            char *msg = xstrdup(res.output ? res.output : "git show failed");
            proc_result_free(&res);
            die("%s", msg);
        }
        char *pw = extract_password_or_die(res.output);
        set_password(to_level, pw);
        record_password(to_level, pw);
        free(pw);
        proc_result_free(&res);
        free(object); free(remote_path); free(git_user);
        remove_recursive(tmp);
        free(repo); free(tmp);
    } else if (strcmp(type, "git_push_file") == 0) {
        int to_level = step_to_single(step);
        char *tmp = mkdtemp_or_die("bandit-repo.");
        char *repo = xasprintf("%s/repo", tmp);
        char *git_user = step_must_string(step, "git_user");
        char *remote_path = step_must_string(step, "repo");
        git_clone_repo(git_user, from_password, remote_path, repo);

        char *file = step_must_string(step, "file");
        char *content = step_must_string(step, "content");
        char *commit_message = step_must_string(step, "commit_message");

        proc_result_t res;
        char *args1[] = {"-C", repo, "config", "user.email", "bandit-solver@example.invalid", NULL};
        run_command("git", args1, NULL, NULL, NULL, &res);
        if (res.exit_code != 0) die("git config: %s", res.output ? res.output : "");
        proc_result_free(&res);

        char *args2[] = {"-C", repo, "config", "user.name", "bandit-solver", NULL};
        run_command("git", args2, NULL, NULL, NULL, &res);
        if (res.exit_code != 0) die("git config: %s", res.output ? res.output : "");
        proc_result_free(&res);

        char *file_path = xasprintf("%s/%s", repo, file);
        if (write_file(file_path, content, strlen(content), 0644) != 0) die("write %s: %s", file_path, strerror(errno));
        free(file_path);

        char *args3[] = {"-C", repo, "add", "-f", file, NULL};
        run_command("git", args3, NULL, NULL, NULL, &res);
        if (res.exit_code != 0) die("git add: %s", res.output ? res.output : "");
        proc_result_free(&res);

        char *args4[] = {"-C", repo, "commit", "-m", commit_message, NULL};
        run_command("git", args4, NULL, NULL, NULL, &res);
        if (res.exit_code != 0) die("git commit: %s", res.output ? res.output : "");
        proc_result_free(&res);

        char *push_out = git_push_with_password(from_password, repo);
        char *pw = extract_password_or_die(push_out);
        set_password(to_level, pw);
        record_password(to_level, pw);
        free(pw); free(push_out);
        free(commit_message); free(content); free(file);
        free(remote_path); free(git_user);
        remove_recursive(tmp);
        free(repo); free(tmp);
    } else if (strcmp(type, "uppercase_shell") == 0) {
        int to_level = step_to_single(step);
        char *pw = solve_uppercase_shell(from_password);
        set_password(to_level, pw);
        record_password(to_level, pw);
        free(pw);
    } else {
        die("unsupported step type: %s", type);
    }

    free(type);
    free(from_user);
}

/* ---------- config ---------- */

typedef struct {
    toml_table_t *root;
    int bootstrap_level;
    char *bootstrap_password;
    toml_array_t *steps;
} config_t;

static const char *supported_types[] = {
    "ssh_command", "path_then_command", "private_key_then_ssh", "bandit26_escape",
    "git_read_file", "git_show", "git_push_file", "uppercase_shell", NULL
};

static const struct {
    const char *type;
    const char *fields[8];
} required_fields[] = {
    {"ssh_command", {"from", "to", "command", NULL}},
    {"path_then_command", {"from", "to", "find_command", "command", NULL}},
    {"private_key_then_ssh", {"from", "to", "key_command", "key_name", "next_user", "next_command", NULL}},
    {"bandit26_escape", {"from", "to", "key_command", "key_name", NULL}},
    {"git_read_file", {"from", "to", "git_user", "repo", "file", NULL}},
    {"git_show", {"from", "to", "git_user", "repo", "object", NULL}},
    {"git_push_file", {"from", "to", "git_user", "repo", "file", "content", "commit_message", NULL}},
    {"uppercase_shell", {"from", "to", NULL}},
};

static void validate_steps(toml_array_t *steps) {
    int n = toml_array_nelem(steps);
    if (n <= 0) die("config has no steps");
    for (int i = 0; i < n; i++) {
        toml_table_t *step = toml_table_at(steps, i);
        if (!step) die("step %d is not a table", i + 1);
        toml_datum_t t = toml_string_in(step, "type");
        if (!t.ok) die("step %d is missing type", i + 1);
        bool found = false;
        for (size_t k = 0; supported_types[k]; k++) {
            if (strcmp(t.u.s, supported_types[k]) == 0) { found = true; break; }
        }
        if (!found) {
            char *bad = xstrdup(t.u.s);
            free(t.u.s);
            die("step %d has unsupported type \"%s\"", i + 1, bad);
        }
        for (size_t k = 0; k < sizeof(required_fields) / sizeof(*required_fields); k++) {
            if (strcmp(required_fields[k].type, t.u.s) == 0) {
                for (size_t f = 0; required_fields[k].fields[f]; f++) {
                    if (!toml_key_exists(step, required_fields[k].fields[f])) {
                        char *typ = xstrdup(t.u.s);
                        const char *field = required_fields[k].fields[f];
                        free(t.u.s);
                        die("step %d (%s) is missing %s", i + 1, typ, field);
                    }
                }
                break;
            }
        }
        free(t.u.s);
    }
}

static config_t load_config(void) {
    FILE *fp = fopen(g_config_path, "r");
    if (!fp) die("read config: %s: %s", g_config_path, strerror(errno));
    char errbuf[256];
    toml_table_t *root = toml_parse_file(fp, errbuf, sizeof(errbuf));
    fclose(fp);
    if (!root) die("parse config: %s", errbuf);

    config_t cfg = {0};
    cfg.root = root;

    toml_table_t *conn = toml_table_in(root, "connection");
    char *cfg_host = conn ? toml_string_dup(conn, "host") : NULL;
    int64_t cfg_port = 0;
    if (conn) toml_int_get(conn, "port", &cfg_port);

    const char *env_host = getenv("BANDIT_HOST");
    g_host = xstrdup((env_host && *env_host) ? env_host : (cfg_host && *cfg_host ? cfg_host : DEFAULT_HOST));
    const char *env_port = getenv("BANDIT_PORT");
    if (env_port && *env_port) g_port = xstrdup(env_port);
    else if (cfg_port > 0) g_port = xasprintf("%lld", (long long)cfg_port);
    else g_port = xstrdup(DEFAULT_PORT);
    free(cfg_host);

    toml_table_t *boot = toml_table_in(root, "bootstrap");
    if (!boot) die("config is missing [bootstrap]");
    int64_t blevel = 0;
    if (!toml_int_get(boot, "level", &blevel)) die("config bootstrap level is missing");
    cfg.bootstrap_level = (int)blevel;
    cfg.bootstrap_password = toml_string_dup(boot, "password");
    if (!cfg.bootstrap_password || !*cfg.bootstrap_password) die("config bootstrap password is empty");

    cfg.steps = toml_array_in(root, "steps");
    if (!cfg.steps) die("config has no steps");
    validate_steps(cfg.steps);
    return cfg;
}

static void config_free(config_t *cfg) {
    free(cfg->bootstrap_password);
    if (cfg->root) toml_free(cfg->root);
    cfg->root = NULL;
    cfg->bootstrap_password = NULL;
    cfg->steps = NULL;
}

/* ---------- top-level actions ---------- */

static void refresh(config_t *cfg) {
    check_dependencies();
    ensure_state();

    printf("Refreshing Bandit passwords via %s:%s\n", g_host, g_port);
    printf("Level config:  %s\n", g_config_path);
    printf("Password file: %s\n", g_pass_file);
    printf("Key cache:     %s\n\n", g_key_dir);

    set_password(cfg->bootstrap_level, cfg->bootstrap_password);
    record_password(cfg->bootstrap_level, cfg->bootstrap_password);

    int n = toml_array_nelem(cfg->steps);
    for (int i = 0; i < n; i++) {
        solve_step(toml_table_at(cfg->steps, i));
    }

    printf("\nRefresh complete.\n");
}

static void show_passwords(void) {
    ensure_state();
    size_t len = 0;
    char *content = read_file(g_pass_file, &len);
    if (!content || len == 0) {
        printf("No passwords saved yet.\n");
    } else {
        fwrite(content, 1, len, stdout);
    }
    free(content);
}

static void ssh_level(int level) {
    ensure_state();
    char *user = xasprintf("bandit%d", level);
    char *password = get_saved_password(user);
    if (!password || !*password) {
        free(password);
        char *target = xasprintf("%s@%s", user, g_host);
        char *args[] = {"ssh", target, "-p", g_port, NULL};
        execvp("ssh", args);
        die("execvp ssh: %s", strerror(errno));
    }
    char *env[] = {
        xasprintf("BANDIT_HOST_VALUE=%s", g_host),
        xasprintf("BANDIT_PORT_VALUE=%s", g_port),
        xasprintf("BANDIT_USER_VALUE=%s", user),
        xasprintf("BANDIT_PASSWORD_VALUE=%s", password),
        NULL
    };
    for (size_t i = 0; env[i]; i++) {
        char *eq = strchr(env[i], '=');
        if (!eq) continue;
        *eq = '\0';
        setenv(env[i], eq + 1, 1);
        *eq = '=';
    }

    /* write script to a temp file so expect can use TTY-driven interact */
    char tmpl[] = "/tmp/bandit-ssh.XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) die("mkstemp: %s", strerror(errno));
    size_t script_len = strlen(script_interactive_ssh);
    if (write(fd, script_interactive_ssh, script_len) != (ssize_t)script_len) die("write script: %s", strerror(errno));
    close(fd);

    pid_t pid = fork();
    if (pid < 0) die("fork: %s", strerror(errno));
    if (pid == 0) {
        execlp("expect", "expect", "-f", tmpl, (char *)NULL);
        _exit(127);
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR);
    unlink(tmpl);
    for (size_t i = 0; env[i]; i++) free(env[i]);
    free(password);
    free(user);
}

static char *read_line_stdin(void) {
    char *line = NULL;
    size_t cap = 0;
    ssize_t n = getline(&line, &cap, stdin);
    if (n < 0) {
        free(line);
        return NULL;
    }
    while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) {
        line[--n] = '\0';
    }
    return line;
}

static void save_password_interactive(void) {
    printf("Save password for which user? Example: bandit6: ");
    fflush(stdout);
    char *user = read_line_stdin();
    if (!user) return;
    printf("Password: ");
    fflush(stdout);
    char *password = read_line_stdin();
    if (!password) { free(user); return; }
    save_password(user, password);
    printf("Saved password for %s.\n", user);
    free(user);
    free(password);
}

static void menu(config_t *cfg) {
    ensure_state();
    for (;;) {
        printf("====================================\n");
        printf("        OverTheWire Bandit App\n");
        printf("====================================\n\n");
        printf("Password file: %s\n", g_pass_file);
        printf("Key cache:     %s\n\n", g_key_dir);
        printf("1) SSH into a Bandit level\n");
        printf("2) Refresh all passwords\n");
        printf("3) Save/update a password\n");
        printf("4) Show saved passwords\n");
        printf("5) Exit\n\n");
        printf("Choose an option: ");
        fflush(stdout);

        char *choice = read_line_stdin();
        if (!choice) return;
        if (strcmp(choice, "1") == 0) {
            free(choice);
            printf("Bandit level number, e.g. 0, 1, 26, 33: ");
            fflush(stdout);
            char *lvl = read_line_stdin();
            if (!lvl) return;
            ssh_level(atoi(lvl));
            free(lvl);
        } else if (strcmp(choice, "2") == 0) {
            free(choice);
            refresh(cfg);
            printf("Press Enter to continue...");
            fflush(stdout);
            free(read_line_stdin());
        } else if (strcmp(choice, "3") == 0) {
            free(choice);
            save_password_interactive();
        } else if (strcmp(choice, "4") == 0) {
            free(choice);
            show_passwords();
            printf("Press Enter to continue...");
            fflush(stdout);
            free(read_line_stdin());
        } else if (strcmp(choice, "5") == 0) {
            free(choice);
            return;
        } else {
            printf("Invalid option.\n");
            free(choice);
        }
    }
}

/* ---------- main ---------- */

int main(int argc, char **argv) {
    srand((unsigned)(time(NULL) ^ getpid()));

    g_repo_root = find_repo_root();
    char *default_config = xasprintf("%s/levels/bandit-levels.toml", g_repo_root);
    g_config_path = xstrdup(env_or("BANDIT_LEVELS_FILE", default_config));
    free(default_config);
    g_pass_file = xasprintf("%s/bandit-passwords.txt", g_repo_root);
    g_key_dir = xasprintf("%s/.bandit-keys", g_repo_root);

    bool do_refresh = false;
    bool do_show = false;
    int ssh_lvl = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0) {
            if (++i >= argc) die("--config requires a path");
            free(g_config_path);
            g_config_path = xstrdup(argv[i]);
        } else if (strcmp(argv[i], "--refresh") == 0) {
            do_refresh = true;
        } else if (strcmp(argv[i], "--show") == 0) {
            do_show = true;
        } else if (strcmp(argv[i], "--ssh") == 0) {
            if (++i >= argc) die("--ssh requires a level");
            ssh_lvl = atoi(argv[i]);
        } else {
            die("unknown flag: %s", argv[i]);
        }
    }

    config_t cfg = load_config();

    if (do_refresh) refresh(&cfg);
    else if (do_show) show_passwords();
    else if (ssh_lvl >= 0) ssh_level(ssh_lvl);
    else menu(&cfg);

    config_free(&cfg);
    for (size_t i = 0; i < 64; i++) free(g_passwords[i]);
    free(g_host); free(g_port); free(g_config_path); free(g_pass_file); free(g_key_dir); free(g_repo_root);
    return 0;
}
