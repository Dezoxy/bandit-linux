#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>

#include "toml.h"

static int failures = 0;

#define CHECK(cond, msg)                                                                                          \
    do {                                                                                                          \
        if (!(cond)) {                                                                                            \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, msg);                                         \
            failures++;                                                                                           \
        }                                                                                                         \
    } while (0)

static char *find_repo_root(void) {
    char buf[PATH_MAX];
    if (!getcwd(buf, sizeof(buf))) return NULL;
    for (;;) {
        char probe[PATH_MAX];
        snprintf(probe, sizeof(probe), "%s/levels/bandit-levels.toml", buf);
        struct stat st;
        if (stat(probe, &st) == 0) return strdup(buf);
        char *slash = strrchr(buf, '/');
        if (!slash || slash == buf) return NULL;
        *slash = '\0';
    }
}

static void test_load_shared_config(void) {
    char *root = find_repo_root();
    CHECK(root != NULL, "find repo root");
    if (!root) return;

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/levels/bandit-levels.toml", root);
    FILE *fp = fopen(path, "r");
    CHECK(fp != NULL, "open config");
    if (!fp) { free(root); return; }

    char errbuf[256];
    toml_table_t *tbl = toml_parse_file(fp, errbuf, sizeof(errbuf));
    fclose(fp);
    CHECK(tbl != NULL, "parse config");
    if (!tbl) { free(root); return; }

    toml_table_t *conn = toml_table_in(tbl, "connection");
    CHECK(conn != NULL, "[connection] table");
    toml_datum_t host = toml_string_in(conn, "host");
    CHECK(host.ok && strcmp(host.u.s, "bandit.labs.overthewire.org") == 0, "host value");
    if (host.ok) free(host.u.s);
    toml_datum_t port = toml_int_in(conn, "port");
    CHECK(port.ok && port.u.i == 2220, "port value");

    toml_table_t *boot = toml_table_in(tbl, "bootstrap");
    CHECK(boot != NULL, "[bootstrap] table");
    toml_datum_t lvl = toml_int_in(boot, "level");
    CHECK(lvl.ok && lvl.u.i == 0, "bootstrap level");
    toml_datum_t pass = toml_string_in(boot, "password");
    CHECK(pass.ok && strcmp(pass.u.s, "bandit0") == 0, "bootstrap password");
    if (pass.ok) free(pass.u.s);

    toml_array_t *steps = toml_array_in(tbl, "steps");
    CHECK(steps != NULL, "[[steps]] array");
    int n = toml_array_nelem(steps);
    CHECK(n == 32, "expected 32 steps");

    toml_table_t *bandit26 = toml_table_at(steps, 25);
    CHECK(bandit26 != NULL, "step 26 table");
    toml_datum_t type = toml_string_in(bandit26, "type");
    CHECK(type.ok && strcmp(type.u.s, "bandit26_escape") == 0, "step 26 type");
    if (type.ok) free(type.u.s);

    toml_array_t *targets = toml_array_in(bandit26, "to");
    CHECK(targets != NULL, "step 26 'to' is an array");
    if (targets) {
        CHECK(toml_array_nelem(targets) == 2, "step 26 has 2 targets");
        toml_datum_t t0 = toml_int_at(targets, 0);
        toml_datum_t t1 = toml_int_at(targets, 1);
        CHECK(t0.ok && t0.u.i == 26, "target[0] == 26");
        CHECK(t1.ok && t1.u.i == 27, "target[1] == 27");
    }

    toml_free(tbl);
    free(root);
}

static void test_password_regex_present(void) {
    /* sanity check that POSIX ERE [A-Za-z0-9]{32} compiles */
    #include <regex.h>
    regex_t re;
    int rc = regcomp(&re, "[A-Za-z0-9]{32}", REG_EXTENDED);
    CHECK(rc == 0, "password regex compiles");
    if (rc == 0) {
        const char *sample = "noise ABCDEFGHIJKLMNOPQRSTUVWXYZ012345 tail";
        regmatch_t m;
        rc = regexec(&re, sample, 1, &m, 0);
        CHECK(rc == 0, "password regex matches sample");
        CHECK(m.rm_eo - m.rm_so == 32, "match length is 32");
        regfree(&re);
    }
}

int main(void) {
    test_load_shared_config();
    test_password_regex_present();
    if (failures > 0) {
        fprintf(stderr, "%d test failure(s)\n", failures);
        return 1;
    }
    printf("All tests passed.\n");
    return 0;
}
