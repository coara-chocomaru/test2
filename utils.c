#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <limits.h>
#include "tests.h"

/* ----------------------------------------------------------------------
 * テスト環境のセットアップ
 *   - TEST_DIR を作成
 *   - TARGET_DIR (ディレクトリ) を作成
 *   - CACHE_DIR が TARGET_DIR を指すシンボリックリンクになるよう設定
 * ---------------------------------------------------------------------- */
void setup_test_environment(void) {
    struct stat st;
    if (stat(TEST_DIR, &st) == 0) {
        cleanup_test_environment();
    }
    mkdir(TEST_DIR, 0755);
    mkdir(TARGET_DIR, 0755);   /* chown の対象ディレクトリ */

    /* キャッシュディレクトリの親を作成 */
    char parent[PATH_MAX];
    strcpy(parent, CACHE_DIR);
    char *slash = strrchr(parent, '/');
    if (slash) *slash = '\0';
    mkdir(parent, 0755);

    /* シンボリックリンクを張る (TARGET_DIR へ) */
    unlink(CACHE_DIR);
    if (symlink(TARGET_DIR, CACHE_DIR) != 0) {
        perror("symlink");
        exit(1);
    }
    printf("[ENV] %s -> %s\n", CACHE_DIR, TARGET_DIR);
}

/* ----------------------------------------------------------------------
 * 後片付け (TEST_DIR ごと削除)
 * ---------------------------------------------------------------------- */
void cleanup_test_environment(void) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", TEST_DIR);
    system(cmd);
    printf("[ENV] クリーンアップ完了\n");
}

/* ----------------------------------------------------------------------
 * app_process を execve で起動し、終了コードを返す
 * ---------------------------------------------------------------------- */
int run_app_process(const char *path, char *const argv[], char *const envp[]) {
    pid_t pid = fork();
    if (pid == 0) {
        execve(path, argv, envp);
        perror("execve");
        exit(1);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) return WEXITSTATUS(status);
        return -1;
    } else {
        perror("fork");
        return -1;
    }
}

/* ----------------------------------------------------------------------
 * ファイルの所有者 (uid, gid) を取得
 * ---------------------------------------------------------------------- */
int check_file_owner(const char *path, uid_t *uid, gid_t *gid) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if (uid) *uid = st.st_uid;
        if (gid) *gid = st.st_gid;
        return 0;
    }
    return -1;
}

/* ----------------------------------------------------------------------
 * ファイルのモード (パーミッション) を取得
 * ---------------------------------------------------------------------- */
int check_file_mode(const char *path, mode_t *mode) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if (mode) *mode = st.st_mode;
        return 0;
    }
    return -1;
}
