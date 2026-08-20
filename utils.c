#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include "tests.h"

#define TEST_DIR "/data/local/tmp/exploit_test"
#define TARGET_FILE TEST_DIR "/target"
#define CACHE_DIR TEST_DIR "/dalvik-cache/arm64"

void setup_test_environment(void) {
    struct stat st;
    if (stat(TEST_DIR, &st) == 0) {
        cleanup_test_environment();
    }
    mkdir(TEST_DIR, 0755);
    // ダミーターゲットファイル作成
    int fd = open(TARGET_FILE, O_CREAT | O_WRONLY, 0644);
    if (fd < 0) { perror("open target"); exit(1); }
    close(fd);
    // キャッシュディレクトリの親を作成
    char parent[PATH_MAX];
    strcpy(parent, CACHE_DIR);
    char *slash = strrchr(parent, '/');
    if (slash) *slash = '\0';
    mkdir(parent, 0755);
    // シンボリックリンク作成
    unlink(CACHE_DIR);
    if (symlink(TARGET_FILE, CACHE_DIR) != 0) {
        perror("symlink");
        exit(1);
    }
    printf("[ENV] セットアップ完了: %s -> %s\n", CACHE_DIR, TARGET_FILE);
}

void cleanup_test_environment(void) {
    system("rm -rf " TEST_DIR);
    printf("[ENV] クリーンアップ完了\n");
}

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

int check_file_owner(const char *path, uid_t *uid, gid_t *gid) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if (uid) *uid = st.st_uid;
        if (gid) *gid = st.st_gid;
        return 0;
    }
    return -1;
}