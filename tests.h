#ifndef TESTS_H
#define TESTS_H

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

/* テスト用パス定義 */
#define TEST_DIR        "/data/local/tmp/exploit_test"
#define TARGET_FILE     TEST_DIR "/target"
#define CACHE_DIR       TEST_DIR "/dalvik-cache/arm64"

#define APP_PROCESS_64  "/system/bin/app_process64"
#define APP_PROCESS_32  "/system/bin/app_process32"

/* ユーティリティ関数 */
void setup_test_environment(void);
void cleanup_test_environment(void);
int run_app_process(const char *path, char *const argv[], char *const envp[]);
int check_file_owner(const char *path, uid_t *uid, gid_t *gid);

/* テスト関数 */
void test_symlink_chown(const char *app_path);
void test_env_overflow(const char *app_path);
void test_argv_overflow(const char *app_path);
void test_dl_hijack(const char *app_path);
void test_toctou_race(const char *app_path);

#endif
