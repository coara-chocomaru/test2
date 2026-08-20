#ifndef TESTS_H
#define TESTS_H

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

#define TEST_DIR        "/data/local/tmp/exploit_test"
#define TARGET_FILE     TEST_DIR "/target"
#define CACHE_DIR       TEST_DIR "/dalvik-cache/arm64"

#define APP_PROCESS_64  "/system/bin/app_process64"
#define APP_PROCESS_32  "/system/bin/app_process32"

/* ユーティリティ */
void setup_test_environment(void);
void cleanup_test_environment(void);
int run_app_process(const char *path, char *const argv[], char *const envp[]);
int check_file_owner(const char *path, uid_t *uid, gid_t *gid);
int check_file_mode(const char *path, mode_t *mode);

/* 基本テスト (1-5) */
void test_symlink_chown(const char *app_path);
void test_env_overflow(const char *app_path);
void test_argv_overflow(const char *app_path);
void test_dl_hijack(const char *app_path);
void test_toctou_race(const char *app_path);

/* 拡張テスト (6-9) */
void test_chmod_setuid(const char *app_path);
void test_ptrace_toctou(const char *app_path);
void test_property_overflow(const char *app_path);
void test_null_byte_injection(const char *app_path);

#endif
