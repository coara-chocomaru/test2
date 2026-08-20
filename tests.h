#ifndef TESTS_H
#define TESTS_H

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

/* テスト用ディレクトリ・ファイル */
#define TEST_DIR        "/data/local/tmp/exploit_test"
#define TARGET_FILE     TEST_DIR "/target"          /* 通常ファイル（chown対象） */
#define TARGET_DIR      TEST_DIR "/target_dir"      /* ディレクトリ（chown対象） */
#define CACHE_DIR       TEST_DIR "/dalvik-cache/arm64"

/* app_process のパス */
#define APP_PROCESS_64  "/system/bin/app_process64"
#define APP_PROCESS_32  "/system/bin/app_process32"

/* ----------------------------------------------------------------------
 * ユーティリティ関数
 * ---------------------------------------------------------------------- */
void setup_test_environment(void);
void cleanup_test_environment(void);
int  run_app_process(const char *path, char *const argv[], char *const envp[]);
int  check_file_owner(const char *path, uid_t *uid, gid_t *gid);
int  check_file_mode(const char *path, mode_t *mode);

/* ----------------------------------------------------------------------
 * テスト関数 (1～10)
 * ---------------------------------------------------------------------- */
void test_symlink_chown(const char *app_path);          /* 1 */
void test_env_overflow(const char *app_path);           /* 2 */
void test_argv_overflow(const char *app_path);          /* 3 */
void test_dl_hijack(const char *app_path);              /* 4 */
void test_toctou_race(const char *app_path);            /* 5 */
void test_chmod_setuid(const char *app_path);           /* 6 */
void test_ptrace_toctou(const char *app_path);          /* 7 */
void test_property_overflow(const char *app_path);      /* 8 */
void test_null_byte_injection(const char *app_path);    /* 9 */
void test_path_traversal_chown(const char *app_path);   /* 10 */

#endif
