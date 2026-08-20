#ifndef TESTS_H
#define TESTS_H

/* テスト関数プロトタイプ */
void test_symlink_chown(const char *app_path);
void test_env_overflow(const char *app_path);
void test_argv_overflow(const char *app_path);
void test_dl_hijack(const char *app_path);
void test_toctou_race(const char *app_path);

/* ユーティリティ */
void setup_test_environment(void);
void cleanup_test_environment(void);
int run_app_process(const char *path, char *const argv[], char *const envp[]);
int check_file_owner(const char *path, uid_t *uid, gid_t *gid);

#endif