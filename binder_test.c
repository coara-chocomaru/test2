/*
 * binder_race_close.c - close() vs ioctl() 競合テスト (mmap不要)
 * コンパイル: ndk-build または arm-linux-gnueabihf-gcc -static -pthread
 * 実行: adb shell /data/local/tmp/binder_race_close
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

// 提供された binder.h をインクルード（必須）
#include "binder.h"

#define BINDER_DEVICE "/dev/binder"
#define MMAP_SIZE (256 * 1024)

static int binder_fd = -1;
static volatile int running = 1;
static volatile int fd_closed = 0;

// エラーチェック（mmap失敗は許容）
static void check_ioctl(int ret, const char *msg) {
    if (ret < 0 && errno != ENOMEM && errno != EPERM) {
        perror(msg);
        // 競合テストではエラーが出ても続行
    }
}

// ワーカースレッド: トランザクションを連投
void *worker_thread(void *arg) {
    int tid = (int)(intptr_t)arg;
    printf("[%d] worker started\n", tid);

    // ローカルで binder_fd をコピー（closeされてもこのスレッドの fd はクローズされないが、参照は無効化される）
    int local_fd = binder_fd;

    while (running && !fd_closed) {
        // BC_TRANSACTION (handle=0, oneway) を構築
        struct binder_transaction_data tr = {
            .target.handle = 0,
            .code = 0xDEAD,
            .flags = TF_ONE_WAY,
            .data_size = 0,
            .offsets_size = 0,
            .data.ptr.buffer = 0,
            .data.ptr.offsets = 0,
        };

        uint32_t cmd = BC_TRANSACTION;
        uint8_t write_buf[sizeof(cmd) + sizeof(tr)];
        memcpy(write_buf, &cmd, sizeof(cmd));
        memcpy(write_buf + sizeof(cmd), &tr, sizeof(tr));

        struct binder_write_read bwr = {
            .write_size = sizeof(write_buf),
            .write_consumed = 0,
            .write_buffer = (uintptr_t)write_buf,
            .read_size = 0,
            .read_consumed = 0,
            .read_buffer = 0,
        };

        // ioctl 呼び出し (closeと競合させる)
        int ret = ioctl(local_fd, BINDER_WRITE_READ, &bwr);
        if (ret < 0) {
            // エラーは無視（close後に呼ばれるとEBADFなどになる）
        }

        // 負荷をかけるため delay
        usleep(10);
    }

    printf("[%d] worker stopped\n", tid);
    return NULL;
}

int main(int argc, char **argv) {
    int ret;

    printf("=== Binder close() vs ioctl() Race Test ===\n");

    // 1. binder オープン
    binder_fd = open(BINDER_DEVICE, O_RDWR);
    if (binder_fd < 0) {
        perror("open binder");
        return 1;
    }
    printf("binder_fd = %d\n", binder_fd);

    // 2. mmap 試行 (失敗しても構わない)
    void *map = mmap(NULL, MMAP_SIZE, PROT_READ | PROT_WRITE,
                     MAP_SHARED, binder_fd, 0);
    if (map == MAP_FAILED) {
        perror("mmap (ignored)");
        // 失敗しても続行
    } else {
        printf("mmap succeeded at %p\n", map);
    }

    // 3. ワーカースレッドを起動 (4つ)
    pthread_t threads[4];
    for (int i = 0; i < 4; i++) {
        pthread_create(&threads[i], NULL, worker_thread, (void*)(intptr_t)(i+1));
    }

    // 4. 少し待ってから close() を呼び出し、競合を発生させる
    printf("Sleeping 1s before close()...\n");
    sleep(1);

    printf("Calling close(binder_fd) ...\n");
    fd_closed = 1;  // フラグ設定
    close(binder_fd);
    binder_fd = -1;

    // 5. ワーカースレッドの終了を待つ
    running = 0;
    for (int i = 0; i < 4; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("Test finished. Check dmesg for kernel crash or UAF traces.\n");
    return 0;
}
