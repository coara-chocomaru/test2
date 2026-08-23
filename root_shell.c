#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <pthread.h>
#include <errno.h>
#include <sys/sendfile.h>
#include <sys/time.h>
#include <sys/resource.h>

// ==================== 設定 ====================
#define OUTPUT_DIR          "/sdcard/download"
#define BLOCK_DEV_BASE      "/dev/block/mmcblk0p"
#define BLOCK_START         1
#define BLOCK_END           69
#define DATA_SYSTEM_DIR     "/data/system"

// スレッド数（同時実行制御）
#define MAX_BLOCK_WORKERS   4
#define MAX_FILE_WORKERS    8

// I/Oバッファ（ブロック用：1MB / ファイル用：64KB）
#define BLOCK_BUFFER_SIZE   (1024 * 1024)      // 1MiB (512で割り切れる)
#define FILE_BUFFER_SIZE    (64 * 1024)        // 64KB

// ==================== ブロックデバイス用スレッドプール ====================
static int block_queue[BLOCK_END - BLOCK_START + 1];
static int block_front = 0;
static int block_rear = 0;
static int block_done = 0;
static pthread_mutex_t block_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t block_cond = PTHREAD_COND_INITIALIZER;

// ==================== ファイル用スレッドプール ====================
typedef struct file_job {
    char src[512];
    char dst[512];
    struct file_job *next;
} file_job_t;

static file_job_t *file_head = NULL;
static file_job_t *file_tail = NULL;
static int file_done = 0;
static pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t file_cond = PTHREAD_COND_INITIALIZER;

// ==================== ユーティリティ関数 ====================
// スレッドセーフなprintf代わり（競合しても許容）
#define LOG(fmt, ...) printf("[copy] " fmt, ##__VA_ARGS__)

// 出力ディレクトリを再帰的に作成（親階層も含む簡易実装）
static void mkdir_recursive(const char *path) {
    char tmp[512];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    if (tmp[len - 1] == '/') tmp[len - 1] = 0;

    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, 0777);
            *p = '/';
        }
    }
    mkdir(tmp, 0777);
}

// ==================== ブロックデバイス ダンプ本体 ====================
static void dump_single_block(int num) {
    char src_path[128];
    char dst_path[128];
    snprintf(src_path, sizeof(src_path), "%s%d", BLOCK_DEV_BASE, num);
    snprintf(dst_path, sizeof(dst_path), "%s/mmcblk0p%d.img", OUTPUT_DIR, num);

    // 1. 入力デバイスを開く（O_DIRECT を試行）
    int fd_in = open(src_path, O_RDONLY | O_DIRECT);
    int use_direct = 1;
    if (fd_in < 0) {
        // O_DIRECT非対応の場合、通常オープン
        fd_in = open(src_path, O_RDONLY);
        use_direct = 0;
        if (fd_in < 0) {
            LOG("ブロックデバイスを開けません: %s (%s)\n", src_path, strerror(errno));
            return;
        }
    }

    // 2. 出力ファイルを開く
    int fd_out = open(dst_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd_out < 0) {
        LOG("出力ファイルを作成できません: %s (%s)\n", dst_path, strerror(errno));
        close(fd_in);
        return;
    }

    // 3. デバイスサイズを取得
    off_t size = lseek(fd_in, 0, SEEK_END);
    if (size <= 0) {
        LOG("サイズ取得失敗 %s (size=%ld)\n", src_path, (long)size);
        close(fd_in);
        close(fd_out);
        return;
    }
    lseek(fd_in, 0, SEEK_SET);

    LOG("ダンプ開始: %s (サイズ: %lld MB)\n", src_path, (long long)(size / (1024*1024)));

    // 4. 高速化: シーケンシャルアクセスをカーネルに指示
    posix_fadvise(fd_in, 0, 0, POSIX_FADV_SEQUENTIAL);

    // 5. sendfile() でゼロコピー転送を試行
    off_t offset = 0;
    int use_sendfile = 1;
    while (offset < size) {
        ssize_t ret = sendfile(fd_out, fd_in, &offset, (size_t)(size - offset));
        if (ret <= 0) {
            if (errno == EINTR) continue;
            // sendfile失敗時はフォールバックへ
            use_sendfile = 0;
            break;
        }
    }
    if (use_sendfile && offset == size) {
        LOG("  → sendfile 成功: %s\n", dst_path);
        close(fd_in);
        close(fd_out);
        return;
    }

    // 6. sendfile が使えなかった場合のフォールバック（read/write）
    //    O_DIRECT使用時はアライメントされたバッファが必要
    char *buf = NULL;
    size_t buf_size = BLOCK_BUFFER_SIZE;
    if (use_direct) {
        if (posix_memalign((void**)&buf, 4096, buf_size) != 0) {
            // アライメント確保失敗 → directを諦めて通常malloc
            use_direct = 0;
            buf = malloc(buf_size);
        }
    } else {
        buf = malloc(buf_size);
    }
    if (!buf) {
        // それでもダメなら小さいバッファ（スタック）で再挑戦（ただしdirect時はアライメント違反で失敗する可能性あり）
        LOG("  メモリ確保失敗、小バッファで再試行\n");
        char small_buf[8192];
        lseek(fd_in, 0, SEEK_SET);
        while (1) {
            ssize_t r = read(fd_in, small_buf, sizeof(small_buf));
            if (r <= 0) break;
            ssize_t w = write(fd_out, small_buf, r);
            if (w != r) break;
        }
        close(fd_in);
        close(fd_out);
        return;
    }

    // バッファを使ったコピー
    lseek(fd_in, 0, SEEK_SET);
    while (1) {
        ssize_t r = read(fd_in, buf, buf_size);
        if (r < 0) {
            if (errno == EINTR) continue;
            // O_DIRECTでアライメントエラーが起きた場合は再試行しない
            break;
        }
        if (r == 0) break;
        ssize_t w = write(fd_out, buf, r);
        if (w != r) {
            break;
        }
    }
    free(buf);
    close(fd_in);
    close(fd_out);
    LOG("  → フォールバック完了: %s\n", dst_path);
}

// ==================== ブロックデバイス ワーカースレッド ====================
static void *block_worker(void *arg) {
    (void)arg;
    while (1) {
        pthread_mutex_lock(&block_mutex);
        while (block_front == block_rear && !block_done) {
            pthread_cond_wait(&block_cond, &block_mutex);
        }
        if (block_front == block_rear && block_done) {
            pthread_mutex_unlock(&block_mutex);
            break;
        }
        int num = block_queue[block_front++];
        pthread_mutex_unlock(&block_mutex);

        dump_single_block(num);
    }
    return NULL;
}

// ==================== 通常ファイル コピー本体 ====================
static int copy_file(const char *src, const char *dst) {
    int fd_in = open(src, O_RDONLY);
    if (fd_in < 0) {
        LOG("  ファイル開けず: %s (%s)\n", src, strerror(errno));
        return -1;
    }

    // 出力先ディレクトリが存在することを確認（既に作成済みだが念のため）
    char dst_dir[512];
    strcpy(dst_dir, dst);
    char *last_slash = strrchr(dst_dir, '/');
    if (last_slash) {
        *last_slash = 0;
        mkdir_recursive(dst_dir);
    }

    int fd_out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd_out < 0) {
        LOG("  出力開けず: %s (%s)\n", dst, strerror(errno));
        close(fd_in);
        return -1;
    }

    // サイズ取得
    off_t size = lseek(fd_in, 0, SEEK_END);
    lseek(fd_in, 0, SEEK_SET);
    if (size == 0) {
        // 空ファイルは作成のみで終了
        close(fd_in);
        close(fd_out);
        return 0;
    }

    // シーケンシャルアクセスヒント
    posix_fadvise(fd_in, 0, 0, POSIX_FADV_SEQUENTIAL);

    // 1. sendfile 優先
    off_t offset = 0;
    int sendfile_ok = 1;
    while (offset < size) {
        ssize_t ret = sendfile(fd_out, fd_in, &offset, (size_t)(size - offset));
        if (ret <= 0) {
            if (errno == EINTR) continue;
            sendfile_ok = 0;
            break;
        }
    }
    if (sendfile_ok && offset == size) {
        close(fd_in);
        close(fd_out);
        return 0;
    }

    // 2. フォールバック: read/write
    char buf[FILE_BUFFER_SIZE];
    lseek(fd_in, 0, SEEK_SET);
    while (1) {
        ssize_t r = read(fd_in, buf, sizeof(buf));
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (r == 0) break;
        ssize_t w = write(fd_out, buf, r);
        if (w != r) break;
    }

    close(fd_in);
    close(fd_out);
    return 0;
}

// ==================== ファイル ワーカースレッド ====================
static void *file_worker(void *arg) {
    (void)arg;
    while (1) {
        pthread_mutex_lock(&file_mutex);
        while (file_head == NULL && !file_done) {
            pthread_cond_wait(&file_cond, &file_mutex);
        }
        if (file_head == NULL && file_done) {
            pthread_mutex_unlock(&file_mutex);
            break;
        }
        file_job_t *job = file_head;
        file_head = file_head->next;
        if (file_head == NULL) file_tail = NULL;
        pthread_mutex_unlock(&file_mutex);

        copy_file(job->src, job->dst);
        free(job);
    }
    return NULL;
}

// ==================== ディレクトリウォーカー（再帰） ====================
static void walk_directory(const char *base, const char *out_base) {
    DIR *dir = opendir(base);
    if (!dir) {
        LOG("ディレクトリを開けません: %s (%s)\n", base, strerror(errno));
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char src_path[512];
        char dst_path[512];
        snprintf(src_path, sizeof(src_path), "%s/%s", base, entry->d_name);
        snprintf(dst_path, sizeof(dst_path), "%s/%s", out_base, entry->d_name);

        struct stat st;
        if (lstat(src_path, &st) < 0) continue;

        if (S_ISDIR(st.st_mode)) {
            // ディレクトリは再帰 + 出力先にmkdir
            mkdir_recursive(dst_path);
            walk_directory(src_path, dst_path);
        } else if (S_ISREG(st.st_mode)) {
            // 通常ファイル → ジョブキューに投入
            file_job_t *job = (file_job_t *)malloc(sizeof(file_job_t));
            if (!job) {
                LOG("メモリ不足、ファイルスキップ: %s\n", src_path);
                continue;
            }
            strncpy(job->src, src_path, sizeof(job->src) - 1);
            job->src[sizeof(job->src) - 1] = 0;
            strncpy(job->dst, dst_path, sizeof(job->dst) - 1);
            job->dst[sizeof(job->dst) - 1] = 0;
            job->next = NULL;

            pthread_mutex_lock(&file_mutex);
            if (file_tail) {
                file_tail->next = job;
                file_tail = job;
            } else {
                file_head = file_tail = job;
            }
            pthread_cond_signal(&file_cond);
            pthread_mutex_unlock(&file_mutex);
        }
        // シンボリックリンクやスペシャルファイルは無視
    }
    closedir(dir);
}

// ==================== メイン ====================
int main(void) {
    umask(0); // パーミッション強制

    // 出力ルートディレクトリ作成
    mkdir_recursive(OUTPUT_DIR);

    LOG("=== ブロックデバイス ダンプ開始 (mmcblk0p1 ~ p69) ===\n");

    // ---- ブロックデバイス用スレッドプール起動 ----
    pthread_t block_threads[MAX_BLOCK_WORKERS];
    for (int i = 0; i < MAX_BLOCK_WORKERS; i++) {
        pthread_create(&block_threads[i], NULL, block_worker, NULL);
    }

    // ブロックキューにタスク投入
    pthread_mutex_lock(&block_mutex);
    for (int i = BLOCK_START; i <= BLOCK_END; i++) {
        block_queue[block_rear++] = i;
    }
    pthread_cond_broadcast(&block_cond);
    pthread_mutex_unlock(&block_mutex);

    // ブロックキューが空になるまで待機
    while (1) {
        pthread_mutex_lock(&block_mutex);
        if (block_front == block_rear) {
            block_done = 1;
            pthread_cond_broadcast(&block_cond);
            pthread_mutex_unlock(&block_mutex);
            break;
        }
        pthread_mutex_unlock(&block_mutex);
        usleep(100000); // 100ms待機
    }

    // ブロックワーカースレッド終了待ち
    for (int i = 0; i < MAX_BLOCK_WORKERS; i++) {
        pthread_join(block_threads[i], NULL);
    }
    LOG("=== ブロックデバイス ダンプ完了 ===\n");

    // ---- ファイルコピー ( /data/system/ ) ----
    LOG("=== /data/system/ スキャン & コピー開始 ===\n");

    // ファイル用スレッドプール起動
    pthread_t file_threads[MAX_FILE_WORKERS];
    for (int i = 0; i < MAX_FILE_WORKERS; i++) {
        pthread_create(&file_threads[i], NULL, file_worker, NULL);
    }

    // 出力ベースディレクトリ
    char data_out_dir[512];
    snprintf(data_out_dir, sizeof(data_out_dir), "%s/data_system", OUTPUT_DIR);
    mkdir_recursive(data_out_dir);

    // 再帰ウォーク開始（この関数内でキューにジョブを投入し続ける）
    walk_directory(DATA_SYSTEM_DIR, data_out_dir);

    // キューが空になるまで待機し、完了フラグをセット
    while (1) {
        pthread_mutex_lock(&file_mutex);
        if (file_head == NULL) {
            file_done = 1;
            pthread_cond_broadcast(&file_cond);
            pthread_mutex_unlock(&file_mutex);
            break;
        }
        pthread_mutex_unlock(&file_mutex);
        usleep(100000);
    }

    // ファイルワーカースレッド終了待ち
    for (int i = 0; i < MAX_FILE_WORKERS; i++) {
        pthread_join(file_threads[i], NULL);
    }

    LOG("=== 全処理完了 (/sdcard/download/ に出力済み) ===\n");
    return 0;
}
