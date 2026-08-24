#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <limits.h>

// ダンプ先（デフォルト）
#ifndef DUMP_BASE
#define DUMP_BASE "/cache/"
#endif

#define MAX_PATH 4096
#define CHUNK_SIZE (1024 * 1024)          // 1MB
#define MAX_FILE_SIZE (64 * 1024 * 1024)  // 64MB
#define BLOCK_READ_SIZE (2 * 1024 * 1024) // ブロックデバイスは先頭2MB

// タイムスタンプを取得（グローバル）
static char g_timestamp[32];

// 安全なファイル名生成（パスをファイル名に変換：スラッシュ→アンダースコア）
static void path_to_filename(const char *path, char *out, size_t out_size) {
    char tmp[MAX_PATH];
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    // 先頭の / を除去
    char *p = tmp;
    if (*p == '/') p++;
    // スラッシュをアンダースコアに置換
    for (int i = 0; p[i]; i++) {
        if (p[i] == '/') p[i] = '_';
    }
    snprintf(out, out_size, "%s_%s", p, g_timestamp);
}

// ファイルの完全コピー（サイズ制限付き）
static void dump_file_full(const char *src, const char *dst) {
    int fd_in = open(src, O_RDONLY | O_NOFOLLOW);
    if (fd_in < 0) return;
    struct stat st;
    if (fstat(fd_in, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size > MAX_FILE_SIZE) {
        close(fd_in);
        return;
    }
    int fd_out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd_out < 0) {
        close(fd_in);
        return;
    }
    char buf[8192];
    ssize_t n;
    while ((n = read(fd_in, buf, sizeof(buf))) > 0) {
        if (write(fd_out, buf, n) != n) break;
    }
    close(fd_in);
    close(fd_out);
}

// ブロックデバイス用（先頭2MBのみ）
static void dump_block_partial(const char *src, const char *dst) {
    int fd_in = open(src, O_RDONLY | O_NOFOLLOW);
    if (fd_in < 0) return;
    int fd_out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd_out < 0) {
        close(fd_in);
        return;
    }
    char buf[CHUNK_SIZE];
    ssize_t n;
    size_t total = 0;
    while ((n = read(fd_in, buf, sizeof(buf))) > 0) {
        if (write(fd_out, buf, n) != n) break;
        total += n;
        if (total >= BLOCK_READ_SIZE) break;
    }
    close(fd_in);
    close(fd_out);
}

// ディレクトリを再帰的に探索し、各ファイルをダンプ（外部コマンドなし）
static void dump_dir_recursive(const char *base, const char *rel, const char *dest_prefix) {
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s/%s", base, rel[0] ? rel : "");
    DIR *dir = opendir(path);
    if (!dir) return;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        char full[MAX_PATH];
        snprintf(full, sizeof(full), "%s/%s", path, entry->d_name);
        struct stat st;
        if (lstat(full, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                char sub_rel[MAX_PATH];
                snprintf(sub_rel, sizeof(sub_rel), "%s/%s", rel[0] ? rel : "", entry->d_name);
                dump_dir_recursive(base, sub_rel, dest_prefix);
            } else if (S_ISREG(st.st_mode)) {
                char dst_file[MAX_PATH];
                // 相対パスをファイル名に変換（スラッシュ→アンダースコア）
                char rel_path[MAX_PATH];
                snprintf(rel_path, sizeof(rel_path), "%s/%s", rel[0] ? rel : "", entry->d_name);
                path_to_filename(rel_path, dst_file, sizeof(dst_file));
                char dst[MAX_PATH];
                snprintf(dst, sizeof(dst), "%s%s", dest_prefix, dst_file);
                dump_file_full(full, dst);
            }
        }
    }
    closedir(dir);
}

// 特定のパス一覧をダンプ（ファイル or ディレクトリ）
static void dump_path_list(const char *dest_prefix, const char *paths[], int count) {
    for (int i = 0; i < count; i++) {
        const char *src = paths[i];
        struct stat st;
        if (lstat(src, &st) == 0) {
            char dst_file[MAX_PATH];
            path_to_filename(src, dst_file, sizeof(dst_file));
            char dst[MAX_PATH];
            snprintf(dst, sizeof(dst), "%s%s", dest_prefix, dst_file);
            if (S_ISDIR(st.st_mode)) {
                // ディレクトリの場合は再帰的にダンプ（相対パスは空）
                dump_dir_recursive(src, "", dest_prefix);
            } else if (S_ISREG(st.st_mode)) {
                dump_file_full(src, dst);
            }
        }
    }
}

// ブロックデバイス一括ダンプ（mmcblk0p0〜68）
static void dump_block_devices(const char *dest_prefix) {
    for (int i = 0; i <= 68; i++) {
        char src[MAX_PATH];
        snprintf(src, sizeof(src), "/dev/block/mmcblk0p%d", i);
        if (access(src, F_OK) == 0) {
            char dst_file[MAX_PATH];
            snprintf(dst_file, sizeof(dst_file), "block_mmcblk0p%d_%s", i, g_timestamp);
            char dst[MAX_PATH];
            snprintf(dst, sizeof(dst), "%s%s", dest_prefix, dst_file);
            dump_block_partial(src, dst);
        }
    }
}

// メイン
int main(int argc, char **argv) {
    // タイムスタンプ生成
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    strftime(g_timestamp, sizeof(g_timestamp), "%Y%m%d_%H%M%S", tm);

    // ダンプ先ディレクトリ（/cache/ 直下）
    const char *base_dir = DUMP_BASE;
    if (argc > 1) {
        base_dir = argv[1];
    }

    // /cache/ に書き込めるか確認（存在しなければ作成はしない）
    // 実際にはすでに存在するはず

    // 1. /proc/self/ 以下
    dump_dir_recursive("/proc/self", "", base_dir);

    // 2. /vendor/bin/ 以下
    dump_dir_recursive("/vendor/bin", "", base_dir);

    // 3. ブロックデバイス
    dump_block_devices(base_dir);

    // 4. 特定のシステムファイル/ディレクトリ
    const char *system_paths[] = {
        "/system/build.prop",
        "/default.prop",
        "/vendor/build.prop",
        "/data/system/packages.xml",
        "/data/system/users.xml",
        "/data/misc/wifi/wpa_supplicant.conf",
        "/data/misc/keystore/",
        "/data/misc/vpn/",
        "/data/misc/bluetooth/",
        "/etc/hosts",
        "/system/etc/hosts"
    };
    dump_path_list(base_dir, system_paths, sizeof(system_paths)/sizeof(system_paths[0]));

    // 5. /data/system/ 全体（権限があれば）
    dump_dir_recursive("/data/system", "", base_dir);

    // 6. /data/misc/ 全体
    dump_dir_recursive("/data/misc", "", base_dir);

    // 7. ファイル一覧を作成（外部コマンドを使わず、自分で探索）
    // ただし、/以下を全探索するのは時間がかかるので、主要ディレクトリに限定
    // ここでは簡易的に、/proc, /sys, /data, /system, /vendor, /etc, /dev など
    // 実際には / 全体を探索すると非常に時間がかかるので、コメントアウト
    // 代わりに、重要なディレクトリを個別に指定する
    // ここでは既に上記で多くのものをカバーしているので省略

    // 完了メッセージ（標準エラーに出力、logcatで見える）
    fprintf(stderr, "Dump completed at %s\n", base_dir);
    return 0;
}
