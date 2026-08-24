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
#include <libgen.h>

// ダンプ先（デフォルト）
#ifndef DUMP_BASE
#define DUMP_BASE "/cache/"
#endif

#define MAX_PATH 4096
#define CHUNK_SIZE (1024 * 1024)      // 1MB
#define MAX_FILE_SIZE (64 * 1024 * 1024) // 64MB
#define BLOCK_READ_SIZE (2 * 1024 * 1024) // ブロックデバイスは先頭2MB

// 安全な文字列結合
static void safe_concat(char *dest, const char *src, size_t max) {
    size_t len = strlen(dest);
    if (len + strlen(src) + 1 < max) {
        strcat(dest, src);
    }
}

// 再帰的ディレクトリ作成
static void mkdir_recursive(const char *path) {
    char tmp[MAX_PATH];
    char *p;
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);
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

// ディレクトリ再帰ダンプ（相対パスを保持）
static void dump_dir_recursive(const char *base, const char *rel, const char *dest_root) {
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
            char dest_path[MAX_PATH];
            snprintf(dest_path, sizeof(dest_path), "%s/%s/%s", dest_root, rel[0] ? rel : "", entry->d_name);
            if (S_ISDIR(st.st_mode)) {
                mkdir_recursive(dest_path);
                char sub_rel[MAX_PATH];
                snprintf(sub_rel, sizeof(sub_rel), "%s/%s", rel[0] ? rel : "", entry->d_name);
                dump_dir_recursive(base, sub_rel, dest_root);
            } else if (S_ISREG(st.st_mode)) {
                char dest_dir[MAX_PATH];
                strncpy(dest_dir, dest_path, sizeof(dest_dir));
                char *last = strrchr(dest_dir, '/');
                if (last) *last = '\0';
                mkdir_recursive(dest_dir);
                dump_file_full(full, dest_path);
            }
        }
    }
    closedir(dir);
}

// 特定のパス一覧をダンプ（ファイル or ディレクトリ）
static void dump_path_list(const char *dest_root, const char *paths[], int count) {
    for (int i = 0; i < count; i++) {
        const char *src = paths[i];
        struct stat st;
        if (lstat(src, &st) == 0) {
            char dest[MAX_PATH];
            snprintf(dest, sizeof(dest), "%s/%s", dest_root, basename((char*)src));
            if (S_ISDIR(st.st_mode)) {
                mkdir_recursive(dest);
                dump_dir_recursive(src, "", dest);
            } else if (S_ISREG(st.st_mode)) {
                dump_file_full(src, dest);
            }
        }
    }
}

// ブロックデバイス一括ダンプ（mmcblk0p0〜68）
static void dump_block_devices(const char *dest_dir) {
    for (int i = 0; i <= 68; i++) {
        char src[MAX_PATH], dst[MAX_PATH];
        snprintf(src, sizeof(src), "/dev/block/mmcblk0p%d", i);
        if (access(src, F_OK) == 0) {
            snprintf(dst, sizeof(dst), "%s/block_mmcblk0p%d", dest_dir, i);
            dump_block_partial(src, dst);
        }
    }
}

// メイン
int main(int argc, char **argv) {
    char base_dir[MAX_PATH] = DUMP_BASE;
    if (argc > 1) {
        snprintf(base_dir, sizeof(base_dir), "%s", argv[1]);
    }
    // タイムスタンプ付きサブディレクトリ
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", tm);
    char dump_root[MAX_PATH];
    snprintf(dump_root, sizeof(dump_root), "%s/dump_%s", base_dir, timestamp);
    mkdir_recursive(dump_root);

    // 1. /proc/self/ 以下
    char proc_dest[MAX_PATH];
    snprintf(proc_dest, sizeof(proc_dest), "%s/proc_self", dump_root);
    mkdir_recursive(proc_dest);
    dump_dir_recursive("/proc/self", "", proc_dest);

    // 2. /vendor/bin/
    char vendor_dest[MAX_PATH];
    snprintf(vendor_dest, sizeof(vendor_dest), "%s/vendor_bin", dump_root);
    mkdir_recursive(vendor_dest);
    dump_dir_recursive("/vendor/bin", "", vendor_dest);

    // 3. ブロックデバイス
    char block_dest[MAX_PATH];
    snprintf(block_dest, sizeof(block_dest), "%s/block", dump_root);
    mkdir_recursive(block_dest);
    dump_block_devices(block_dest);

    // 4. システムディレクトリ（読み取り可能なもの）
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
    char sys_dest[MAX_PATH];
    snprintf(sys_dest, sizeof(sys_dest), "%s/system_misc", dump_root);
    mkdir_recursive(sys_dest);
    dump_path_list(sys_dest, system_paths, sizeof(system_paths)/sizeof(system_paths[0]));

    // 5. /data/system/ 全体（権限があれば）
    char data_sys_dest[MAX_PATH];
    snprintf(data_sys_dest, sizeof(data_sys_dest), "%s/data_system", dump_root);
    mkdir_recursive(data_sys_dest);
    dump_dir_recursive("/data/system", "", data_sys_dest);

    // 6. /data/misc/ 全体
    char data_misc_dest[MAX_PATH];
    snprintf(data_misc_dest, sizeof(data_misc_dest), "%s/data_misc", dump_root);
    mkdir_recursive(data_misc_dest);
    dump_dir_recursive("/data/misc", "", data_misc_dest);

    // 7. /data/local/tmp/ など（もし権限があれば）→ シェルが読める場所にダンプ
    // ただし system_app は通常読み書き不可なのでスキップ

    // 8. ファイル一覧作成（find / -type f -readable 相当）
    char list_path[MAX_PATH];
    snprintf(list_path, sizeof(list_path), "%s/file_list.txt", dump_root);
    int fd = open(list_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "find / -type f -readable 2>/dev/null | head -1000");
        FILE *fp = popen(cmd, "r");
        if (fp) {
            char line[1024];
            while (fgets(line, sizeof(line), fp)) {
                write(fd, line, strlen(line));
            }
            pclose(fp);
        }
        close(fd);
    }

    // 完了メッセージ（ファイルに出力）
    char done_path[MAX_PATH];
    snprintf(done_path, sizeof(done_path), "%s/COMPLETE", dump_root);
    fd = open(done_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Dump completed at %s\n", dump_root);
        write(fd, msg, strlen(msg));
        close(fd);
    }

    // 標準出力にも表示（logcatで見えるように）
    fprintf(stderr, "Dump completed: %s\n", dump_root);
    return 0;
}
