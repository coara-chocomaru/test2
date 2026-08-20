/*
 * binder_test.c - Binder driver stress/fuzz test for vulnerability verification
 * Build with Android NDK: ndk-build
 * Run on device: adb shell /data/local/tmp/binder_test
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/types.h>

// Define Binder ioctl structures (from kernel headers)
#define BINDER_IPC_32BIT 1

#ifdef BINDER_IPC_32BIT
typedef __u32 binder_size_t;
typedef __u32 binder_uintptr_t;
#else
typedef __u64 binder_size_t;
typedef __u64 binder_uintptr_t;
#endif

struct binder_object_header {
    __u32 type;
};

struct flat_binder_object {
    struct binder_object_header hdr;
    __u32 flags;
    union {
        binder_uintptr_t binder;
        __u32 handle;
    };
    binder_uintptr_t cookie;
};

struct binder_fd_object {
    struct binder_object_header hdr;
    __u32 pad_flags;
    union {
        binder_uintptr_t pad_binder;
        __u32 fd;
    };
    binder_uintptr_t cookie;
};

struct binder_buffer_object {
    struct binder_object_header hdr;
    __u32 flags;
    binder_uintptr_t buffer;
    binder_size_t length;
    binder_size_t parent;
    binder_size_t parent_offset;
};

struct binder_fd_array_object {
    struct binder_object_header hdr;
    __u32 pad;
    binder_size_t num_fds;
    binder_size_t parent;
    binder_size_t parent_offset;
};

struct binder_write_read {
    binder_size_t write_size;
    binder_size_t write_consumed;
    binder_uintptr_t write_buffer;
    binder_size_t read_size;
    binder_size_t read_consumed;
    binder_uintptr_t read_buffer;
};

struct binder_transaction_data {
    union {
        __u32 handle;
        binder_uintptr_t ptr;
    } target;
    binder_uintptr_t cookie;
    __u32 code;
    __u32 flags;
    pid_t sender_pid;
    uid_t sender_euid;
    binder_size_t data_size;
    binder_size_t offsets_size;
    union {
        struct {
            binder_uintptr_t buffer;
            binder_uintptr_t offsets;
        } ptr;
        __u8 buf[8];
    } data;
};

struct binder_transaction_data_secctx {
    struct binder_transaction_data transaction_data;
    binder_uintptr_t secctx;
};

struct binder_transaction_data_sg {
    struct binder_transaction_data transaction_data;
    binder_size_t buffers_size;
};

struct binder_version {
    __s32 protocol_version;
};

struct binder_node_debug_info {
    binder_uintptr_t ptr;
    binder_uintptr_t cookie;
    __u32 has_strong_ref;
    __u32 has_weak_ref;
};

struct binder_node_info_for_ref {
    __u32 handle;
    __u32 strong_count;
    __u32 weak_count;
    __u32 reserved1;
    __u32 reserved2;
    __u32 reserved3;
};

struct binder_ptr_cookie {
    binder_uintptr_t ptr;
    binder_uintptr_t cookie;
};

struct binder_handle_cookie {
    __u32 handle;
    binder_uintptr_t cookie;
};

#define BINDER_WRITE_READ           _IOWR('b', 1, struct binder_write_read)
#define BINDER_SET_MAX_THREADS      _IOW('b', 5, __u32)
#define BINDER_SET_CONTEXT_MGR      _IOW('b', 7, __s32)
#define BINDER_SET_CONTEXT_MGR_EXT  _IOW('b', 13, struct flat_binder_object)
#define BINDER_THREAD_EXIT          _IOW('b', 8, __s32)
#define BINDER_VERSION              _IOWR('b', 9, struct binder_version)
#define BINDER_GET_NODE_DEBUG_INFO  _IOWR('b', 11, struct binder_node_debug_info)
#define BINDER_GET_NODE_INFO_FOR_REF _IOWR('b', 12, struct binder_node_info_for_ref)

#define BC_TRANSACTION      _IOW('c', 0, struct binder_transaction_data)
#define BC_REPLY            _IOW('c', 1, struct binder_transaction_data)
#define BC_FREE_BUFFER      _IOW('c', 3, binder_uintptr_t)
#define BC_INCREFS          _IOW('c', 4, __u32)
#define BC_ACQUIRE          _IOW('c', 5, __u32)
#define BC_RELEASE          _IOW('c', 6, __u32)
#define BC_DECREFS          _IOW('c', 7, __u32)
#define BC_INCREFS_DONE     _IOW('c', 8, struct binder_ptr_cookie)
#define BC_ACQUIRE_DONE     _IOW('c', 9, struct binder_ptr_cookie)
#define BC_REGISTER_LOOPER  _IO('c', 11)
#define BC_ENTER_LOOPER     _IO('c', 12)
#define BC_EXIT_LOOPER      _IO('c', 13)
#define BC_REQUEST_DEATH_NOTIFICATION _IOW('c', 14, struct binder_handle_cookie)
#define BC_CLEAR_DEATH_NOTIFICATION   _IOW('c', 15, struct binder_handle_cookie)
#define BC_DEAD_BINDER_DONE _IOW('c', 16, binder_uintptr_t)
#define BC_TRANSACTION_SG   _IOW('c', 17, struct binder_transaction_data_sg)
#define BC_REPLY_SG         _IOW('c', 18, struct binder_transaction_data_sg)

#define BINDER_CURRENT_PROTOCOL_VERSION 8

// Helper to send a binder command (write)
static int binder_write(int fd, void *data, size_t size) {
    struct binder_write_read bwr = {
        .write_size = size,
        .write_buffer = (binder_uintptr_t)data,
        .read_size = 0,
        .read_buffer = 0,
    };
    return ioctl(fd, BINDER_WRITE_READ, &bwr);
}

// Helper to read a binder command
static int binder_read(int fd, void *data, size_t size) {
    struct binder_write_read bwr = {
        .write_size = 0,
        .write_buffer = 0,
        .read_size = size,
        .read_buffer = (binder_uintptr_t)data,
    };
    return ioctl(fd, BINDER_WRITE_READ, &bwr);
}

// Global file descriptor
int binder_fd = -1;

// Thread function to perform refcount operations
void *refcount_thr(void *arg) {
    uint32_t handle = (uint32_t)(uintptr_t)arg;
    for (int i = 0; i < 10000; i++) {
        // Inc/dec strong ref
        uint32_t cmd = BC_ACQUIRE;
        if (ioctl(binder_fd, cmd, &handle) < 0) {
            // ignore
        }
        cmd = BC_RELEASE;
        if (ioctl(binder_fd, cmd, &handle) < 0) {
            // ignore
        }
        // Also inc/dec weak
        cmd = BC_INCREFS;
        if (ioctl(binder_fd, cmd, &handle) < 0) {
            // ignore
        }
        cmd = BC_DECREFS;
        if (ioctl(binder_fd, cmd, &handle) < 0) {
            // ignore
        }
    }
    return NULL;
}

// Test 1: Large data size with invalid offsets to cause overflow
void test_large_transaction() {
    printf("[*] Test large transaction with invalid sizes\n");
    struct binder_transaction_data tr = {0};
    tr.target.handle = 0; // context manager
    tr.code = 0x1234;
    tr.flags = 0;
    // Use huge data_size to trigger integer overflow (should be caught)
    tr.data_size = 0xFFFFFFFF; // -1 on 32-bit
    tr.offsets_size = 0;
    tr.data.ptr.buffer = 0;
    tr.data.ptr.offsets = 0;

    struct binder_write_read bwr = {
        .write_size = sizeof(tr),
        .write_buffer = (binder_uintptr_t)&tr,
        .read_size = 0,
        .read_buffer = 0,
    };
    int ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    printf("  BC_TRANSACTION with large data_size returned %d (errno=%d)\n", ret, errno);
}

// Test 2: Invalid handle for inc/dec ref
void test_invalid_handle() {
    printf("[*] Test invalid handle inc/dec\n");
    uint32_t handle = 0xDEADBEEF;
    int ret = ioctl(binder_fd, BC_ACQUIRE, &handle);
    printf("  BC_ACQUIRE invalid handle returned %d\n", ret);
    ret = ioctl(binder_fd, BC_RELEASE, &handle);
    printf("  BC_RELEASE invalid handle returned %d\n", ret);
}

// Test 3: Free buffer with invalid pointer
void test_free_invalid_buffer() {
    printf("[*] Test BC_FREE_BUFFER with invalid pointer\n");
    binder_uintptr_t ptr = 0x12345678;
    int ret = ioctl(binder_fd, BC_FREE_BUFFER, &ptr);
    printf("  BC_FREE_BUFFER invalid ptr returned %d\n", ret);
}

// Test 4: Death notification with invalid handle
void test_death_notification() {
    printf("[*] Test BC_REQUEST_DEATH_NOTIFICATION invalid handle\n");
    struct binder_handle_cookie hc = {
        .handle = 0xFFFF,
        .cookie = 0x1234,
    };
    int ret = ioctl(binder_fd, BC_REQUEST_DEATH_NOTIFICATION, &hc);
    printf("  BC_REQUEST_DEATH_NOTIFICATION returned %d\n", ret);
}

// Test 5: Race condition by spawning multiple threads doing refcount ops
void test_race_refcount() {
    printf("[*] Test race condition on refcounts\n");
    // First create a node and get a handle
    struct flat_binder_object fbo = {
        .hdr.type = BINDER_TYPE_BINDER,
        .flags = 0,
        .binder = 0,
        .cookie = 0,
    };
    int ret = ioctl(binder_fd, BINDER_SET_CONTEXT_MGR_EXT, &fbo);
    if (ret < 0) {
        printf("  Failed to set context manager: %d\n", ret);
        return;
    }
    // Now we need to get a handle to our own node. We can send a transaction to ourselves.
    // Simplified: we'll just spawn threads that inc/dec on handle 0 (context manager)
    pthread_t threads[4];
    for (int i = 0; i < 4; i++) {
        pthread_create(&threads[i], NULL, refcount_thr, (void*)(uintptr_t)0);
    }
    for (int i = 0; i < 4; i++) {
        pthread_join(threads[i], NULL);
    }
    printf("  Race test completed (check kernel log for crashes)\n");
}

// Test 6: Get node debug info (information leak)
void test_node_debug_info() {
    printf("[*] Test BINDER_GET_NODE_DEBUG_INFO\n");
    struct binder_node_debug_info info = {0};
    info.ptr = 0; // start from first
    while (1) {
        int ret = ioctl(binder_fd, BINDER_GET_NODE_DEBUG_INFO, &info);
        if (ret < 0) {
            printf("  BINDER_GET_NODE_DEBUG_INFO failed: %d\n", ret);
            break;
        }
        if (info.ptr == 0 && info.cookie == 0) break; // no more nodes
        printf("  Node ptr=%llx cookie=%llx strong=%d weak=%d\n",
               (unsigned long long)info.ptr, (unsigned long long)info.cookie,
               info.has_strong_ref, info.has_weak_ref);
        // next iteration uses last ptr as start
    }
}

int main() {
    printf("=== Binder Driver Vulnerability Test ===\n");

    binder_fd = open("/dev/binder", O_RDWR);
    if (binder_fd < 0) {
        perror("open /dev/binder");
        return 1;
    }

    // Set max threads
    int max_threads = 10;
    if (ioctl(binder_fd, BINDER_SET_MAX_THREADS, &max_threads) < 0) {
        perror("BINDER_SET_MAX_THREADS");
    }

    // Register as context manager (required for some operations)
    if (ioctl(binder_fd, BINDER_SET_CONTEXT_MGR, 0) < 0) {
        perror("BINDER_SET_CONTEXT_MGR");
        // Continue anyway
    }

    test_large_transaction();
    test_invalid_handle();
    test_free_invalid_buffer();
    test_death_notification();
    test_race_refcount();
    test_node_debug_info();

    close(binder_fd);
    printf("[+] Test completed. Check dmesg for kernel crashes.\n");
    return 0;
}
