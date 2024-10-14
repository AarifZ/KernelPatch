/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <asm/current.h>
#include <asm/unistd.h>  // For syscall numbers

#ifndef __NR_open
#define __NR_open 2      // Define the system call number for open if not declared
#endif

KPM_NAME("kpm-syscall-hook-demo");
KPM_VERSION("1.0.2");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("bmax121");
KPM_DESCRIPTION("KernelPatch Module System Call Hook Example");

const char *margs = 0;
enum hook_type hook_type = NONE;

// Declare function pointers for the original open and openat syscalls
void *orig_open = NULL;
void *orig_openat = NULL;

// Helper function to determine if a file path should be blocked
int should_block_path(const char *buf) {
    // Check if the file path contains restricted directories or keywords
    if (strstr(buf, "/system") || strstr(buf, "/vendor") || strstr(buf, "/product")) {
        if (strstr(buf, "lineage") || strstr(buf, "addon.d")) {
            pr_info("Blocking access to: %s\n", buf);
            return 1; // Block access
        }
    }
    return 0; // Allow access
}

// New open syscall to replace the original
long new_open(const char __user *filename, int flags, umode_t mode) {
    char buf[1024];
    strncpy_from_user(buf, filename, sizeof(buf));

    // Block if the path is restricted
    if (should_block_path(buf)) {
        return -EACCES; // Return Permission Denied
    }

    // Call the original open if not blocked
    return ((long(*)(const char __user *, int, umode_t))orig_open)(filename, flags, mode);
}

// New openat syscall to replace the original
long new_openat(int dfd, const char __user *filename, int flags, umode_t mode) {
    char buf[1024];
    strncpy_from_user(buf, filename, sizeof(buf));

    // Block if the path is restricted
    if (should_block_path(buf)) {
        return -EACCES; // Return Permission Denied
    }

    // Call the original openat if not blocked
    return ((long(*)(int, const char __user *, int, umode_t))orig_openat)(dfd, filename, flags, mode);
}

static long syscall_hook_demo_init(const char *args, const char *event, void *__user reserved) {
    // Get the original open and openat syscalls
    orig_open = (typeof(orig_open))kallsyms_lookup_name("sys_open");
    if (!orig_open) {
        pr_err("failed to get sys_open address\n");
        return -1;
    }

    orig_openat = (typeof(orig_openat))kallsyms_lookup_name("sys_openat");
    if (!orig_openat) {
        pr_err("failed to get sys_openat address\n");
        return -1;
    }

    // Hook the open syscall using hook_wrap3
    hook_err_t err = hook_wrap3((void *)orig_open, 0, new_open, 0);
    if (err) {
        pr_err("hooking open error: %d\n", err);
        return err;
    }

    // Hook the openat syscall using hook_wrap3
    err = hook_wrap3((void *)orig_openat, 0, new_openat, 0);
    if (err) {
        pr_err("hooking openat error: %d\n", err);
        return err;
    }

    pr_info("sys_open and sys_openat hooked successfully\n");
    return 0;
}

static long syscall_hook_demo_exit(void *__user reserved) {
    pr_info("kpm-syscall-hook-demo exit ...\n");

    // Unhook the open and openat syscalls
    hook_err_t err;
    err = hook_unwrap((void *)orig_open);
    if (err) {
        pr_err("unhooking open error: %d\n", err);
    }

    err = hook_unwrap((void *)orig_openat);
    if (err) {
        pr_err("unhooking openat error: %d\n", err);
    }

    return 0;
}

KPM_INIT(syscall_hook_demo_init);
KPM_EXIT(syscall_hook_demo_exit);
