/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 * Copyright (C) 2024 Assistant. All Rights Reserved.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <kputils.h>
#include <asm/current.h>
#include <linux/errno.h>

KPM_NAME("kpm-path-hiding");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Assistant");
KPM_DESCRIPTION("KernelPatch Module for Hiding Specific Paths");

enum hook_type hook_type = NONE;

// Function to check if a path should be hidden
static int should_hide_path(const char *path)
{
    return (strstr(path, "/system") || strstr(path, "/vendor") || strstr(path, "/product")) &&
           (strstr(path, "lineage") || strstr(path, "addon.d"));
}

void before_openat(hook_fargs4_t *args, void *udata)
{
    const char __user *filename = (typeof(filename))syscall_argn(args, 1);
    char buf[1024];
    
    // Safely copy the user-space string to kernel space
    if (strncpy_from_user(buf, filename, sizeof(buf)) < 0) {
        pr_err("Failed to copy filename from user space\n");
        return;
    }

    pr_info("Attempting to open: %s\n", buf);

    // Check if the path should be hidden
    if (should_hide_path(buf)) {
        pr_info("Hiding path from access: %s\n", buf);
        args->local.data0 = 1; // Set flag to indicate hiding
        syscall_set_argn(args, 1, "/dev/null");
    } else {
        args->local.data0 = 0;
    }
}

void after_openat(hook_fargs4_t *args, void *udata)
{
    // If we're hiding the path, return -ENOENT (No such file or directory)
    if (args->local.data0) {
        syscall_set_retval((hook_fargs_t *)args, -ENOENT);
    }
}

static long path_hiding_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("kpm-path-hiding init ...\n");

    hook_err_t err = HOOK_NO_ERR;

    // Use function pointer hook for this example
    hook_type = FUNCTION_POINTER_CHAIN;
    err = fp_hook_syscalln(__NR_openat, 4, before_openat, after_openat, NULL);

    if (err) {
        pr_err("hook openat error: %d\n", err);
    } else {
        pr_info("hook openat success\n");
    }

    return 0;
}

static long path_hiding_exit(void *__user reserved)
{
    pr_info("kpm-path-hiding exit ...\n");

    if (hook_type == FUNCTION_POINTER_CHAIN) {
        fp_unhook_syscalln(__NR_openat, before_openat, after_openat);
    }

    return 0;
}

KPM_INIT(path_hiding_init);
KPM_EXIT(path_hiding_exit);
