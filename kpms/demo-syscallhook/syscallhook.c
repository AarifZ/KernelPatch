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
#include <kputils.h>
#include <asm/current.h>
#include <linux/fs.h>
#include <linux/errno.h>

KPM_NAME("kpm-enhanced-syscall-hook");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("YourName");
KPM_DESCRIPTION("Enhanced KernelPatch Module for System Call Interception");

const char *margs = 0;
enum hook_type hook_type = NONE;

// Function to check if a path should be hidden
static int should_hide_path(const char *path)
{
    return (strstr(path, "/system") || strstr(path, "/vendor") || strstr(path, "/product")) &&
           (strstr(path, "lineage") || strstr(path, "addon.d"));
}

void before_openat(hook_fargs4_t *args, void *udata)
{
    int dfd = (int)syscall_argn(args, 0);
    const char __user *filename = (const char __user *)syscall_argn(args, 1);
    int flag = (int)syscall_argn(args, 2);
    umode_t mode = (umode_t)syscall_argn(args, 3);

    char buf[PATH_MAX];
    long ret = strncpy_from_user(buf, filename, sizeof(buf));
    if (ret > 0 && should_hide_path(buf)) {
        pr_info("Hiding path from access: %s\n", buf);
        // Set flag to indicate hiding
        args->local.data0 = 1;
    } else {
        args->local.data0 = 0;
    }

    pr_info("Attempting to open: %s\n", buf);
}

void after_openat(hook_fargs4_t *args, void *udata)
{
    if (args->local.data0) {
        // If we're hiding the path, return -ENOENT (No such file or directory)
        syscall_set_retval(args, -ENOENT);
    }
}

static long syscall_hook_init(const char *args, const char *event, void *__user reserved)
{
    margs = args;
    pr_info("kpm-enhanced-syscall-hook init ..., args: %s\n", margs);

    hook_err_t err = HOOK_NO_ERR;

    hook_type = INLINE_CHAIN;
    err = inline_hook_syscalln(__NR_openat, 4, before_openat, after_openat, 0);

    if (err) {
        pr_err("Hook openat error: %d\n", err);
    } else {
        pr_info("Hook openat success\n");
    }

    return 0;
}

static long syscall_hook_exit(void *__user reserved)
{
    pr_info("kpm-enhanced-syscall-hook exit ...\n");

    if (hook_type == INLINE_CHAIN) {
        inline_unhook_syscalln(__NR_openat, before_openat, after_openat);
    }

    return 0;
}

KPM_INIT(syscall_hook_init);
KPM_EXIT(syscall_hook_exit);
