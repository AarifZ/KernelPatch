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
KPM_VERSION("1.0.1");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("bmax121");
KPM_DESCRIPTION("KernelPatch Module System Call Hook Example");

const char *margs = 0;
enum hook_type hook_type = NONE;

enum pid_type {
    PIDTYPE_PID,
    PIDTYPE_TGID,
    PIDTYPE_PGID,
    PIDTYPE_SID,
    PIDTYPE_MAX,
};
struct pid_namespace;
pid_t (*__task_pid_nr_ns)(struct task_struct *task, enum pid_type type, struct pid_namespace *ns) = 0;

void check_and_redirect_path(const char __user *filename) {
    char buf[1024];
    compat_strncpy_from_user(buf, filename, sizeof(buf));

    // Check if the file path contains restricted directories and redirect/block
    if (strstr(buf, "/system") || strstr(buf, "/vendor") || strstr(buf, "/product")) {
        if (strstr(buf, "lineage") || strstr(buf, "addon.d")) {
            pr_info("Hiding access to: %s\n", buf);
            
            // Redirect the path to /dev/null
            const char *redirect_path = "/dev/null";
            strncpy_to_user((void __user *)filename, redirect_path, strlen(redirect_path) + 1);  // Use strncpy_to_user
        }
    }
}

void before_open(hook_fargs3_t *args, void *udata) {
    const char __user *filename = (typeof(filename))syscall_argn(args, 0);
    pr_info("Intercepting open syscall\n");
    check_and_redirect_path(filename);
}

void before_openat(hook_fargs4_t *args, void *udata) {
    const char __user *filename = (typeof(filename))syscall_argn(args, 1);
    pr_info("Intercepting openat syscall\n");
    check_and_redirect_path(filename);
}

static long syscall_hook_demo_init(const char *args, const char *event, void *__user reserved) {
    margs = args;
    pr_info("kpm-syscall-hook-demo init ..., args: %s\n", margs);

    __task_pid_nr_ns = (typeof(__task_pid_nr_ns))kallsyms_lookup_name("__task_pid_nr_ns");
    pr_info("kernel function __task_pid_nr_ns addr: %llx\n", __task_pid_nr_ns);

    if (!margs) {
        pr_warn("no args specified, skip hook\n");
        return 0;
    }

    hook_err_t err = HOOK_NO_ERR;

    if (!strcmp("function_pointer_hook", margs)) {
        pr_info("function pointer hook ...");
        hook_type = FUNCTION_POINTER_CHAIN;
        err = fp_hook_syscalln(__NR_open, 3, before_open, 0, 0);
        if (err) goto out;
        err = fp_hook_syscalln(__NR_openat, 4, before_openat, 0, 0);
    } else if (!strcmp("inline_hook", margs)) {
        pr_info("inline hook ...");
        hook_type = INLINE_CHAIN;
        err = inline_hook_syscalln(__NR_open, 3, before_open, 0, 0);
        if (err) goto out;
        err = inline_hook_syscalln(__NR_openat, 4, before_openat, 0, 0);
    } else {
        pr_warn("unknown args: %s\n", margs);
        return 0;
    }

out:
    if (err) {
        pr_err("hook syscall error: %d\n", err);
    } else {
        pr_info("hook syscall success\n");
    }
    return 0;
}

static long syscall_hook_demo_exit(void *__user reserved) {
    pr_info("kpm-syscall-hook-demo exit ...\n");

    if (hook_type == INLINE_CHAIN) {
        inline_unhook_syscall(__NR_open, before_open, 0);
        inline_unhook_syscall(__NR_openat, before_openat, 0);
    } else if (hook_type == FUNCTION_POINTER_CHAIN) {
        fp_unhook_syscall(__NR_open, before_open, 0);
        fp_unhook_syscall(__NR_openat, before_openat, 0);
    }
    return 0;
}

KPM_INIT(syscall_hook_demo_init);
KPM_EXIT(syscall_hook_demo_exit);
