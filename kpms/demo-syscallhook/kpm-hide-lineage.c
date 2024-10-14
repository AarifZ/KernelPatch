#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <kputils.h>
#include <asm/current.h>

KPM_NAME("kpm-hide-lineage");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Bard");
KPM_DESCRIPTION("KPM Module to Hide Lineage Traces in Open Calls");

static char *hidden_dirs[] = {"/system", "/vendor", "/product"};
static int num_hidden_dirs = sizeof(hidden_dirs) / sizeof(hidden_dirs[0]);

enum hook_type
{
  PIDTYPE_PID,
  PIDTYPE_TGID,
  PIDTYPE_PGID,
  PIDTYPE_SID,
  PIDTYPE_MAX,
};
struct pid_namespace;
pid_t (*__task_pid_nr_ns)(struct task_struct *task, enum pid_type type, struct pid_namespace *ns) = 0;

void before_openat_0(hook_fargs4_t *args, void *udata)
{
  int dfd = (int)syscall_argn(args, 0);
  const char __user *filename = (typeof(filename))syscall_argn(args, 1);

  char buf[1024];
  compat_strncpy_from_user(buf, filename, sizeof(buf));
  buf[sizeof(buf) - 1] = '\0'; // Ensure null termination

  struct task_struct *task = current;
  pid_t pid = -1, tgid = -1;
  if (__task_pid_nr_ns) {
    pid = __task_pid_nr_ns(task, PIDTYPE_PID, 0);
    tgid = __task_pid_nr_ns(task, PIDTYPE_TGID, 0);
  }

  bool hide_path = false;
  for (int i = 0; i < num_hidden_dirs; i++) {
    if (strstr(buf, hidden_dirs[i])) {
      hide_path = true;
      break;
    }
  }

  if (hide_path) {
    pr_info("Hiding path from access for pid %d, tgid %d: %s\n", pid, tgid, buf);
    args->args[1] = (void *)"/dev/null";
  } else {
    pr_info("Opening file: %s\n", buf);
  }
}

static long kpm_hide_lineage_init(const char *args, const char *event, void *__user reserved)
{
  pr_info("kpm-hide-lineage init ...\n");

  __task_pid_nr_ns = (typeof(__task_pid_nr_ns))kallsyms_lookup_name("__task_pid_nr_ns");
  pr_info("kernel function __task_pid_nr_ns addr: %llx\n", __task_pid_nr_ns);

  hook_err_t err = inline_hook_syscalln(__NR_openat, 4, before_openat_0, 0, 0);

  if (err) {
    pr_err("hook openat error: %d\n", err);
  } else {
    pr_info("hook openat success\n");
  }

  return 0;
}

static long kpm_hide_lineage_exit(void *__user reserved)
{
  pr_info("kpm-hide-lineage exit ...\n");

  inline_unhook_syscalln(__NR_openat, before_openat_0, 0);

  return 0;
}

KPM_INIT(kpm_hide_lineage_init);
KPM_EXIT(kpm_hide_lineage_exit);
