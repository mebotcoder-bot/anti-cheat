// SPDX-License-Identifier: GPL-2.0
/*
 * acheat - anti-cheat integrity kernel module (starting skeleton).
 *
 * Publishes a signed-by-position integrity snapshot at /proc/acheat/status that
 * the userspace agent folds into its attestation report. Running in ring 0 is
 * what makes the *hard* signals trustworthy: a userspace-only check can be lied
 * to by a rooted process, but detections rooted here (module-load hooks, syscall
 * table integrity) see tampering the userspace agent cannot.
 *
 * This is a foundation. Marked TODO are the detections that turn it from a
 * reporter into a real anti-cheat:
 *   - kprobe on the module loader to catch modules that hide from /proc/modules
 *   - periodic syscall-table + IDT integrity hashing (rootkit hooks)
 *   - notifier on /dev/mem opens
 *   - self-protection so the module cannot be silently unloaded
 *
 * Build on the target with `make`; load with `sudo insmod acheat.ko`.
 * With Secure Boot enabled the .ko must be signed with an enrolled MOK key.
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/panic.h>   /* for tainted-mask access on modern kernels */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("anti-cheat");
MODULE_DESCRIPTION("Anti-cheat kernel integrity reporter");
MODULE_VERSION("0.1");

#define PROC_DIR  "acheat"
#define PROC_FILE "status"

static struct proc_dir_entry *acheat_dir;

/* Count currently loaded modules by walking the module list. A count that
 * disagrees with userspace's /proc/modules is a hint that something is hiding. */
static unsigned int count_modules(void)
{
	struct module *mod;
	unsigned int n = 0;

	/* THIS_MODULE->list is threaded into the global module list. */
	list_for_each_entry(mod, THIS_MODULE->list.prev, list)
		n++;
	return n;
}

static int acheat_show(struct seq_file *m, void *v)
{
	/* get_taint() returns the current tainted mask; nonzero => out-of-tree or
	 * forced modules, etc. Reported here so the value is read in-kernel rather
	 * than from a userspace file a cheat could shadow. */
	seq_printf(m, "acheat_version=0.1\n");
	seq_printf(m, "taint_mask=%lu\n", get_taint());
	seq_printf(m, "module_count=%u\n", count_modules());
	/* TODO: syscall_table_ok=, dev_mem_opens=, idt_ok= ... */
	return 0;
}

static int acheat_open(struct inode *inode, struct file *file)
{
	return single_open(file, acheat_show, NULL);
}

static const struct proc_ops acheat_pops = {
	.proc_open    = acheat_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

static int __init acheat_init(void)
{
	acheat_dir = proc_mkdir(PROC_DIR, NULL);
	if (!acheat_dir)
		return -ENOMEM;

	if (!proc_create(PROC_FILE, 0444, acheat_dir, &acheat_pops)) {
		proc_remove(acheat_dir);
		return -ENOMEM;
	}

	pr_info("acheat: integrity reporter loaded (taint=%lu)\n", get_taint());
	return 0;
}

static void __exit acheat_exit(void)
{
	proc_remove(acheat_dir);
	pr_info("acheat: unloaded\n");
}

module_init(acheat_init);
module_exit(acheat_exit);
