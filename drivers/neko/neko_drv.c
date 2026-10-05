// SPDX-License-Identifier: GPL-2.0
/*
 * Neko stealth process-memory driver for Linux 4.19 (arm64).
 *
 * In-tree home: drivers/neko/ in Neko-Kernel (aosp-16, 4.19.325, alioth).
 * Also builds out-of-tree as neko_drv.ko (see kernel/build.sh).
 *
 * What it replaces in the daemon, and why it is stealthier:
 *   /proc/<pid>/mem + pread/pwrite  -> NEKO_IOCTL_READ/WRITE/BATCH
 *       (no per-read /proc fd, no ptrace attach, syscall count collapses
 *       with batch mode; reads/writes go through access_process_vm with
 *       FOLL_FORCE, mirroring ptrace semantics incl. r-x code patching)
 *   /proc scan + cmdline compare     -> NEKO_IOCTL_FIND_PID
 *       (pid lookup happens in-kernel; daemon never walks /proc)
 *   /proc/<pid>/maps parse           -> NEKO_IOCTL_MODULE_BASE
 *       (vma walk under mmap_sem in-kernel)
 *
 * Stealth model:
 *   - Built-in (=y, recommended): no .ko on disk, nothing in lsmod that
 *     matters; only a /dev node which the daemon can unlink after open.
 *   - Loadable (=m): NEKO_IOCTL_HIDE unlinks /proc/modules + sysfs entries.
 *   - NEKO_IOCTL_HIDE mode 1 additionally tears down the chrdev so the
 *     device cannot be opened again (existing fds keep working).
 *
 * All ioctls require an authed fd (NEKO_IOCTL_AUTH with the build token)
 * plus CAP_SYS_PTRACE (i.e. root). There is intentionally no read()/write()
 * file op, only ioctls.
 */

#define pr_fmt(fmt) "neko: " fmt

#include <linux/capability.h>
#include <linux/cdev.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "neko_uapi.h"

#define NEKO_CHUNK (32u * 1024u)
#define NEKO_PID_SCAN_MAX 8192

#ifdef CONFIG_NEKO_DEV_NAME
static char *neko_devname = CONFIG_NEKO_DEV_NAME;
#else
static char *neko_devname = (char *)NEKO_DEFAULT_DEV;
#endif
module_param(neko_devname, charp, 0444);
MODULE_PARM_DESC(neko_devname, "device node name under /dev");

static unsigned long long neko_token = NEKO_DEFAULT_TOKEN;
module_param(neko_token, ullong, 0400);
MODULE_PARM_DESC(neko_token, "auth token required by NEKO_IOCTL_AUTH");

static bool neko_verbose;
module_param(neko_verbose, bool, 0644);
MODULE_PARM_DESC(neko_verbose, "log every ioctl (default off, noisy)");

#define rvdbg(fmt, ...)                                   \
	do {                                              \
		if (neko_verbose)                          \
			pr_info(fmt, ##__VA_ARGS__);      \
	} while (0)

static dev_t neko_devno;
static struct cdev neko_cdev;
static struct class *neko_class;
static struct device *neko_device;
static bool neko_torn_down; /* set by HIDE lockdown; guards exit path */

/* Copy to/from a pid's address space. Returns bytes moved or -errno. */
static long neko_xfer(pid_t pid, unsigned long addr, void __user *ubuf,
		     size_t len, bool write)
{
	struct task_struct *task;
	void *kbuf;
	size_t done = 0;
	long ret = 0;
	/* Same flags ptrace uses: FOLL_FORCE lets root read --x pages and
	 * patch r-x code (COW break via copy_to_user_page, icache-safe). */
	unsigned int gup = FOLL_FORCE | (write ? FOLL_WRITE : 0);

	if (!len || !ubuf)
		return -EINVAL;
	task = get_pid_task(find_vpid(pid), PIDTYPE_PID);
	if (!task)
		return -ESRCH;
	kbuf = kmalloc(NEKO_CHUNK, GFP_KERNEL);
	if (!kbuf) {
		ret = -ENOMEM;
		goto out_task;
	}
	while (done < len) {
		size_t n = min_t(size_t, len - done, NEKO_CHUNK);
		int rc;

		if (write &&
		    copy_from_user(kbuf, (char __user *)ubuf + done, n)) {
			ret = done ? (long)done : -EFAULT;
			goto out_free;
		}
		rc = access_process_vm(task, addr + done, kbuf, n, gup);
		if (rc <= 0) {
			ret = done ? (long)done : -EIO;
			goto out_free;
		}
		if (!write &&
		    copy_to_user((char __user *)ubuf + done, kbuf, rc)) {
			ret = done ? (long)done : -EFAULT;
			goto out_free;
		}
		done += rc;
		if ((size_t)rc < n)
			break; /* short range (unmapped hole), keep partial */
	}
	ret = (long)done;
out_free:
	kfree(kbuf);
out_task:
	put_task_struct(task);
	return ret;
}

/* True when task's cmdline (argv[0]) equals `want`. Falls back to comm. */
static bool neko_task_cmdline_is(struct task_struct *task, const char *want)
{
	struct mm_struct *mm;
	unsigned long arg_start, arg_len;
	char buf[NEKO_PKG_MAX];
	size_t want_len;
	int rc;

	want_len = strnlen(want, NEKO_PKG_MAX);
	if (!want_len || want_len >= NEKO_PKG_MAX)
		return false;

	mm = get_task_mm(task);
	if (!mm)
		goto comm_fallback;
	down_read(&mm->mmap_sem);
	arg_start = mm->arg_start;
	arg_len = (mm->arg_end > arg_start) ? mm->arg_end - arg_start : 0;
	up_read(&mm->mmap_sem);
	if (!arg_start || !arg_len) {
		mmput(mm);
		goto comm_fallback;
	}
	if (arg_len >= sizeof(buf))
		arg_len = sizeof(buf) - 1;
	memset(buf, 0, sizeof(buf));
	rc = access_process_vm(task, arg_start, buf, arg_len, FOLL_FORCE);
	mmput(mm);
	if (rc <= 0)
		goto comm_fallback;
	buf[sizeof(buf) - 1] = '\0';
	return strncmp(buf, want, want_len) == 0 && buf[want_len] == '\0';

comm_fallback: {
	char comm[TASK_COMM_LEN];

	get_task_comm(comm, task);
	return want_len < sizeof(comm) && strcmp(comm, want) == 0;
}
}

/*
 * Find a pid by full process name. Two passes: snapshot pids under RCU
 * (no sleeping there), then sleepable cmdline reads per pid. Verifies the
 * cmdline after lookup, so pid reuse between passes cannot mismatch.
 */
static long neko_find_pid(const char *name, pid_t *out)
{
	pid_t *pids;
	struct task_struct *p;
	int i, n = 0;
	long ret = -ESRCH;

	pids = kmalloc_array(NEKO_PID_SCAN_MAX, sizeof(*pids), GFP_KERNEL);
	if (!pids)
		return -ENOMEM;
	rcu_read_lock();
	for_each_process(p) {
		if (p->flags & PF_KTHREAD)
			continue;
		if (n >= NEKO_PID_SCAN_MAX)
			break;
		pids[n++] = task_pid_nr(p);
	}
	rcu_read_unlock();

	for (i = 0; i < n; i++) {
		struct task_struct *task =
			get_pid_task(find_vpid(pids[i]), PIDTYPE_PID);

		if (!task)
			continue;
		if (neko_task_cmdline_is(task, name)) {
			*out = pids[i];
			ret = 0;
			put_task_struct(task);
			break;
		}
		put_task_struct(task);
	}
	kfree(pids);
	return ret;
}

/* First vma start whose file path contains `substr` (maps equivalent).
 * Skips standalone whole-file mappings: some games (AoV/RoV) map the full
 * .so at a lower VA as a decoy; the real image base is the last vm_pgoff==0
 * vma seen before the file's executable vma. */
static long neko_module_base(pid_t pid, const char *substr, u64 *out)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	char *kpage;
	long ret;
	unsigned long last_off0 = 0;
	bool have_exec = false;

	task = get_pid_task(find_vpid(pid), PIDTYPE_PID);
	if (!task)
		return -ESRCH;
	mm = get_task_mm(task);
	if (!mm) {
		ret = -ESRCH;
		goto out_task;
	}
	kpage = (char *)__get_free_page(GFP_KERNEL);
	if (!kpage) {
		ret = -ENOMEM;
		goto out_mm;
	}
	ret = -ENOENT;
	down_read(&mm->mmap_sem);
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		char *path;

		if (!vma->vm_file)
			continue;
		path = d_path(&vma->vm_file->f_path, kpage, PAGE_SIZE);
		if (IS_ERR(path))
			continue;
		if (!strstr(path, substr))
			continue;
		if (vma->vm_pgoff == 0)
			last_off0 = vma->vm_start;
		if (vma->vm_flags & VM_EXEC) {
			if (last_off0) {
				*out = last_off0;
				ret = 0;
			}
			have_exec = true;
			break;
		}
	}
	if (ret && !have_exec && last_off0) {
		/* no exec vma matched (odd); fall back to first match */
		*out = last_off0;
		ret = 0;
	}
	up_read(&mm->mmap_sem);
	free_page((unsigned long)kpage);
out_mm:
	mmput(mm);
out_task:
	put_task_struct(task);
	return ret;
}

static void neko_hide_module(void)
{
#ifdef MODULE
	/* Unlink from /proc/modules and drop /sys/module/neko*. Open fds
	 * keep working; only new discovery breaks. */
	if (!list_empty(&THIS_MODULE->list))
		list_del_init(&THIS_MODULE->list);
	kobject_del(&THIS_MODULE->mkobj.kobj);
#else
	/* Built-in: nothing to unlink, and nothing in lsmod from a .ko. */
#endif
}

static void neko_lockdown_device(void)
{
	if (neko_torn_down)
		return;
	neko_torn_down = true;
	if (neko_device) {
		device_destroy(neko_class, neko_devno);
		neko_device = NULL;
	}
	if (neko_class) {
		class_destroy(neko_class);
		neko_class = NULL;
	}
	cdev_del(&neko_cdev);
	unregister_chrdev_region(neko_devno, 1);
}

static long neko_do_batch(struct neko_batch __user *ub, bool write)
{
	struct neko_batch b;
	struct neko_batch_entry *ents;
	u32 i;

	if (copy_from_user(&b, ub, sizeof(b)))
		return -EFAULT;
	if (!b.count || b.count > NEKO_BATCH_MAX || !b.entries)
		return -EINVAL;
	ents = memdup_user((void __user *)(uintptr_t)b.entries,
			   b.count * sizeof(*ents));
	if (IS_ERR(ents))
		return PTR_ERR(ents);
	for (i = 0; i < b.count; i++) {
		long rc;

		if (!ents[i].len || ents[i].len > NEKO_RW_MAX || !ents[i].buf) {
			kfree(ents);
			return -EINVAL;
		}
		rc = neko_xfer(b.pid, (unsigned long)ents[i].addr,
			      (void __user *)(uintptr_t)ents[i].buf,
			      (size_t)ents[i].len, write);
		if (rc < 0 || (size_t)rc != ents[i].len) {
			b.count = i; /* report how many fully completed */
			kfree(ents);
			if (copy_to_user(ub, &b, sizeof(b)))
				return -EFAULT;
			return -EIO;
		}
	}
	kfree(ents);
	return 0;
}

static long neko_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	void __user *uarg = (void __user *)arg;

	if (cmd == NEKO_IOCTL_PING) {
		__u32 v = NEKO_DRV_VERSION;

		if (copy_to_user(uarg, &v, sizeof(v)))
			return -EFAULT;
		return 0;
	}
	if (cmd == NEKO_IOCTL_AUTH) {
		__u64 tok;

		if (copy_from_user(&tok, uarg, sizeof(tok)))
			return -EFAULT;
		if (tok != neko_token)
			return -EACCES;
		filp->private_data = (void *)1;
		return 0;
	}
	if (!filp->private_data)
		return -EACCES;
	if (!capable(CAP_SYS_PTRACE))
		return -EPERM;

	switch (cmd) {
	case NEKO_IOCTL_READ:
	case NEKO_IOCTL_WRITE: {
		struct neko_rw rw;
		long rc;

		if (copy_from_user(&rw, uarg, sizeof(rw)))
			return -EFAULT;
		if (!rw.len || rw.len > NEKO_RW_MAX || !rw.buf)
			return -EINVAL;
		rvdbg("xfer pid=%d addr=%llx len=%llu %s\n", rw.pid,
		      (unsigned long long)rw.addr,
		      (unsigned long long)rw.len,
		      cmd == NEKO_IOCTL_WRITE ? "W" : "R");
		rc = neko_xfer(rw.pid, (unsigned long)rw.addr,
			      (void __user *)(uintptr_t)rw.buf, (size_t)rw.len,
			      cmd == NEKO_IOCTL_WRITE);
		if (rc < 0)
			return rc;
		rw.len = (u64)rc;
		if (copy_to_user(uarg, &rw, sizeof(rw)))
			return -EFAULT;
		return 0;
	}
	case NEKO_IOCTL_READ_BATCH:
	case NEKO_IOCTL_WRITE_BATCH:
		return neko_do_batch(uarg, cmd == NEKO_IOCTL_WRITE_BATCH);
	case NEKO_IOCTL_FIND_PID: {
		struct neko_find_pid fp;
		pid_t pid;
		long rc;

		if (copy_from_user(&fp, uarg, sizeof(fp)))
			return -EFAULT;
		fp.name[sizeof(fp.name) - 1] = '\0';
		rc = neko_find_pid(fp.name, &pid);
		if (rc)
			return rc;
		fp.pid = pid;
		if (copy_to_user(uarg, &fp, sizeof(fp)))
			return -EFAULT;
		return 0;
	}
	case NEKO_IOCTL_MODULE_BASE: {
		struct neko_modbase mb;
		u64 base;
		long rc;

		if (copy_from_user(&mb, uarg, sizeof(mb)))
			return -EFAULT;
		mb.name[sizeof(mb.name) - 1] = '\0';
		rc = neko_module_base(mb.pid, mb.name, &base);
		if (rc)
			return rc;
		mb.base = base;
		if (copy_to_user(uarg, &mb, sizeof(mb)))
			return -EFAULT;
		return 0;
	}
	case NEKO_IOCTL_HIDE: {
		__u32 mode;

		if (copy_from_user(&mode, uarg, sizeof(mode)))
			return -EFAULT;
		if (mode > 1)
			return -EINVAL;
		neko_hide_module();
		if (mode == 1)
			neko_lockdown_device();
		pr_info("hide mode %u applied\n", mode);
		return 0;
	}
	default:
		return -ENOTTY;
	}
}

static int neko_open(struct inode *ino, struct file *filp)
{
	if (!capable(CAP_SYS_PTRACE))
		return -EPERM;
	filp->private_data = NULL; /* must AUTH before use */
	return 0;
}

static int neko_release(struct inode *ino, struct file *filp)
{
	filp->private_data = NULL;
	return 0;
}

static const struct file_operations neko_fops = {
	.owner = THIS_MODULE,
	.open = neko_open,
	.release = neko_release,
	.unlocked_ioctl = neko_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = neko_ioctl,
#endif
	.llseek = noop_llseek,
};

static int __init neko_init(void)
{
	int rc;

	rc = alloc_chrdev_region(&neko_devno, 0, 1, neko_devname);
	if (rc)
		return rc;
	cdev_init(&neko_cdev, &neko_fops);
	neko_cdev.owner = THIS_MODULE;
	rc = cdev_add(&neko_cdev, neko_devno, 1);
	if (rc)
		goto err_region;
	neko_class = class_create(THIS_MODULE, neko_devname);
	if (IS_ERR(neko_class)) {
		rc = PTR_ERR(neko_class);
		neko_class = NULL;
		goto err_cdev;
	}
	neko_device =
		device_create(neko_class, NULL, neko_devno, NULL, "%s", neko_devname);
	if (IS_ERR(neko_device)) {
		rc = PTR_ERR(neko_device);
		neko_device = NULL;
		goto err_class;
	}
	pr_info("ready as /dev/%s (major %d)\n", neko_devname,
		MAJOR(neko_devno));
	return 0;

err_class:
	class_destroy(neko_class);
	neko_class = NULL;
err_cdev:
	cdev_del(&neko_cdev);
err_region:
	unregister_chrdev_region(neko_devno, 1);
	return rc;
}

static void __exit neko_exit(void)
{
	if (!neko_torn_down) {
		if (neko_device)
			device_destroy(neko_class, neko_devno);
		if (neko_class)
			class_destroy(neko_class);
		cdev_del(&neko_cdev);
		unregister_chrdev_region(neko_devno, 1);
	}
	pr_info("unloaded\n");
}

module_init(neko_init);
module_exit(neko_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Neko-CIO");
MODULE_DESCRIPTION("Neko stealth process-memory driver");
MODULE_VERSION("1.0");
