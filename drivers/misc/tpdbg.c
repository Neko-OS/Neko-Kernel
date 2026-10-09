// SPDX-License-Identifier: GPL-2.0
//
// touchpanel debug proc node - kernel-side memory read/write.
//
// Goes through access_process_vm() (the internal API behind /proc/pid/mem),
// so there is no ptrace attach, no open fd on the target's mem file, no
// process_vm_readv syscall - nothing a userspace scanner can observe on the
// target. The only artifacts are ours: the device node + the module itself.
//
// Built into the kernel (CONFIG_TPDBG=y); /proc/<random 8-char>
// appears at boot. Use from userspace with: neko -m kernel

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/pid.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/version.h>

#pragma message("tpdbg: touchpanel debug proc node")
/* random 8-char alnum procfs name per boot (china-driver trick): name
 * signatures can't match, and the entry blends into the /proc noise.
 * userspace finds it by probing candidates with the INIT ioctl. */
static char tpd_name[9];

/* session key: first INIT ioctl sets it, every other ioctl must carry it.
 * not a security boundary - just makes the device dead to blind probing. */
static u64 tpd_key;

struct tpd_rw {
	__u64 key;
	__u32 pid;
	__u64 addr;  /* target address */
	__u64 buf;   /* userspace buffer in *our* process */
	__u64 size;
};

#define TPD_IOC_MAGIC  'k'
#define TPD_IOC_INIT   _IOW(TPD_IOC_MAGIC, 0, __u64)
#define TPD_IOC_READ   _IOWR(TPD_IOC_MAGIC, 1, struct tpd_rw)
#define TPD_IOC_WRITE  _IOWR(TPD_IOC_MAGIC, 2, struct tpd_rw)
#define TPD_IOC_READV  _IOWR(TPD_IOC_MAGIC, 4, struct tpd_rwv)
#define TPD_IOC_MODULE _IOWR(TPD_IOC_MAGIC, 5, struct tpd_mod)
#define TPD_IOC_DEL    _IOW(TPD_IOC_MAGIC, 6, __u64) /* unlink proc node */

/* batch read: one ioctl, N remote regions -> one flat userspace buffer.
 * fewer context switches, no per-region syscall pattern to flag. */
struct tpd_rwv {
	__u64 key;
	__u32 pid;
	__u32 count;
	__u64 addrs; /* u64 array of remote addrs    */
	__u64 sizes; /* u64 array of remote sizes    */
	__u64 buf;   /* user buffer, sum(sizes)      */
	__u64 buf_size;
};

/* module base lookup: kernel walks the vma list itself so userspace
 * never has to open /proc/pid/maps at all. */
struct tpd_mod {
	__u64 key;
	__u32 pid;
	__u64 base;    /* out: vm_start of first vma whose file matches name */
	char name[64]; /* basename substring, e.g. "libil2cpp.so" */
};

static inline bool tpd_keyok(u64 k)
{
	return k && k == READ_ONCE(tpd_key);
}

#define TPD_MAX_RW  (1 << 20)
#define TPD_MAX_VEC 256

static struct task_struct *tpd_task(u32 pid)
{
	struct pid *p = find_get_pid(pid);
	struct task_struct *t;

	if (!p)
		return NULL;
	t = get_pid_task(p, PIDTYPE_PID);
	put_pid(p);
	return t;
}

static long tpd_rw(struct tpd_rw *rw, bool write)
{
	struct task_struct *tsk;
	char *kbuf;
	long ret = -EFAULT;
	unsigned int flags = FOLL_FORCE;

	if (!tpd_keyok(rw->key))
		return -EACCES;
	if (!rw->size || rw->size > TPD_MAX_RW)
		return -EINVAL;

	kbuf = kvzalloc(rw->size, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	if (write) {
		flags |= FOLL_WRITE;
		if (copy_from_user(kbuf, (void __user *)rw->buf, rw->size)) {
			ret = -EFAULT;
			goto out;
		}
	}

	tsk = tpd_task(rw->pid);
	if (!tsk) { ret = -ESRCH; goto out; }

	ret = access_process_vm(tsk, rw->addr, kbuf, rw->size, flags);
	put_task_struct(tsk);

	if (!write && ret > 0 &&
	    copy_to_user((void __user *)rw->buf, kbuf, ret))
		ret = -EFAULT;

out:
	kvfree(kbuf);
	return ret;
}

/* batch: one task lookup + one copy_to_user for the whole region list */
static long tpd_rwv(struct tpd_rwv *r)
{
	struct task_struct *tsk;
	u64 *addrs, *sizes;
	char *kbuf;
	u32 i;
	u64 total = 0, off = 0;
	long done = 0;

	if (!tpd_keyok(r->key))
		return -EACCES;
	if (!r->count || r->count > TPD_MAX_VEC ||
	    r->buf_size > TPD_MAX_RW)
		return -EINVAL;

	addrs = kcalloc(r->count, sizeof(u64), GFP_KERNEL);
	sizes = kcalloc(r->count, sizeof(u64), GFP_KERNEL);
	if (!addrs || !sizes) { done = -ENOMEM; goto out_vec; }
	if (copy_from_user(addrs, (void __user *)r->addrs,
			   r->count * sizeof(u64)) ||
	    copy_from_user(sizes, (void __user *)r->sizes,
			   r->count * sizeof(u64))) {
		done = -EFAULT;
		goto out_vec;
	}
	for (i = 0; i < r->count; i++) {
		if (!sizes[i]) continue;
		if (total + sizes[i] > r->buf_size) { done = -EINVAL; goto out_vec; }
		total += sizes[i];
	}

	kbuf = kvzalloc(total, GFP_KERNEL);
	if (!kbuf) { done = -ENOMEM; goto out_vec; }

	tsk = tpd_task(r->pid);
	if (!tsk) { done = -ESRCH; goto out_buf; }

	for (i = 0; i < r->count; i++) {
		/* each region lands at its own slot; short/failed read leaves
		 * that slot zeroed so userspace can map offsets 1:1 */
		int n = access_process_vm(tsk, addrs[i], kbuf + off,
					sizes[i], FOLL_FORCE);
		if (n > 0)
			done += n;
		off += sizes[i];
	}
	put_task_struct(tsk);

	if (total > 0 &&
	    copy_to_user((void __user *)r->buf, kbuf, total))
		done = -EFAULT;

out_buf:
	kvfree(kbuf);
out_vec:
	kfree(addrs);
	kfree(sizes);
	return done;
}

/* walk vma list, return vm_start of first file-backed region whose
 * basename contains the requested substring (same order as /proc/maps). */
static long tpd_mod(struct tpd_mod *m)
{
	struct task_struct *tsk;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	long ret = -ENOENT;

	if (!tpd_keyok(m->key))
		return -EACCES;
	m->name[sizeof(m->name) - 1] = 0;

	tsk = tpd_task(m->pid);
	if (!tsk)
		return -ESRCH;
	mm = get_task_mm(tsk);
	put_task_struct(tsk);
	if (!mm)
		return -ESRCH;

	mmap_read_lock(mm); /* mmap_sem on pre-5.8 kernels */
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		const unsigned char *fn;
		if (!vma->vm_file || !vma->vm_file->f_path.dentry)
			continue;
		fn = vma->vm_file->f_path.dentry->d_name.name;
		if (strstr(fn, m->name)) {
			m->base = vma->vm_start;
			ret = 0;
			break;
		}
	}
	mmap_read_unlock(mm);
	mmput(mm);
	return ret;
}

static long tpd_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct tpd_rw rw;
	struct tpd_rwv rwv;
	struct tpd_mod mod;
	u64 key;

	switch (cmd) {
	case TPD_IOC_INIT:
		if (copy_from_user(&key, (void __user *)arg, sizeof(key)))
			return -EFAULT;
		/* first attach wins; idempotent for the same key only */
		if (cmpxchg(&tpd_key, 0, key) && key != tpd_key)
			return -EBUSY;
		return 0;
	case TPD_IOC_DEL:
		if (copy_from_user(&key, (void __user *)arg, sizeof(key)))
			return -EFAULT;
		if (!tpd_keyok(key))
			return -EACCES;
		/* unlink the /proc node; open fds keep working (fops ref) */
		if (tpd_ent) {
			proc_remove(tpd_ent);
			tpd_ent = NULL;
		}
		return 0;
	case TPD_IOC_READ:
	case TPD_IOC_WRITE:
		if (copy_from_user(&rw, (void __user *)arg, sizeof(rw)))
			return -EFAULT;
		return tpd_rw(&rw, cmd == TPD_IOC_WRITE);
	case TPD_IOC_READV:
		if (copy_from_user(&rwv, (void __user *)arg, sizeof(rwv)))
			return -EFAULT;
		return tpd_rwv(&rwv);
	case TPD_IOC_MODULE:
		if (copy_from_user(&mod, (void __user *)arg, sizeof(mod)))
			return -EFAULT;
		if (tpd_mod(&mod))
			return -ENOENT;
		if (copy_to_user((void __user *)arg, &mod, sizeof(mod)))
			return -EFAULT;
		return 0;
	default:
		return -ENOTTY;
	}
}

/* when the client closes, recreate the node and clear the key:
 * hidden while in use, discoverable again for the next run. */
static int tpd_release(struct inode *i, struct file *f)
{
	if (!tpd_ent)
		tpd_ent = proc_create(tpd_name, 0600, NULL, &tpd_fops);
	WRITE_ONCE(tpd_key, 0);
	return 0;
}

static const struct file_operations tpd_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = tpd_ioctl,
	.release = tpd_release,
#ifdef CONFIG_COMPAT
	.compat_ioctl = tpd_ioctl,
#endif
};

static struct proc_dir_entry *tpd_ent;

static int __init tpd_init(void)
{
	static const char alnum[] =
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	u8 r[8];
	int i;

	get_random_bytes(r, sizeof(r));
	tpd_name[0] = alnum[r[0] % 52]; /* letter - never looks like a pid dir */
	for (i = 1; i < 8; i++)
		tpd_name[i] = alnum[r[i] % 62];
	tpd_name[8] = 0;

	/* /proc/<random>, 0600 root-only - no /dev node at all */
	tpd_ent = proc_create(tpd_name, 0600, NULL, &tpd_fops);
	return tpd_ent ? 0 : -ENOMEM;
}

static void __exit tpd_exit(void)
{
	proc_remove(tpd_ent);
}

module_init(tpd_init);
module_exit(tpd_exit);

