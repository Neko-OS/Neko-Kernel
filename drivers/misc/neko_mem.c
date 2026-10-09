// SPDX-License-Identifier: GPL-2.0
//
// /dev/neko_mem - kernel-side process memory read/write.
//
// Goes through access_process_vm() (the internal API behind /proc/pid/mem),
// so there is no ptrace attach, no open fd on the target's mem file, no
// process_vm_readv syscall - nothing a userspace scanner can observe on the
// target. The only artifacts are ours: the device node + the module itself.
//
// Built into the kernel (CONFIG_NEKO_MEM=y); /dev/neko_mem appears at boot.
// Use from userspace with: neko -m kernel

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/pid.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sched/mm.h>
#include <linux/version.h>

#define NEKO_DEV_NAME "neko_mem" /* rename for less obvious /dev entry */

/* session key: first INIT ioctl sets it, every other ioctl must carry it.
 * not a security boundary - just makes the device dead to blind probing. */
static u64 neko_key;

struct neko_rw {
	__u64 key;
	__u32 pid;
	__u64 addr;  /* target address */
	__u64 buf;   /* userspace buffer in *our* process */
	__u64 size;
};

#define NEKO_IOC_MAGIC  'k'
#define NEKO_IOC_INIT   _IOW(NEKO_IOC_MAGIC, 0, __u64)
#define NEKO_IOC_READ   _IOWR(NEKO_IOC_MAGIC, 1, struct neko_rw)
#define NEKO_IOC_WRITE  _IOWR(NEKO_IOC_MAGIC, 2, struct neko_rw)
#define NEKO_IOC_READV  _IOWR(NEKO_IOC_MAGIC, 4, struct neko_rwv)
#define NEKO_IOC_MODULE _IOWR(NEKO_IOC_MAGIC, 5, struct neko_mod)

/* batch read: one ioctl, N remote regions -> one flat userspace buffer.
 * fewer context switches, no per-region syscall pattern to flag. */
struct neko_rwv {
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
struct neko_mod {
	__u64 key;
	__u32 pid;
	__u64 base;    /* out: vm_start of first vma whose file matches name */
	char name[64]; /* basename substring, e.g. "libil2cpp.so" */
};

static inline bool key_ok(u64 k)
{
	return k && k == READ_ONCE(neko_key);
}

#define NEKO_MAX_RW  (1 << 20)
#define NEKO_MAX_VEC 256

static struct task_struct *task_by_pid(u32 pid)
{
	struct pid *p = find_get_pid(pid);
	struct task_struct *t;

	if (!p)
		return NULL;
	t = get_pid_task(p, PIDTYPE_PID);
	put_pid(p);
	return t;
}

static long neko_rw(struct neko_rw *rw, bool write)
{
	struct task_struct *tsk;
	char *kbuf;
	long ret = -EFAULT;
	unsigned int flags = FOLL_FORCE;

	if (!key_ok(rw->key))
		return -EACCES;
	if (!rw->size || rw->size > NEKO_MAX_RW)
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

	tsk = task_by_pid(rw->pid);
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
static long neko_rwv(struct neko_rwv *r)
{
	struct task_struct *tsk;
	u64 *addrs, *sizes;
	char *kbuf;
	u32 i;
	u64 total = 0, off = 0;
	long done = 0;

	if (!key_ok(r->key))
		return -EACCES;
	if (!r->count || r->count > NEKO_MAX_VEC ||
	    r->buf_size > NEKO_MAX_RW)
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

	tsk = task_by_pid(r->pid);
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
static long neko_mod(struct neko_mod *m)
{
	struct task_struct *tsk;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	long ret = -ENOENT;

	if (!key_ok(m->key))
		return -EACCES;
	m->name[sizeof(m->name) - 1] = 0;

	tsk = task_by_pid(m->pid);
	if (!tsk)
		return -ESRCH;
	mm = get_task_mm(tsk);
	put_task_struct(tsk);
	if (!mm)
		return -ESRCH;

	down_read(&mm->mmap_sem); /* mmap_read_lock() on 5.8+ */
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
	up_read(&mm->mmap_sem);
	mmput(mm);
	return ret;
}

static long neko_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct neko_rw rw;
	struct neko_rwv rwv;
	struct neko_mod mod;
	u64 key;

	switch (cmd) {
	case NEKO_IOC_INIT:
		if (copy_from_user(&key, (void __user *)arg, sizeof(key)))
			return -EFAULT;
		WRITE_ONCE(neko_key, key);
		return 0;
	case NEKO_IOC_READ:
	case NEKO_IOC_WRITE:
		if (copy_from_user(&rw, (void __user *)arg, sizeof(rw)))
			return -EFAULT;
		return neko_rw(&rw, cmd == NEKO_IOC_WRITE);
	case NEKO_IOC_READV:
		if (copy_from_user(&rwv, (void __user *)arg, sizeof(rwv)))
			return -EFAULT;
		return neko_rwv(&rwv);
	case NEKO_IOC_MODULE:
		if (copy_from_user(&mod, (void __user *)arg, sizeof(mod)))
			return -EFAULT;
		if (neko_mod(&mod))
			return -ENOENT;
		if (copy_to_user((void __user *)arg, &mod, sizeof(mod)))
			return -EFAULT;
		return 0;
	default:
		return -ENOTTY;
	}
}

static const struct file_operations neko_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = neko_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = neko_ioctl,
#endif
};

static struct miscdevice neko_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = NEKO_DEV_NAME,
	.fops = &neko_fops,
	.mode = 0600, /* root only */
};

static int __init neko_mem_init(void)
{
	return misc_register(&neko_dev);
}

static void __exit neko_mem_exit(void)
{
	misc_deregister(&neko_dev);
}

module_init(neko_mem_init);
module_exit(neko_mem_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("kernel-side process memory access");
