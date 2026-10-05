// SPDX-License-Identifier: GPL-2.0
/*
 * Neko stealth process-memory driver - shared userspace/kernel ABI.
 *
 * Included by drivers/neko/neko_drv.c in the kernel tree AND by the
 * userspace daemon (copy this file next to neko_kdrv.h, or add
 * -Ikernel/drivers/neko to the daemon build).
 */
#ifndef _NEKO_UAPI_H
#define _NEKO_UAPI_H

#ifdef __KERNEL__
#include <linux/ioctl.h>
#include <linux/types.h>
#else
#include <stdint.h>
#include <sys/ioctl.h>
/* __u32/__u64/__s32 come from here on glibc and the Android NDK alike. */
#include <linux/types.h>
#endif

#define NEKO_DRV_VERSION 1

/* Default /dev node (overridable via CONFIG_NEKO_DEV_NAME / devname param). */
#define NEKO_DEFAULT_DEV "nekodrv"

/*
 * Default auth token. CHANGE THIS before building your kernel, and use the
 * same value in the daemon. Anyone with the token + root can read/write any
 * process, so never ship the default.
 */
#define NEKO_DEFAULT_TOKEN 0x4E454B4F44525631ULL /* "NEKODRV1" */

#define NEKO_IOC_MAGIC 0x51

#define NEKO_PKG_MAX 128
#define NEKO_NAME_MAX 64
#define NEKO_RW_MAX (64u * 1024u) /* per-request cap, client chunks above this */
#define NEKO_BATCH_MAX 16

/* Read/write one range. len: in=requested, out=transferred. buf = user ptr. */
struct neko_rw {
	__s32 pid;
	__u32 reserved;
	__u64 addr;
	__u64 len;
	__u64 buf;
};

struct neko_batch_entry {
	__u64 addr;
	__u64 len;
	__u64 buf; /* user ptr for this entry */
};

/* entries = user ptr to array of `count`. On -EIO, count = # completed. */
struct neko_batch {
	__s32 pid;
	__u32 count;
	__u64 entries;
};

/* name = full cmdline (e.g. "com.garena.game.kgth"). pid is the output. */
struct neko_find_pid {
	char name[NEKO_PKG_MAX];
	__s32 pid;
	__u32 reserved;
};

/* name = maps pathname substring (e.g. "libil2cpp.so"). base is the output. */
struct neko_modbase {
	__s32 pid;
	__u32 reserved;
	char name[NEKO_NAME_MAX];
	__u64 base;
};

#define NEKO_IOCTL_AUTH _IOW(NEKO_IOC_MAGIC, 0x01, __u64)
#define NEKO_IOCTL_PING _IOR(NEKO_IOC_MAGIC, 0x02, __u32)
#define NEKO_IOCTL_READ _IOWR(NEKO_IOC_MAGIC, 0x10, struct neko_rw)
#define NEKO_IOCTL_WRITE _IOWR(NEKO_IOC_MAGIC, 0x11, struct neko_rw)
#define NEKO_IOCTL_READ_BATCH _IOW(NEKO_IOC_MAGIC, 0x12, struct neko_batch)
#define NEKO_IOCTL_WRITE_BATCH _IOW(NEKO_IOC_MAGIC, 0x13, struct neko_batch)
#define NEKO_IOCTL_FIND_PID _IOWR(NEKO_IOC_MAGIC, 0x20, struct neko_find_pid)
#define NEKO_IOCTL_MODULE_BASE _IOWR(NEKO_IOC_MAGIC, 0x21, struct neko_modbase)

/*
 * Hide the driver. mode 0 = unlink module from /proc/modules + sysfs
 * (loadable-module builds only; built-in is hidden by nature). mode 1 =
 * mode 0 plus tear down the /dev node and chrdev registration; already-open
 * fds keep working but nothing can open it again until reboot/reload.
 */
#define NEKO_IOCTL_HIDE _IOW(NEKO_IOC_MAGIC, 0x30, __u32)

#endif /* _NEKO_UAPI_H */
