/* SPDX-License-Identifier: GPL-3.0-only */
/*
 * Exclusive control node /dev/fluxrs. fluxd holds the fd; close/SIGKILL
 * clears live and published listeners/UIDs so the hook is NF_ACCEPT.
 */
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/atomic.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include "fluxrs.h"

#define FLUXRS_CTL_NAME "fluxrs"

static atomic_t opened = ATOMIC_INIT(0);

static int fluxrs_ctl_open(struct inode *inode, struct file *file)
{
	if (atomic_cmpxchg(&opened, 0, 1) != 0)
		return -EBUSY;
	fluxrs_set_live(true);
	return 0;
}

static int fluxrs_ctl_release(struct inode *inode, struct file *file)
{
	fluxrs_set_live(false);
	atomic_set(&opened, 0);
	return 0;
}

static long fluxrs_ctl_ioctl(struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	struct fluxrs_listeners listeners;
	struct fluxrs_uids *uids;
	struct fluxrs_status status;
	int err;

	(void)file;
	switch (cmd) {
	case FLUXRS_SET_LISTENERS:
		if (copy_from_user(&listeners, (void __user *)arg,
				   sizeof(listeners)))
			return -EFAULT;
		fluxrs_set_listeners(&listeners);
		return 0;
	case FLUXRS_SET_UIDS:
		uids = kmalloc(sizeof(*uids), GFP_KERNEL);
		if (!uids)
			return -ENOMEM;
		if (copy_from_user(uids, (void __user *)arg, sizeof(*uids))) {
			kfree(uids);
			return -EFAULT;
		}
		err = fluxrs_set_uids(uids);
		kfree(uids);
		return err;
	case FLUXRS_CLEAR_UIDS:
		fluxrs_clear_uids();
		return 0;
	case FLUXRS_GET_STATUS:
		fluxrs_get_status(&status);
		if (copy_to_user((void __user *)arg, &status, sizeof(status)))
			return -EFAULT;
		return 0;
	case FLUXRS_SET_BYPASS:
		return fluxrs_set_bypass((void __user *)arg);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations fluxrs_ctl_fops = {
	.owner = THIS_MODULE,
	.open = fluxrs_ctl_open,
	.release = fluxrs_ctl_release,
	.unlocked_ioctl = fluxrs_ctl_ioctl,
	.compat_ioctl = fluxrs_ctl_ioctl,
	.llseek = noop_llseek,
};

static struct miscdevice fluxrs_ctl = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = FLUXRS_CTL_NAME,
	.fops = &fluxrs_ctl_fops,
	.mode = 0600,
};

int fluxrs_ctl_register(void)
{
	return misc_register(&fluxrs_ctl);
}

void fluxrs_ctl_unregister(void)
{
	fluxrs_set_live(false);
	atomic_set(&opened, 0);
	misc_deregister(&fluxrs_ctl);
}
