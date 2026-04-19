// SPDX-License-Identifier: GPL-2.0
/*
 * vping - virtual network interface that replies to ICMP echo requests
 *         on an IPv4 address configured via procfs.
 */

#include <linux/fs.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#define DRV_NAME "vping"

/* "255.255.255.255\n\0" = 17 bytes; round up for comfort. */
#define VPING_PROC_BUF_SIZE 32

union v4_addr {
	u8     bytes[4];
	__be32 addr;
};

static __be32 vping_ip;
static struct proc_dir_entry *vping_proc;

static ssize_t vping_proc_read(struct file *file, char __user *buf,
			       size_t len, loff_t *offset)
{
	char out[VPING_PROC_BUF_SIZE];
	__be32 cur_ip;
	size_t total_len;

	cur_ip = READ_ONCE(vping_ip);
	total_len = scnprintf(out, sizeof(out), "%pI4\n", &cur_ip);
	return simple_read_from_buffer(buf, len, offset, out, total_len);
}

static ssize_t vping_proc_write(struct file *file, const char __user *buf,
				size_t len, loff_t *offset)
{
	char in[VPING_PROC_BUF_SIZE];
	char *trimmed;
	union v4_addr ip;

	if (len == 0 || len >= sizeof(in))
		return -EINVAL;

	if (copy_from_user(in, buf, len))
		return -EFAULT;
	in[len] = '\0';

	trimmed = strim(in);
	if (!in4_pton(trimmed, -1, ip.bytes, -1, NULL)) {
		pr_warn("%s: invalid IPv4 address: '%s'\n", DRV_NAME, trimmed);
		return -EINVAL;
	}

	if (ipv4_is_zeronet(ip.addr) ||
	    ipv4_is_lbcast(ip.addr) ||
	    ipv4_is_multicast(ip.addr) ||
		ipv4_is_loopback(ip.addr)) {
		pr_warn("%s: refusing non-unicast address %pI4\n",
			DRV_NAME, &(ip.addr));
		return -EINVAL;
	}

	WRITE_ONCE(vping_ip, ip.addr);
	pr_info("%s: address set to %pI4\n", DRV_NAME, &(ip.addr));
	return len;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops vping_proc_ops = {
	.proc_read  = vping_proc_read,
	.proc_write = vping_proc_write,
};
#else
static const struct file_operations vping_proc_ops = {
	.owner = THIS_MODULE,
	.read  = vping_proc_read,
	.write = vping_proc_write,
};
#endif

static int __init vping_init(void)
{
	vping_proc = proc_create(DRV_NAME, 0644, NULL, &vping_proc_ops);
	if (!vping_proc) {
		pr_err("%s: failed to create /proc/%s\n", DRV_NAME, DRV_NAME);
		return -ENOMEM;
	}

	pr_info("%s: loaded, /proc/%s created\n", DRV_NAME, DRV_NAME);
	return 0;
}

static void __exit vping_exit(void)
{
	proc_remove(vping_proc);
	pr_info("%s: unloaded\n", DRV_NAME);
}

module_init(vping_init);
module_exit(vping_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrey Misyurov <andrey.misyurov@gmail.com>");
MODULE_DESCRIPTION("vping: configurable IPv4 address via /proc/vping (read/write)");
MODULE_VERSION("0.2.0");
