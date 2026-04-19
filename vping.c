// SPDX-License-Identifier: GPL-2.0
/*
 * vping - virtual network interface that replies to ICMP echo requests
 *         on an IPv4 address configured via procfs.
 */

#include <linux/etherdevice.h>
#include <linux/fs.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
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
static struct net_device *vping_dev;

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

static int vping_ndo_open(struct net_device *dev)
{
	netif_start_queue(dev);
	return 0;
}

static int vping_ndo_stop(struct net_device *dev)
{
	netif_stop_queue(dev);
	return 0;
}

static netdev_tx_t vping_ndo_start_xmit(struct sk_buff *skb,
				       struct net_device *dev)
{
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

static const struct net_device_ops vping_netdev_ops = {
	.ndo_open	= vping_ndo_open,
	.ndo_stop	= vping_ndo_stop,
	.ndo_start_xmit	= vping_ndo_start_xmit,
};

static void vping_setup(struct net_device *dev)
{
	ether_setup(dev);
	dev->netdev_ops = &vping_netdev_ops;
	dev->flags |= IFF_NOARP;
	eth_hw_addr_random(dev);
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
	int err;

	vping_proc = proc_create(DRV_NAME, 0644, NULL, &vping_proc_ops);
	if (!vping_proc) {
		pr_err("%s: failed to create /proc/%s\n", DRV_NAME, DRV_NAME);
		return -ENOMEM;
	}

	vping_dev = alloc_netdev(0, "vping%d", NET_NAME_ENUM, vping_setup);
	if (!vping_dev) {
		pr_err("%s: alloc_netdev failed\n", DRV_NAME);
		err = -ENOMEM;
		goto err_proc;
	}

	err = register_netdev(vping_dev);
	if (err) {
		pr_err("%s: register_netdev failed: %d\n", DRV_NAME, err);
		goto err_free;
	}

	pr_info("%s: loaded, /proc/%s and %s ready\n",
		DRV_NAME, DRV_NAME, vping_dev->name);
	return 0;

err_free:
	free_netdev(vping_dev);
	vping_dev = NULL;
err_proc:
	proc_remove(vping_proc);
	return err;
}

static void __exit vping_exit(void)
{
	unregister_netdev(vping_dev);
	free_netdev(vping_dev);
	proc_remove(vping_proc);
	pr_info("%s: unloaded\n", DRV_NAME);
}

module_init(vping_init);
module_exit(vping_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrey Misyurov <andrey.misyurov@gmail.com>");
MODULE_DESCRIPTION("vping: virtual netdev with IPv4 configured via /proc/vping");
MODULE_VERSION("0.3.0");
