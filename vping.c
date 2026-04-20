// SPDX-License-Identifier: GPL-2.0
/*
 * vping - virtual network interface that replies to ICMP echo requests
 *         on an IPv4 address configured via procfs.
 */

#include <linux/etherdevice.h>
#include <linux/fs.h>
#include <linux/icmp.h>
#include <linux/if_arp.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <net/arp.h>

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

static void vping_send_arp_reply(struct sk_buff *req, __be32 our_ip,
				 __be32 sender_ip, const unsigned char *sender_hw)
{
	struct net_device *dev = req->dev;
	struct sk_buff *reply;

	reply = arp_create(ARPOP_REPLY, ETH_P_ARP,
			   sender_ip,        /* target IP    (requester's IP)  */
			   dev,              /* egress device                  */
			   our_ip,           /* sender IP    (our IP)          */
			   sender_hw,        /* dest HW      (requester's MAC) */
			   dev->dev_addr,    /* sender HW    (NIC's own MAC)   */
			   sender_hw);       /* target HW    (requester's MAC) */
	if (!reply) {
		pr_warn("%s: arp_create failed\n", DRV_NAME);
		return;
	}

	dev_queue_xmit(reply);
}

static int vping_arp_rcv(struct sk_buff *skb, struct net_device *dev,
			 struct packet_type *pt, struct net_device *orig_dev)
{
	const struct arphdr *arp;
	const unsigned char *p;
	unsigned char sha[ETH_ALEN];
	__be32 sip, tip;
	__be32 our_ip;

	our_ip = READ_ONCE(vping_ip);
	if (!our_ip)
		goto out;

	if (!pskb_may_pull(skb, sizeof(*arp)))
		goto out;
	arp = arp_hdr(skb);

	if (arp->ar_hrd != htons(ARPHRD_ETHER) ||
	    arp->ar_pro != htons(ETH_P_IP) ||
	    arp->ar_hln != ETH_ALEN ||
	    arp->ar_pln != 4 ||
	    arp->ar_op  != htons(ARPOP_REQUEST))
		goto out;

	if (!pskb_may_pull(skb, sizeof(*arp) + 2 * (ETH_ALEN + 4)))
		goto out;
	arp = arp_hdr(skb);
	p = (const unsigned char *)(arp + 1);
	memcpy(sha, p, ETH_ALEN);
	memcpy(&sip, p + ETH_ALEN, 4);
	memcpy(&tip, p + ETH_ALEN + 4 + ETH_ALEN, 4);

	if (tip != our_ip)
		goto out;

	pr_info("%s: ARP reply for %pI4 -> %pM, to %pI4 on %s\n",
		DRV_NAME, &tip, skb->dev->dev_addr, &sip, skb->dev->name);
	vping_send_arp_reply(skb, our_ip, sip, sha);

out:
	consume_skb(skb);
	return NET_RX_SUCCESS;
}

static int vping_ip_rcv(struct sk_buff *skb, struct net_device *dev,
			struct packet_type *pt, struct net_device *orig_dev)
{
	const struct iphdr *iph;
	const struct icmphdr *icmph;
	__be32 our_ip;
	unsigned int ihl;

	our_ip = READ_ONCE(vping_ip);
	if (!our_ip)
		goto out;

	if (!pskb_may_pull(skb, sizeof(*iph)))
		goto out;
	iph = ip_hdr(skb);

	if (iph->daddr != our_ip || iph->protocol != IPPROTO_ICMP)
		goto out;

	ihl = iph->ihl * 4;
	if (!pskb_may_pull(skb, ihl + sizeof(*icmph)))
		goto out;
	iph = ip_hdr(skb);
	icmph = (const struct icmphdr *)((const u8 *)iph + ihl);

	if (icmph->type != ICMP_ECHO)
		goto out;

	pr_info("%s: ICMP echo for %pI4 from %pI4 on %s\n",
		DRV_NAME, &iph->daddr, &iph->saddr, skb->dev->name);

out:
	consume_skb(skb);
	return NET_RX_SUCCESS;
}

static struct packet_type vping_arp_pt __read_mostly = {
	.type = cpu_to_be16(ETH_P_ARP),
	.func = vping_arp_rcv,
};

static struct packet_type vping_ip_pt __read_mostly = {
	.type = cpu_to_be16(ETH_P_IP),
	.func = vping_ip_rcv,
};

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

	dev_add_pack(&vping_arp_pt);
	dev_add_pack(&vping_ip_pt);

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
	dev_remove_pack(&vping_ip_pt);
	dev_remove_pack(&vping_arp_pt);
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
MODULE_VERSION("0.5.0");
