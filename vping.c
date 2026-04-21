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
#include <linux/rtnetlink.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <net/arp.h>
#include <net/checksum.h>
#include <net/dst.h>
#include <net/net_namespace.h>

#define DRV_NAME "vping"

/* "255.255.255.255\n\0" = 17 bytes; round up for comfort. */
#define VPING_PROC_BUF_SIZE 32

union v4_addr {
	u8     bytes[4];
	__be32 addr;
};

static union v4_addr vping_ip;
static struct proc_dir_entry *vping_proc;
static struct net_device *vping_dev;
static struct net_device *vping_lower_dev;

static char *initial_ip;
module_param_named(ip, initial_ip, charp, 0);
MODULE_PARM_DESC(ip, "Optional initial IPv4 address (e.g. ip=192.168.1.50)");

static char *lower_ifname;
module_param_named(lower_if, lower_ifname, charp, 0);
MODULE_PARM_DESC(lower_if, "Required: lower netdev for rx (e.g. lower_if=enp0s8)");

/* ---------- address helpers ---------- */

static int vping_set_from_str(const char *s)
{
	char buf[VPING_PROC_BUF_SIZE];
	union v4_addr ip;
	size_t n;

	if (!s)
		return -EINVAL;

	n = strlen(s);
	if (n >= sizeof(buf))
		n = sizeof(buf) - 1;

	memcpy(buf, s, n);
	buf[n] = '\0';

	if (!in4_pton(buf, -1, ip.bytes, -1, NULL)) {
		pr_warn("%s: invalid IPv4 address: '%s'\n",
			DRV_NAME, buf);
		return -EINVAL;
	}

	if (ipv4_is_zeronet(ip.addr) ||
	    ipv4_is_lbcast(ip.addr) ||
	    ipv4_is_multicast(ip.addr) ||
	    ipv4_is_loopback(ip.addr)) {
		pr_warn("%s: refusing non-unicast address %pI4\n",
			DRV_NAME, &ip.addr);
		return -EINVAL;
	}

	WRITE_ONCE(vping_ip.addr, ip.addr);
	pr_info("%s: address set to %pI4\n", DRV_NAME, &ip.addr);
	return 0;
}

/* ---------- /proc/vping ---------- */

static ssize_t vping_proc_read(struct file *file, char __user *buf,
			       size_t len, loff_t *offset)
{
	char out[VPING_PROC_BUF_SIZE];
	__be32 cur_ip;
	size_t total_len;

	cur_ip = READ_ONCE(vping_ip.addr);
	total_len = scnprintf(out, sizeof(out), "%pI4\n", &cur_ip);
	return simple_read_from_buffer(buf, len, offset, out, total_len);
}

static ssize_t vping_proc_write(struct file *file, const char __user *buf,
				size_t len, loff_t *offset)
{
	char in[VPING_PROC_BUF_SIZE];
	int err;

	if (len == 0)
		return -EINVAL;

	if (len >= sizeof(in))
		len = sizeof(in) - 1;

	if (copy_from_user(in, buf, len))
		return -EFAULT;
	in[len] = '\0';

	err = vping_set_from_str(in);
	if (err)
		return err;

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

/* ---------- virtual net_device ---------- */

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

/* Forward packets from vping0 to the configured lower device. */
static netdev_tx_t vping_ndo_start_xmit(struct sk_buff *skb,
				       struct net_device *dev)
{
	if (!vping_lower_dev) {
		dev->stats.tx_dropped++;
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	dev->stats.tx_packets++;
	dev->stats.tx_bytes += skb->len;
	skb->dev = vping_lower_dev;
	dev_queue_xmit(skb);
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

/* ---------- ARP ---------- */

static void vping_send_arp_reply(struct sk_buff *req, __be32 our_ip,
				 __be32 sender_ip, const unsigned char *sender_hw)
{
	struct net_device *lower_dev = req->dev;
	struct sk_buff *reply;

	/* For a reply, sender/target are swapped relative to the request. */
	reply = arp_create(ARPOP_REPLY, ETH_P_ARP,
			   sender_ip,     /* dest IP    */
			   lower_dev,
			   our_ip,        /* src IP     */
			   sender_hw,     /* dest HW    */
			   lower_dev->dev_addr, /* src HW     */
			   sender_hw);    /* target HW  */
	if (!reply) {
		pr_warn("%s: arp_create failed\n", DRV_NAME);
		return;
	}

	reply->dev = vping_dev;
	dev_queue_xmit(reply);
}

static bool vping_handle_arp(struct sk_buff *skb)
{
	const struct arphdr *arp;
	const unsigned char *p;
	unsigned char sha[ETH_ALEN];
	__be32 sip, tip;
	__be32 our_ip;

	our_ip = READ_ONCE(vping_ip.addr);

	if (!our_ip || !pskb_may_pull(skb, sizeof(*arp)))
		return false;
	arp = arp_hdr(skb);

	if (arp->ar_hrd != htons(ARPHRD_ETHER) ||
	    arp->ar_pro != htons(ETH_P_IP) ||
	    arp->ar_hln != ETH_ALEN ||
	    arp->ar_pln != 4 ||
	    arp->ar_op  != htons(ARPOP_REQUEST))
		return false;

	if (!pskb_may_pull(skb, sizeof(*arp) + 2 * (ETH_ALEN + 4)))
		return false;
	arp = arp_hdr(skb);
	p = (const unsigned char *)(arp + 1);
	memcpy(sha, p, ETH_ALEN);
	memcpy(&sip, p + ETH_ALEN, 4);
	memcpy(&tip, p + ETH_ALEN + 4 + ETH_ALEN, 4);

	if (tip != our_ip)
		return false;

	vping_send_arp_reply(skb, our_ip, sip, sha);
	return true;
}

/* ---------- ICMP ---------- */

static void vping_send_icmp_reply(struct sk_buff *req)
{
	struct sk_buff *reply;
	struct ethhdr *eth;
	struct iphdr *iph;
	struct icmphdr *icmph;
	unsigned int ihl, icmp_len;
	__be32 tmp_ip;

	reply = skb_copy(req, GFP_ATOMIC);
	if (!reply) {
		pr_warn("%s: skb_copy failed for ICMP reply\n", DRV_NAME);
		return;
	}

	eth = eth_hdr(reply);
	iph = ip_hdr(reply);
	ihl = iph->ihl * 4;
	icmph = (struct icmphdr *)((u8 *)iph + ihl);
	icmp_len = ntohs(iph->tot_len) - ihl;

	ether_addr_copy(eth->h_dest, eth->h_source);
	ether_addr_copy(eth->h_source, reply->dev->dev_addr);

	tmp_ip = iph->saddr;
	iph->saddr = iph->daddr;
	iph->daddr = tmp_ip;

	iph->ttl = 64;
	iph->check = 0;
	iph->check = ip_fast_csum((u8 *)iph, iph->ihl);

	icmph->type = ICMP_ECHOREPLY;
	icmph->checksum = 0;
	icmph->checksum = ip_compute_csum(icmph, icmp_len);

	skb_push(reply, ETH_HLEN);
	skb_dst_drop(reply);

	reply->dev = vping_dev;
	dev_queue_xmit(reply);
}

static bool vping_handle_icmp_echo(struct sk_buff *skb)
{
	const struct iphdr *iph;
	const struct icmphdr *icmph;
	__be32 our_ip;
	unsigned int ihl;

	our_ip = READ_ONCE(vping_ip.addr);

	if (!our_ip || !pskb_may_pull(skb, sizeof(*iph)))
		return false;

	iph = ip_hdr(skb);

	if (iph->daddr != our_ip || iph->protocol != IPPROTO_ICMP)
		return false;

	ihl = iph->ihl * 4;
	if (!pskb_may_pull(skb, ihl + sizeof(*icmph)))
		return false;
	iph = ip_hdr(skb);
	icmph = (const struct icmphdr *)((const u8 *)iph + ihl);

	if (icmph->type != ICMP_ECHO)
		return false;

	vping_send_icmp_reply(skb);
	return true;
}

/* ---------- lower-dev rx handler ---------- */

static rx_handler_result_t vping_rx_handler(struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	bool handled;

	if (skb->protocol == htons(ETH_P_ARP))
		handled = vping_handle_arp(skb);
	else if (skb->protocol == htons(ETH_P_IP))
		handled = vping_handle_icmp_echo(skb);
	else
		return RX_HANDLER_PASS;

	if (!handled)
		return RX_HANDLER_PASS;

	vping_dev->stats.rx_packets++;
	vping_dev->stats.rx_bytes += skb->len;
	*pskb = NULL;
	consume_skb(skb);
	return RX_HANDLER_CONSUMED;
}

/* ---------- module init/exit ---------- */

static int __init vping_init(void)
{
	int err;

	if (!lower_ifname || !*lower_ifname) {
		pr_err("%s: lower_if= parameter is required\n", DRV_NAME);
		err = -EINVAL;
		return err;
	}

	if (initial_ip && *initial_ip) {
		err = vping_set_from_str(initial_ip);
		if (err) {
			pr_err("%s: invalid ip parameter '%s'\n",
			       DRV_NAME, initial_ip);
			return err;
		}
	}

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

	vping_lower_dev = dev_get_by_name(&init_net, lower_ifname);
	if (!vping_lower_dev) {
		pr_err("%s: lower interface '%s' not found\n",
		       DRV_NAME, lower_ifname);
		err = -ENODEV;
		goto err_unreg;
	}

	rtnl_lock();
	err = netdev_rx_handler_register(vping_lower_dev, vping_rx_handler,
					 NULL);
	rtnl_unlock();
	if (err) {
		pr_err("%s: netdev_rx_handler_register(%s) failed: %d\n",
		       DRV_NAME, vping_lower_dev->name, err);
		dev_put(vping_lower_dev);
		vping_lower_dev = NULL;
		goto err_unreg;
	}

	pr_info("%s: loaded, /proc/%s, %s ready, rx on %s\n",
		DRV_NAME, DRV_NAME, vping_dev->name, vping_lower_dev->name);
	return 0;

err_unreg:
	unregister_netdev(vping_dev);
err_free:
	free_netdev(vping_dev);
	vping_dev = NULL;
err_proc:
	proc_remove(vping_proc);
	return err;
}

static void __exit vping_exit(void)
{
	if (vping_lower_dev) {
		rtnl_lock();
		netdev_rx_handler_unregister(vping_lower_dev);
		rtnl_unlock();
		dev_put(vping_lower_dev);
		vping_lower_dev = NULL;
	}
	unregister_netdev(vping_dev);
	free_netdev(vping_dev);
	proc_remove(vping_proc);
	pr_info("%s: unloaded\n", DRV_NAME);
}

module_init(vping_init);
module_exit(vping_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrey Misyurov <andrey.misyurov@gmail.com>");
MODULE_DESCRIPTION("vping: virtual netdev that replies to ICMP echo on /proc/vping IP");
MODULE_VERSION("1.0.0");
