// SPDX-License-Identifier: GPL-2.0
/*
 * vping - virtual network interface that replies to ICMP echo requests
 *         on an IPv4 address configured via procfs.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

#define DRV_NAME "vping"

static int __init vping_init(void)
{
	pr_info("%s: loaded\n", DRV_NAME);
	return 0;
}

static void __exit vping_exit(void)
{
	pr_info("%s: unloaded\n", DRV_NAME);
}

module_init(vping_init);
module_exit(vping_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrey Misyurov <andrey.misyurov@gmail.com>");
MODULE_DESCRIPTION("Virtual netdev that replies to ping");
MODULE_VERSION("0.1.0");
