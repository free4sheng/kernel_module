#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/init.h>
#include <linux/skbuff.h>				/* struct sk_buff							*/
#include <linux/if_ether.h>				/* struct ethhdr, ETH_P_IP, ETH_P_ARP		*/
#include <linux/if_vlan.h>				/* struct vlan_ethhdr, vlan_eth_hdr			*/
#include <linux/ip.h>					/* struct iphdr, ip_hdr						*/
#include <linux/ipv6.h>					/* struct ipv6hdr, ipv6_hdr					*/
#include <linux/udp.h>					/* struct udphdr							*/
#include <linux/netfilter.h> 
#include <linux/netfilter_ipv4.h>

#define NMAC(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3], \
    ((unsigned char *)&addr)[4], \
    ((unsigned char *)&addr)[5]
#define NMAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]
#define NIPQUAD_FMT "%u.%u.%u.%u"

#define NIP6(addr) \
    ntohs((addr).s6_addr16[0]), \
    ntohs((addr).s6_addr16[1]), \
    ntohs((addr).s6_addr16[2]), \
    ntohs((addr).s6_addr16[3]), \
    ntohs((addr).s6_addr16[4]), \
    ntohs((addr).s6_addr16[5]), \
    ntohs((addr).s6_addr16[6]), \
    ntohs((addr).s6_addr16[7])
#define NIP6_FMT "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x"

static struct nf_hook_ops nfho;

static unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct ethhdr *ethh;
	struct vlan_ethhdr *vethh;
	struct iphdr *iph;

	if (skb->protocol == htons(ETH_P_8021Q)) {
		vethh = vlan_eth_hdr(skb);
		if (vethh == NULL) {
			return NF_DROP;
		}
		printk("[MYLOG] 8021Q\n");

	} else if (skb->protocol == htons(ETH_P_ARP)) {
		ethh = eth_hdr(skb);
		if (ethh == NULL) {
			return NF_DROP;
		}

		printk("[MYLOG] proto=%x dev_name=%s src="NMAC_FMT" dst="NMAC_FMT"\n",
				ntohs(skb->protocol), skb->dev->name,
				NMAC(ethh->h_source),
				NMAC(ethh->h_dest));

	} else if (skb->protocol == htons(ETH_P_IP)) {
		ethh = eth_hdr(skb);
		if (ethh == NULL) {
			return NF_DROP;
		}
		printk("[MYLOG] proto=%x dev_name=%s src="NMAC_FMT" dst="NMAC_FMT" ",
				ntohs(skb->protocol), skb->dev->name,
				NMAC(ethh->h_source),
				NMAC(ethh->h_dest));

		iph = ip_hdr(skb);
		printk("src="NIPQUAD_FMT" dst="NIPQUAD_FMT"\n",
				NIPQUAD(iph->saddr),
				NIPQUAD(iph->daddr));

	} else {
		printk("[MYLOG] proto=%x dev_name=%s\n", ntohs(skb->protocol), skb->dev->name);
	}

	return NF_ACCEPT;
}

static int __init my_init_module(void) 
{
	printk("[MYLOG] starting my driver ...\n");

	nfho.hook = hook_func;						//function to call when conditions below met
	nfho.hooknum = 0;							//called right after packet recieved, first hook in Netfilter
	/* NF_IP_PRE_ROUTING   0 */
	/* NF_IP_LOCAL_IN      1 */
	/* NF_IP_FORWARD       2 */
	/* NF_IP_LOCAL_OUT     3 */
	/* NF_IP_POST_ROUTING  4 */
	/* NF_IP_NUMHOOKS      5 */

	nfho.pf = PF_INET;							//IPV4 packets
	nfho.priority = NF_IP_PRI_FIRST;			//set to highest priority over all other hook functions
	nf_register_hook(&nfho);					//register hook

	return 0;
}

static void __exit my_cleanup_module(void)
{
	nf_unregister_hook(&nfho);					//cleanup – unregister hook
	printk("[MYLOG] my driver remove successfully\n");
}

module_init(my_init_module);
module_exit(my_cleanup_module);
