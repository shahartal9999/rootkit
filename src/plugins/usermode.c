#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
#endif
#include "usermode.h"
#include "debug_helper.h"

int run_usermode_cmd(void * arguments);

int run_usermode_cmd_thread( void * arguments)
{
    run_cmd_args * args = (run_cmd_args*)arguments;
    dbg_print("Init thread.");
    while (!kthread_should_stop())
    {
        if (args)
        {
            dbg_print("Simple thread.");
            if (args->arg)
            {
                if (run_usermode_cmd(args->arg) != 0)
                {
                    dbg_err_print("Somthing with the usermode_cmd went wrong.");
                }
            }
            else
            {
                dbg_err_print("The args are not full.");
            }
        }
        else
        {
            dbg_err_print("The args are not full.");
        }
        dbg_print("run_usermode_cmd().");
        set_current_state(TASK_INTERRUPTIBLE);
        schedule();
    }
    dbg_print("Close thread.");
    do_exit(0);
}

int run_usermode_cmd(void * arguments) {
    char * cmd = (char *) arguments;
    struct subprocess_info *sub_info;
    char * argv[] = { "/bin/sh", "-c", cmd , NULL };
    static char *envp[] = {
        "HOME=/",
        "TERM=linux",
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
 
    if (cmd == NULL)
    {
        dbg_err_print("Failed to pass arguments.");
        goto exit_with_error;
    }

    dbg_print("command: %s.", cmd);
    sub_info = call_usermodehelper_setup( argv[0], argv, envp, GFP_ATOMIC, NULL,NULL,NULL );    
    if (!sub_info)
        goto exit_with_error;

    call_usermodehelper_exec( sub_info, UMH_WAIT_PROC );

    return 0;

exit_with_error:
    return -1;
}

