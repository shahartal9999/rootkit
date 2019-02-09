#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
#endif
#include "usermode.h"

int run_usermode_cmd(char * cmd);

int run_usermode_cmd_thread( void * arguments)
{
    run_cmd_args * args = (run_cmd_args*)arguments;
    printk(KERN_INFO "[+] Colman: Init thread.\n");
    while (!kthread_should_stop())
    {
        if (args)
        {
            printk(KERN_INFO "[+] Colman: Simple thread\n");
            if (args->arg)
            {
                if (run_usermode_cmd(args->arg) != 0)
                {
                    printk(KERN_INFO "[-] Colman: Somthing with the usermode_cmd went wrong.\n");
                }
            }
            else
            {
                printk(KERN_INFO "[-] Colman: The args are not full.\n");
            }
        }
        else
        {
            printk(KERN_INFO "[-] Colman: The args are not full.\n");
        }
        printk(KERN_INFO "[+] Colman: run_usermode_cmd().\n");
        set_current_state(TASK_INTERRUPTIBLE);
        schedule();
    }
    printk(KERN_INFO "[+] Colman: Close thread.\n");
    do_exit(0);
}

int run_usermode_cmd(char * cmd) {
    struct subprocess_info *sub_info;
    char * argv[] = { "/bin/sh", "-c", cmd , NULL };
    static char *envp[] = {
        "HOME=/",
        "TERM=linux",
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
 
    if (cmd == NULL)
    {
        printk(KERN_INFO "[-] Colman: Failed to pass arguments.");
        goto exit_with_error;
    }

    printk(KERN_INFO "[+] Colman: command: %s.\n", cmd);
    sub_info = call_usermodehelper_setup( argv[0], argv, envp, GFP_ATOMIC, NULL,NULL,NULL );    
    if (!sub_info)
        goto exit_with_error;

    call_usermodehelper_exec( sub_info, UMH_WAIT_PROC );

    return 0;

exit_with_error:
    return -1;
}

