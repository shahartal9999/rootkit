#include <linux/kernel.h>
#include <linux/module.h>
#include <asm/siginfo.h>    //siginfo
#include <linux/init.h>
#include <linux/sched/signal.h>
#include <linux/rcupdate.h> //rcu_read_lock
#include <linux/sched.h>    //find_task_by_pid_type


#define SIG_TEST 44


void send_signal(int pid)
{
	struct siginfo info;
	struct task_struct *t;

	memset(&info, 0, sizeof(struct siginfo));
	info.si_signo = SIG_TEST;
	// This is bit of a trickery: SI_QUEUE is normally used by sigqueue from user space,    and kernel space should use SI_KERNEL. 
	// But if SI_KERNEL is used the real_time data  is not delivered to the user space signal handler function. */
	info.si_code = SI_QUEUE;
	// real time signals may have 32 bits of data.
	info.si_int = 1234; // Any value you want to send
	rcu_read_lock();
	// find the task with that pid
	t = pid_task(find_pid_ns(pid, &init_pid_ns), PIDTYPE_PID);
	if (t != NULL) {
	    rcu_read_unlock();      
	    if (send_sig_info(SIG_TEST, &info, t) < 0) // send signal
	        printk("send_sig_info error\n");
	} else {
	     printk("pid_task error\n");
	     rcu_read_unlock();
	    //return -ENODEV;
	}

}