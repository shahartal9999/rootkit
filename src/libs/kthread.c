


static struct task_struct *thread1;


#define CREATETHREAD(thread_name, ...) \
	static struct task_struct *##thread_name; \
	typedef struct _arg_##thread_name { \
		##__VA_ARGS__; \
	}arg_##thread_name;



CREATETHREAD(thread1, int a, int b)

void create_thread()
{
	//thread1 = kthread_run(run_cmd, cmd_arguments, "thread");
}
	

