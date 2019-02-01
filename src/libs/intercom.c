#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h> /* for put_user */
#include "intercom.h"
#include "signals.h"

#define SUCCESS 0
#define DEVICE_NAME "colman"
#define COLMAN_MAJOR 256
#define IBUF_LEN 80

/*
 * Global variables are declared as static, so are global within the file.
 */

static int Major;
static int Device_Open = 0;
//char imsg[IBUF_LEN];
static char *msg_Ptr = NULL;

static long pid = 0;

#define BUFFER_SIZE 1024
static char device_buffer[BUFFER_SIZE];
static int device_buffer_len = 0;
static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char *, size_t, loff_t *);

static struct file_operations fops = {
	.read = device_read,
	.write = device_write,
	.open = device_open,
	.release = device_release
};

long get_child_pid( void )
{

	return pid;
}

/*
 * This function is called when the module is loaded
 */
int init_intercom(void)
{
	Major = register_chrdev(COLMAN_MAJOR, DEVICE_NAME, &fops);

	if (Major < 0) {
		printk(KERN_ALERT "[-] Colman: Registering char device failed with %d\n", Major);
		return Major;
	}
	return SUCCESS;
}

void send_to_user(char * str, size_t str_len)
{
	if (str==NULL)
	{
		printk("[-] Colman: str is NULL.\n");
		return;
	}
	if (msg_Ptr!=NULL) {
		kfree(msg_Ptr);
	}
	msg_Ptr = (char *)kmalloc(sizeof(char) * (str_len + 1), GFP_KERNEL);
	if (!msg_Ptr)
	{
		printk("[-] Colman: Alloc space failed.\n");
		return;
	}
	memcpy(msg_Ptr, str, str_len);

	msg_Ptr[str_len] = 0x0;

}
/*
 * This function is called when the module is unloaded
 */
void clean_intercom(void)
{
  /*
   * Unregister the device
   */

  unregister_chrdev(COLMAN_MAJOR, DEVICE_NAME);
}


/*
 * Methods
 */

/*
 * Called when a process tries to open the device file, like
 * "cat /dev/mycharfile"
 */
static int device_open(struct inode *inode, struct file *filp)
{
	//static int counter = 0;
	if (Device_Open)
		return -EBUSY;

	Device_Open++;

	//sprintf(imsg, "Hello world!", counter++);
	printk("[+] Colman: strlen(Hello world!)=%ld", strlen("Hello world!"));
	send_to_user("Hello world!", strlen("Hello world!"));
	//msg_Ptr = imsg;
	//msg_Ptr = imsg;
	/*
	* TODO: comment out the line below to have some fun!
	*/
	try_module_get(THIS_MODULE);

	return SUCCESS;
}

/*
 * Called when a process closes the device file.
 */
static int device_release(struct inode *inode, struct file *filp)
{
	Device_Open--;

	/*
	* Decrement the usage count, or else once you opened the file, you'll never
	* get rid of the module.
	*
	* TODO: comment out the line below to have some fun!
	*/
	module_put(THIS_MODULE);

	return SUCCESS;
}

/*
 * Called when a process, which already opened the dev file, attempts to read
 * from it.
 */
static ssize_t device_read(struct file *filp, /* see include/linux/fs.h   */
                           char *buffer,      /* buffer to fill with data */
                           size_t length,     /* length of the buffer     */
                           loff_t *offset)
{
	/*
	* Number of bytes actually written to the buffer
	*/
	int bytes_read = 0;


	//printk("send to usermode: %p (%x)\n", imsg, *imsg);

	//msg_Ptr = imsg;
	/*
	* If we're at the end of the message, return 0 signifying end of file.
	*/
	if (!msg_Ptr)
	{
		printk("[-] Colman: Why msg_Ptr is not allocated?\n");
		return 0;
	}
	if (*msg_Ptr == 0)
		return 0;

	/*
	* Actually put the data into the buffer
	*/
	while (length && *msg_Ptr) {
	/*
	 * The buffer is in the user data segment, not the kernel segment so "*"
	 * assignment won't work. We have to use put_user which copies data from the
	 * kernel data segment to the user data segment.
	 */
		put_user(*(msg_Ptr++), buffer++);
		length--;
		bytes_read++;
	}

	/*
	* Most read functions return the number of bytes put into the buffer
	*/
	return bytes_read;
}

void * recv_from_user(char * buff, int buff_len)
{
	int bytes_to_write = 0;
	if (buff_len < device_buffer_len)
	{
		bytes_to_write = buff_len;
	}
	else {
		bytes_to_write = device_buffer_len;
	}
	memcpy(buff, device_buffer, bytes_to_write);
}

/*
 * Called when a process writes to dev file: echo "hi" > /dev/hello
 */
static ssize_t
device_write(struct file *filp, const char *buf, size_t len, loff_t *off)
{
    int maxbytes;           /* maximum bytes that can be read from ppos to BUFFER_SIZE*/
    int bytes_to_write;     /* gives the number of bytes to write*/
    int bytes_writen;       /* number of bytes actually writen*/
    maxbytes = BUFFER_SIZE - *off -1;
    if (maxbytes > len)
		bytes_to_write = len;
    else
		bytes_to_write = maxbytes;

	device_buffer[bytes_to_write] = 0x0;

    bytes_writen = bytes_to_write - copy_from_user(device_buffer + *off, buf, bytes_to_write);
    printk(KERN_INFO "[+] Colman: device has been written %d\n", bytes_writen);
    *off += bytes_writen;
    printk(KERN_INFO "[+] Colman: device has been written\n");
    device_buffer_len = bytes_writen; 


    if (pid==0)
    {
    	printk("[+] Colman: try too fill pid.\n");
		if (kstrtol(device_buffer, 10, &pid) != 0)
		{
	    	printk("[-] Colman: Cannot insert pid.\n");
			pid = 0;
		}
		printk("[+] Colman: pid is %ld.\n", pid);
	}	
	return bytes_writen;
}

