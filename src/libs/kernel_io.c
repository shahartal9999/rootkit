#include <linux/kernel.h>
#include <linux/module.h>
#include <asm/io.h>
#include <linux/fs.h>
#include <asm/segment.h>
#include <linux/uaccess.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/string.h>

loff_t log_offset;

/* Opens a file from kernel space. */
struct file* kfile_open(const char *path, int flags, int rights)
{
	struct file *fp = NULL;
	mm_segment_t old_fs;
	int error = 0;

	/* Save current process address limit. */
	old_fs = get_fs();
	/* Set current process address limit to that of the kernel, allowing
 	 * the system call to access kernel memory.
	 */ 
	set_fs(get_ds());
	fp = filp_open(path, flags, rights);
	/* Restore address limit to current process. */
	set_fs(old_fs);

	if(IS_ERR(fp)){
		/* Debugging... */
		error = PTR_ERR(fp);
		printk("[-] Colman: log_open(): ERROR = %d", error);
		return NULL;
	}

	return fp;
}

/* Closes file handle. */
void kfile_close(struct file *fp)
{
	filp_close(fp, NULL);
}


/* Writes buffer to file from kernel space. */
int kfile_write(struct file *fp, unsigned char *data,
		unsigned int size)
{
	mm_segment_t old_fs;
	int ret;

	old_fs = get_fs();
	set_fs(get_ds());

	ret = vfs_write(fp, data, size, &log_offset);
	/* Increase file offset, preparing for next write operation. */
	log_offset += size;

	set_fs(old_fs);
	return ret;
}



