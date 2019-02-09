#ifndef KERNELIO_H
#define KERNELIO_H

#include <linux/fs.h>
struct file* kfile_open(const char *path, int flags, int rights);
void kfile_close(struct file *fp);
int kfile_write(struct file *fp, unsigned char *data, unsigned int size);

#endif