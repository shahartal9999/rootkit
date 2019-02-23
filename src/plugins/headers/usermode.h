#ifndef USERMODE_H
#define USERMODE_H

typedef struct _run_cmd_args{
    char * arg;
}run_cmd_args;

int run_usermode_cmd_thread( void * arguments);
int run_usermode_cmd(void * arguments);

#endif