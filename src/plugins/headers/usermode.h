#ifndef USERMODE_H
#define USERMODE_H

typedef struct _run_cmd_args{
    char * arg;
    unsigned int arg_len;   
}run_cmd_args;


int simple( void *arguments);

#endif