#ifndef INTERCOM_H
#define INTERCOM_H

int init_intercom(void);
void clean_intercom(void);
void send_to_user(char * str, size_t str_len);
long get_child_pid( void );
void * recv_from_user(char * buff, int buff_len);

//extern char imsg[IBUF_LEN];

#endif