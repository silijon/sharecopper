#ifndef _jproc_h
#define _jproc_h

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>


typedef pid_t jproc_t;
int jproc_create(jproc_t *proc, void *(*start_routine)(void *), void *arg);
int jproc_join(jproc_t proc, void **retval);


int jproc_create(jproc_t *proc, void *(*start_routine)(void *), void *arg)
{
    pid_t child = fork();

    if (child < 0) {
        perror("fork");
        return -1;
    } 

    if (child > 0) {
        *proc = (jproc_t)child;
        return 0;
    } 

    start_routine(arg);
    _Exit(EXIT_SUCCESS);
}

int jproc_join(jproc_t proc, void **retval)
{
    int status;
    waitpid((pid_t)proc, &status, 0);
    return WIFEXITED(status);
}

#endif
