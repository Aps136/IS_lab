#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>

int main() {
    pid_t pid;
    pid = fork();

    if (pid < 0) {
        printf("FORK FAILED\n");
        return 1;
    } else if (pid == 0) {
        // This is the child process
        printf("Hey, I'm a child process, WAAWAAA\n");
        printf("Child PID: %d\n", getpid());
        printf("Parent PID: %d\n", getppid());
    } else {
        // This is the parent process
        printf("I'm a parent, and you're grounded son!\n");
        printf("Parent PID: %d\n", getpid());
        // Use the 'pid' variable to get the child's PID
        printf("Child PID: %d\n", pid); 
    }

    return 0;
}
