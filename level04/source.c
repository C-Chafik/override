#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <signal.h>

int main(int argc, char **argv, char **envp)
{
    pid_t pid = fork();
    int status = 0;
    char buffer[80];

    memset(buffer, 0, sizeof(buffer));
    if (pid == 0)
    {
        prctl(PR_SET_DUMPABLE, PR_GET_DUMPABLE);
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        puts("Give me some shellcode, k");
        gets(buffer);
    }
    else
    {
        while (true)
        {
            wait(&status);
            if ( !WIFEXITED(status) && !WIFSIGNALED(status) )
            {
                if (ptrace(PTRACE_PEEKUSER, pid, 0x2c, 0) == 0xb)
                {
                    puts("no exec() for you");
                    kill(pid, 9);
                    break;
                }
                continue;
            }
            puts("child is exiting...");
            break;
        }
    }
    return 0;
}