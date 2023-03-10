#include <stdio.h>
#include <stdlib.h>

int main(int ac, char **av, char **env)
{
    int intInput;

    puts("***********************************");
    puts("* \t     -Level00 -\t\t  *");
    puts("***********************************");
    printf("Password:");
    scanf("%d", &intInput);
    if ( intInput == 5276 )
    {
        puts("\nAuthenticated!");
        system("/bin/sh");
        return 0;
    }
    else
        puts("\nInvalid Password!");
    return 1;
}