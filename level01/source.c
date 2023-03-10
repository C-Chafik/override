#include <string.h>
#include <stdio.h>

char a_user_name[256];

int verify_user_name(void)
{
   puts("verifying username....\n");
   return memcmp(a_user_name, "dat_wil", 7) != 0;
}

int verify_user_pass(const char *pass)
{
   return memcmp(pass, "admin", 5) != 0;
}

int main(void)
{
    char buf[64];
    int check;

    check = 0;
    memset(buf, 0, sizeof(buf));
    puts("********* ADMIN LOGIN PROMPT *********");
    printf("Enter Username: ");

    fgets(a_user_name, 256, stdin);
    check = verify_user_name();

    if ( check == 1 )
        puts("nope, incorrect username...\n");
    else
    {
        puts("Enter Password: ");
        fgets(buf, 100, stdin);
        check = verify_user_pass(buf);
        puts("nope, incorrect password...\n");
    }
    return 1;
}