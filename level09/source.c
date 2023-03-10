#include <stdio.h>
#include <string.h>
#include <stdlib.h>

struct user
{
        char name[40];
        char msg[140];
        int len;
};

void secret_backdoor()
{
  char s[128];

  fgets(s, 128, stdin);
  system(s);

  return ;
}

void set_msg(struct user *v1)
{
  char s[1024];

  memset(s, 0, sizeof(s));
  puts(">: Msg @Unix-Dude");
  printf(">>: ");
  fgets(s, 1024, stdin);
  strncpy(v1->msg, s, v1->len);

  return ;
}

void set_username(struct user *v1)
{
  char s[140];
  int i;

  memset(s, 0, 128);
  puts(">: Enter your username");
  printf(">>: ");
  fgets(s, 128, stdin);
  for ( i = 0; i <= 40 && s[i]; ++i )
    v1->name[i] = s[i];
  printf(">: Welcome, %s", v1->name);

  return ;
}

void handle_msg(void)
{
    struct user v1;

    v1.len = 140;

    set_username(&v1);
    set_msg(&v1);
    puts(">: Msg sent!");

    return ;
}

int main(int argc, const char **argv, const char **envp)
{
  puts(
    "--------------------------------------------\n"
    "|   ~Welcome to l33t-m$n ~    v1337        |\n"
    "--------------------------------------------");
  handle_msg();
  return 0;
}