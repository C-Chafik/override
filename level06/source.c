#include <sys/ptrace.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int auth(char *buf, int integerInput)
{
  int i;
  int decrypt;
  int buflen;

  buf[strcspn(buf, "\n")] = 0;
  buflen = strnlen(buf, 32);
  if ( buflen <= 5 )
    return 1;
  if ( ptrace(PTRACE_TRACEME, 0, 1, 0) == -1 )
  {
    puts("\x1B[32m.---------------------------.");
    puts("\x1B[31m| !! TAMPERING DETECTED !!  |");
    puts("\x1B[32m'---------------------------'");
    return 1;
  }
  else
  {
    decrypt = (buf[3] ^ 0x1337) + 6221293;
    for ( i = 0; i < buflen; ++i )
    {
      if ( buf[i] <= 31 )
        return 1;
      decrypt += (decrypt ^ (unsigned int)buf[i]) % 0x539;
    }
    return integerInput != decrypt;
  }
}

int main(int argc, const char **argv, const char **envp)
{
  int integerInput;
  char buf[32];

  puts("***********************************");
  puts("*\t\tlevel06\t\t  *");
  puts("***********************************");
  printf("-> Enter Login: ");
  fgets(buf, 32, stdin);
  puts("***********************************");
  puts("***** NEW ACCOUNT DETECTED ********");
  puts("***********************************");
  printf("-> Enter Serial: ");
  scanf("%u", &integerInput);
  if ( auth(buf, integerInput) )
    return 1;
  puts("Authenticated!");
  system("/bin/sh");
  return 0;
}