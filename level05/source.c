#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

int main(int argc, const char **argv, const char **envp)
{
  int result;
  char v4[100];
  unsigned int i;

  i = 0;
  fgets(v4, 100, stdin);
  for ( i = 0; i < strlen(v4); ++i )
    tolower(v4[i]);
  printf(v4);
  exit(0);
  return result;
}