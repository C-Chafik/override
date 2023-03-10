#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

int decrypt(char integerinput)
{
  unsigned int i;
  unsigned int len;
  char crypted[29];

  strcpy(crypted, "Q}|u`sfg~sf{}|a3");
  len = strlen(crypted);
  for ( i = 0; i < len; ++i )
    crypted[i] ^= integerinput;
  if ( !strcmp(crypted, "Congratulations!") )
  {
    system("/bin/sh");
    exit(0);
  }
  else
    return puts("\nInvalid Password");
}

int test(int integerinput, int decrypter)
{
  int result;
  int random_value;

  switch ( decrypter - integerinput )
  {
    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
    case 6:
    case 7:
    case 8:
    case 9:
    case 16:
    case 17:
    case 18:
    case 19:
    case 20:
    case 21:
      result = decrypt(decrypter - integerinput);
      break;
    default:
      random_value = rand();
      result = decrypt(random_value);
      break;
  }
  return result;
}

int main(int argc, const char **argv)
{
  int timed;
  int integerinput;

  timed = time(0);
  srand(timed);
  puts("***********************************");
  puts("*\t\tlevel03\t\t**");
  puts("***********************************");
  printf("Password:");
  scanf("%d", &integerinput);
  test(integerinput, 322424845);
  return 0;
}