#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int get_unum(void)
{
  int input;

  input = 0;
  fflush(stdout);
  scanf("%u", &input);
  return input;
}

int store_number(int *array)
{
  unsigned int value;
  unsigned int index;

  printf(" Number: ");
  value = get_unum();
  printf(" Index: ");
  index = get_unum();
  if ( index % 3 == 0 )
  {
    puts(" *** ERROR! ***");
    puts("   This index is reserved for wil!");
    puts(" *** ERROR! ***");
    return 1;
  }
  else
  {
    array[index] = value;
    return 0;
  }
}

int read_number(int *array)
{
  int index;

  printf(" Index: ");
  index = get_unum();
  printf(" Number at data[%u] is %u\n", index, array[index]);
  return 0;
}

int main(int argc, const char **argv, const char **envp)
{
  int array[400];
  int number;
  char input[20] = {0};

  number = 1;
  memset(array, 0, sizeof(array));
  while ( *argv )
  {
    memset((void *)*argv, 0, strlen(*argv));
    ++argv;
  }
  while ( *envp )
  {
    memset((void *)*envp, 0, strlen(*envp));
    ++envp;
  }
  puts(
    "----------------------------------------------------\n"
    "  Welcome to wil's crappy number storage service!   \n"
    "----------------------------------------------------\n"
    " Commands:                                          \n"
    "    store - store a number into the data storage    \n"
    "    read  - read a number from the data storage     \n"
    "    quit  - exit the program                        \n"
    "----------------------------------------------------\n"
    "   wil has reserved some storage :>                 \n"
    "----------------------------------------------------\n"
    );
  while ( 1 )
  {
    printf("Input command: ");
    number = 1;
    fgets(input, 20, stdin);
    input[strlen(input) - 1] = 0;

    if ( strncmp(input, "store", 5) == 0 )
      number = store_number(array);
    else if ( strncmp(input, "read", 4) == 0)
      number = read_number(array);
    else if ( strncmp(input, "quit", 4) == 0)
      return 0;

    if ( number )
      printf(" Failed to do %s command\n", input);
    else
      printf(" Completed %s command successfully\n", input);
    memset(input, 0, 20);
  }
}