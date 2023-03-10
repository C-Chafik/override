# Level 00

## GDB Utils 


```c
info func

0x08048380  printf
0x08048380  printf@plt
0x08048390  puts
0x08048390  puts@plt
0x080483a0  system
0x080483a0  system@plt
0x080483e0  _start
0x08048470  frame_dummy
0x08048494  main

info var
(nothing usefull)





disas main


   0x08048494 <+0>:     push   %ebp
   0x08048495 <+1>:     mov    %esp,%ebp
   0x08048497 <+3>:     and    $0xfffffff0,%esp
   0x0804849a <+6>:     sub    $0x20,%esp
   0x0804849d <+9>:     movl   $0x80485f0,(%esp)
   0x080484a4 <+16>:    call   0x8048390 <puts@plt>
   0x080484a9 <+21>:    movl   $0x8048614,(%esp)
   0x080484b0 <+28>:    call   0x8048390 <puts@plt>
   0x080484b5 <+33>:    movl   $0x80485f0,(%esp)
   0x080484bc <+40>:    call   0x8048390 <puts@plt>
   0x080484c1 <+45>:    mov    $0x804862c,%eax
   0x080484c6 <+50>:    mov    %eax,(%esp)
   0x080484c9 <+53>:    call   0x8048380 <printf@plt>
   0x080484ce <+58>:    mov    $0x8048636,%eax
   0x080484d3 <+63>:    lea    0x1c(%esp),%edx
   0x080484d7 <+67>:    mov    %edx,0x4(%esp)
   0x080484db <+71>:    mov    %eax,(%esp)
   0x080484de <+74>:    call   0x80483d0 <__isoc99_scanf@plt>
   0x080484e3 <+79>:    mov    0x1c(%esp),%eax
   0x080484e7 <+83>:    cmp    $0x149c,%eax
   0x080484ec <+88>:    jne    0x804850d <main+121>
   0x080484ee <+90>:    movl   $0x8048639,(%esp)
   0x080484f5 <+97>:    call   0x8048390 <puts@plt>
   0x080484fa <+102>:   movl   $0x8048649,(%esp)
   0x08048501 <+109>:   call   0x80483a0 <system@plt>
   0x08048506 <+114>:   mov    $0x0,%eax
   0x0804850b <+119>:   jmp    0x804851e <main+138>
   0x0804850d <+121>:   movl   $0x8048651,(%esp)
   0x08048514 <+128>:   call   0x8048390 <puts@plt>
   0x08048519 <+133>:   mov    $0x1,%eax
   0x0804851e <+138>:   leave
   0x0804851f <+139>:   ret


```


## IDA

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4;

  puts("***********************************");
  puts("* \t     -Level00 -\t\t  *");
  puts("***********************************");
  printf("Password:");
  __isoc99_scanf("%d", &v4);
  if ( v4 == 5276 )
  {
    puts("\nAuthenticated!");
    system("/bin/sh");
    return 0;
  }
  else
  {
    puts("\nInvalid Password!");
    return 1;
  }
}
```


The behavior is quite obvious but lets still check the binary behavior :


```sh
level00@OverRide:~$ ./level00
***********************************
*            -Level00 -           *
***********************************
Password:hey

Invalid Password!
level00@OverRide:~$ ./level00
***********************************
*            -Level00 -           *
***********************************
Password:5276

Authenticated!
$ id
uid=1000(level00) gid=1000(level00) euid=1001(level01) egid=100(users) groups=1001(level01),100(users),1000(level00)
$ cat /home/users/level01/.pass
uSq2ehEGT6c9S24zbshexZQBXUGrncxn5sD5QfGL
$
```


The programm pretty much takes our input using scanf(), which convert our input to an int since its using %d, it then compare it with 5276, or 0x149c in hex, and execute a shell to us.