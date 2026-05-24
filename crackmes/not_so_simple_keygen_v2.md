---
title: howosec's Not to simple KeyGen V2
description: A crackme
tags: crackmes.one, reverse-engineering, medium(3.0)
---

This is a crackme binary from [crackmes.one](https://crackmes.one/crackme/69a1f44218b5d7ee4709351d), a challenge I chose to level up my reversing skills a bit!

### Description by the author
This CTF is a KeyGen crackme, your trial is to write a valid keyGen function.

**Features:**
- Serial based on inputs
- High-level custom-hashing
- Custom over-xor-like encoding
- GCC "Obfuscation" flags
- Big binary, hard to analyze
- Haven't hard-coded strings at all
- Complex `main` function in IDA Map

**How to solve?**
I'll not say that, try by yourself.
If you got it, you should write a write-up!

---

### Reversing The Binary
First of all, let's run the binary to check what it does:

```shell
Hello! Welcome to Howo's not to simple Keygen CTF!


Welcome back to the NTSK Hotel!

Please insert your full name: test
Please insert your best email: test
Please insert your serial: alskdjl
POLICE, THIS GUY IS A ROBBER BUT HE DON'T HAVE A VALID SERIAL KEY LOL!
```

The binary asks us for a username and an email, and then asks us for a serial key.

I started by putting the binary in Ghidra. The binary is stripped, so we are not directly at the `main` function but at the entry of `libc`:

```c
void processEntry entry(undefined8 param_1,undefined8 param_2)

{
  undefined1 auStack_8 [8];
  
  FUN_00404240(main,param_2,&stack0x00000008,0,0,param_1,auStack_8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}
```

`FUN_00404240` is `__libc_start_main`, so our `main` function will be the first argument passed to it.

The binary is compiled with GCC Obfuscation flags, which is why we can't just `grep` for the string the binary is printing to see where our checks happen.

One thing that immediately stood out to me was the loop in the `main` function:

```c
if (lVar9 == 0x10) {
uVar1 = lVar8 + 1;
uVar13 = 0;
if (0 < (int)uVar1) {
    do {
    uVar2 = uVar13 + 3;
    if (((int)acStack_608[(uVar13 + 1) % uVar1] + (int)acStack_608[uVar13] !=
            (int)acStack_608[(uVar13 + 2) % uVar1] << 3) &&
        ((int)acStack_608[uVar2 % uVar1] == (int)*(char *)(lVar10 + uVar13) << 2)) {
        puVar11 = &DAT_00497388;
        puVar12 = auStack_1a8;
        for (lVar10 = 0x2c; lVar10 != 0; lVar10 = lVar10 + -1) {
        *puVar12 = *puVar11;
        puVar11 = puVar11 + (ulong)bVar14 * -2 + 1;
        puVar12 = puVar12 + (ulong)bVar14 * -2 + 1;
        }
        uVar3 = *(undefined4 *)puVar11;
        *(undefined1 *)((long)puVar12 + 4) = 0xa7;
        *(undefined4 *)puVar12 = uVar3;
        uVar6 = FUN_00402dd0(auStack_1a8,0x165);
        FUN_0044ccb0(1,&DAT_004c50e3,uVar6);
        FUN_0041bb10(uVar6);
        uVar6 = 0;
        goto LAB_00401a7f;
    }
    uVar13 = uVar2;
    } while ((int)uVar2 < (int)uVar1);
}
}
```

The control flow indicates that before this loop, the three strings are printed and the input from the user is taken, and then this loop executes. That's why I assumed that this is the function that checks our provided serial key.

We can immediately tell from the first check that our serial key has to be 16 bytes long:

```c
if (lVar9 == 0x10)
```

Further analysis shows that the function loops over the serial key in chunks of 4 bytes (it holds a pointer to the first element of the chunk and one to the last). After each iteration, the last char of the chunk becomes the first, and so on. For each chunk, it checks if this specific condition is met:

```c
if (((int)acStack_608[(ptr1 + 1) % len] + (int)acStack_608[ptr1] != (int)acStack_608[(ptr1 + 2) % len] << 3) &&
    ((int)acStack_608[ptr2 % len] == (int)*(char *)(lVar10 + ptr1) << 2))
```

This is a bit of an alphabet soup, so let's break it down.

Essentially, we need to match two conditions at once:

1. The second character of the chunk summed up with the first has to be different from the third character times 8:
   `C_0 + C_1 != C_2 * 8`
2. The fourth character (`C_3`) needs to equal the character of a certain buffer (`lVar10`) at our current chunk offset (0, 3, 6, 9, ...) multiplied by 4.

The fatal flaw is also here: we only need to meet this condition *once* to get to the winning path. If we fail the other times, we won't get kicked out of the loop.

So, to solve this puzzle, we need to check what is inside the `lVar10` buffer. After backtracking to its origin, it reveals that it originates from a function:

`lVar10 = FUN_00401d80(lVar8,lVar10)`

Looking inside this function, it seems like some kind of generator for a hash lookup table (an S-Box). It takes in a seed value and spits out an array of 256 scrambled bytes.

The output depends on the input the user has typed in before, specifically the username and the email.

To avoid going through the pain of reversing this whole hash function, I just dumped the S-Box for the user `test` and email `test` using GDB.

The instruction that accesses this lookup table with the current offset is this:

```x86_64
MOVSX   ESI, byte ptr [RBX + ptr1 * 0x1]
```

At runtime, at this exact point, `RBX` holds this desired lookup table. We can set a breakpoint at this specific instruction and dump the S-Box:

```gdb
pwndbg> x/256bx $rbx
0x4cea40:       0x99    0x83    0xfa    0x39    0xe8    0x10    0x97    0x8c
0x4cea48:       0x40    0xdb    0x0e    0x3e    0xf5    0x00    0x90    0x99
0x4cea50:       0x92    0xf4    0x52    0x58    0xd5    0xf3    0xe8    0xb9
0x4cea58:       0xad    0x6a    0x88    0xaa    0x22    0xff    0x0f    0x39
0x4cea60:       0x1c    0xbd    0xc4    0x4e    0xa9    0xe5    0x81    0x99
0x4cea68:       0xd4    0x9b    0xe9    0x94    0x29    0xe9    0x9a    0xe9
...
0x4ceb30:       0xd7    0xd3    0x66    0xf4    0x30    0x1c    0x2a    0xa1
0x4ceb38:       0x51    0x2f    0x8e    0x91    0xed    0x6a    0xfa    0xe9
```

Now we have everything we need to craft our own serial key for the user `test:test`.

The first condition will always be met if we just provide straight 'A's (or really anything other than 0).

For the second condition, we need to do some math. We need to find the offset where, after the multiplication by 4, the result is still representable by a single byte. Also, we have to take into account that the character is interpreted as a *signed* `char` and not an *unsigned* `char`, so we can only represent values between -128 and 127 (not all the way up to 255).

So let's go through the offsets one by one:

*   **0:**  `0x99` -> -103 -> `* 4` = -412
*   **3:**  `0x39` -> 57   -> `* 4` = 228
*   **6:**  `0x97` -> -105 -> `* 4` = -420
*   **9:**  `0xdb` -> -37  -> `* 4` = -148
*   **12:** `0xf5` -> -11  -> `* 4` = -44 -> **Actually in our range!**

The value on the left (the one we send) is also cast to an `int`. We need to send the raw byte that, when interpreted as a signed `char`, equals -44.

We can do this by adding our target value to 256. `256 + (-44) = 212`. 
`212` is actually not in the printable ASCII range, but it is small enough to be represented by exactly one byte (`<= 255`), so we can just pipe it to our binary via Python using `pwntools`:

```python
import pwn

# Calculate the magic byte
expected_char = (0xf5 - 256) * 4
target_char = 256 + expected_char
print(target_char)

# Craft the payload
serial = b"A" * 15 + bytes([target_char])

# Fire the exploit
p = pwn.process("./howo-not-to-simple-keygen")
p.recvuntil(b"Please insert your full name: ")
p.sendline(b"test")
p.recvuntil(b"Please insert your best email: ")
p.sendline(b"test")
p.recvuntil(b"Please insert your serial: ")
p.sendline(serial)
p.interactive()
```

After running this script, we have our flag!