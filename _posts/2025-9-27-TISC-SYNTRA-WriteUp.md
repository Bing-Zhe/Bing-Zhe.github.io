---
title: "TISC CTF 2025 WriteUp"
date: 2025-09-27 09:00:00 +0800
categories: [CTF WriteUps]
tags: []
---

# TISC CTF 2025

## Level 5. Syntra:

### CTF Prompt:

```
Syntra

It looks harmless enough. A jukebox, streaming random music tracks from some unknown source. You press play, it plays music. The buttons work, the dials turn, and there is a faint LED glowing just enough to remind you it is still watching.

But this is not just some forgotten novelty.

Rumors suggest that devices like this were never meant for entertainment. They were built for something else entirely. Devices made specially to broadcast messages covertly, carefully designed to blend in as a regular electronic gadget. Those in the know call it the SYNTRA, Syndicate Transceiver Array.

We seized this unit during an operation targeting individuals linked to Spectre, the same group responsible for the chaos we thought had been buried. However, there seems to have been some countermeasures built into this unit to prevent further analysis by our team. Whether this is a leftover relic from earlier operations or something that is still relevant, no one can say for certain. It might be nothing, or it might be exactly what we need to finally get closer to the kingpin.

Your task is to investigate the SYNTRA and see if you can find any leads.
```

### Analysis of the Webpage

Interface:

![SYNTRA device interface](assets/img/TISC_2025/SYNTRA_image.png)

SYNTRA device interface

SYNTRA device interface:

- 2 Knobs: One knob used to adjust the playback speed of the audio, the other used to adjust the volume of the audio
- 4 buttons: One for play, pause, stop and next (audio) respectively

#### Next Button:

Other than the 2 knobs and the 3 buttons, which performs a function on the audio extract, the next button performs a HTTP POST request to the server and subsequently receive an audio `.mp3` file, which is played back to the user.

HTTP POST Request:

```
POST /?t=1758515815662 HTTP/1.1 
Host: chals.tisc25.ctf.sg:57190 
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0 
Accept: */* 
Accept-Language: en-US,en;q=0.5 
Accept-Encoding: gzip, deflate, br 
Referer: http://chals.tisc25.ctf.sg:57190/ 
R: application/octet-stream 
H: 28 
Content-Length: 28 
Origin: http://chals.tisc25.ctf.sg:57190 
Connection: keep-alive 

+Ùc]¾P
```

Analysis:

- The HTTP POST request is sent with a parameter and value pair `t=1758515815662`, in addition to a 28 byte blob of binary data `+Ùc]¾P`.

### Analysis of the Binary

Besides the provided SYNTRA interface, the challenge also gave users a copy of the server’s binary. After decompiling the binary with IDA, noticed immediately that this was a binary written in golang. I decided to look further into the `main_main()` function.

Taking a look at the `main_main()` function in the binary:

```c
// GET Requests gets handled by this Golang Handler fucntion
(*p__1_gin_HandlerFunc)[0] = (PTR_gin_HandlerFunc)&off_8941F8; // main_main_func1
github_com_gin_gonic_gin__ptr_RouterGroup_handle(
  (__int64)v82,
  (int)"GETPUTEOF???new443ACK../agevia200404tcp100...0\r\n125625nanNaN: *mapintptrKey", // "GET"
  3,
  (int)&unk_86CBCD,  // "/health"
  7,
  (int)p__1_gin_HandlerFunc,  // main_main_func1
  1,
  1,
  v42);

// POST Requests gets handled by this Golang Handler fucntion
(*v47)[0] = (PTR_gin_HandlerFunc)&off_894200;
github_com_gin_gonic_gin__ptr_RouterGroup_handle(
  (__int64)v82,
  (int)&unk_86A5F3, // "POST"
  4,
  (int)&go_string__ptr_,  // "/"
  1,
  (int)v47,  // main_main_func2
  1,
  1,
  v48);
```

Analysis:

- These 2 `github_com_gin_gonic_gin__ptr_RouterGroup_handle()` instances, correspond to the `RouterGroup.handle()` method, which is the internal function that actually registers HTTP routes with the Gin router.
- `RouterGroup.handle()`, takes in 3 arguments HTTP method string, Route path string and function pointer.

GET Route:

- GET Route will handle the GET requests to `/health` that the server receives, and exeuctes the `main_main_func1`

POST Route:

- POST Route will handle the POST requests to `/` that the server receives, and executes the `main_main_func2`
- Since the client only sends POST requests, hence only this route is used

#### Main_main_func2 Route:

Looking at the `main_main_func2`, first that that stood out was the `io_ReadAll()` function, which is a golang function that reads data from the client HTTP body payload. In golang, the `io.ReadAll()` function reads in any source of bytes, returns `[]byte` a slice of bytes containing all the data read from the input and `error` which is an error object containing the value of any error encountered while reading.

`io_ReadAll()` function:

```c
All = (unsigned int *)io_ReadAll(v11, v12, v10, a4, (int)a5, a6, a7, a8, a9);
```

Analysis:

- `All` corresponds to the raw bytes read from the request body
- `a4` starts as a function parameter, but then gets overwritten with the error return value from golang’s `io_RealAll()` function

Main function purpose:

```c
    {
    if ( v12 )
    {
      main_parseMetrics(All, v12, v15);
      v68 = v9;
      *(_QWORD *)&v68 = *(_QWORD *)(v12 + 8);
      *((_QWORD *)&v68 + 1) = v20;
      v72 = main_main_func2_Printf_2;
      v74 = 25;
      v73 = "Error parsing metrics: %vtext/plain; charset=utf-8500 Internal Server Errorhttp2: Framer %p: read %vframe_data_pad_byte_shortframe_settings_has_streamframe_headers_zero_streamframe_headers_pad_too_bigframe_priority_bad_lengthhttp2: invalid header: %vstrict-transport-security";
      v76 = 1;
      v77 = 1;
      v75 = &v68;
      log__ptr_Logger_output(runtime_bss, 0, 2, (int)&v72, (int)a5, v21, v22, v23, v24, v56, v57, v58, v59);
      v65 = v9;
      v66 = v9;
      v67 = v9;
      v30 = main_determineAudioResource((__int64)&v65, 0, v25, (__int64)&v72, (__int64)a5, v26, v27, v28, v29);
    }
    else
    {
      v62 = v9;
      v63 = v9;
      v64 = v9;
      v30 = main_determineAudioResource((__int64)&v62, 0, v15, 0, (__int64)a5, v16, v17, v18, v19);
    }
```

Analysis:

- After performing some dynamic analysis, that the first branch gets activated when a payload is attached, triggering `main_parseMetrics` and `main_determineAudioResource` functions
- As a result, the following will explore these 2 function further

#### main_parseMetrics function:

Decompiled code:

```c
// main.parseMetrics
unsigned int *__golang main_parseMetrics(
        unsigned int *a1,
        __int64 a2,
        __int64 a3,
        int a4,
        int a5,
        int a6,
        int a7,
        int a8,
        int a9)
{
<SNIP>

  if ( a2 < 16 )
    return 0;
  result = (unsigned int *)runtime_newobject(&RTYPE_main_MetricsData, a2, a3, a4, a5, a6, a7, a8, a9);
  v11 = a1;
  if ( result != a1 )
    *(_QWORD *)result = *(_QWORD *)a1;
  v12 = a1[2];
  v13 = 12 * v12 + 16;
  result[2] = v12;
  result[3] = a1[3];
  v14 = a2;
  if ( a2 != v13 )
    return 0;
  v42 = result;
  v15 = a3;
  v16 = 0;
  for ( i = 16; ; i = v20 )
  {
    v19 = result[2];
    if ( (unsigned int)v16 >= v19 )
      break;
    v20 = i + 12;
    if ( v14 < (__int64)(i + 12) )
      return 0;
    v21 = i + 4;
    if ( v15 < i + 4 )
      runtime_panicSliceAcap((__int64)result, v16, i + 4, a4, i, v14, v20, v21, v10, v37, v38);
    if ( i > v21 )
      runtime_panicSliceB(i, v16, i + 4);
    v22 = v15 - i;
    v23 = i + 8;
    v10 = *(unsigned int *)((char *)v11 + (i & ((__int64)(i - v15) >> 63)));
    if ( v15 < i + 8 )
      runtime_panicSliceAcap((__int64)result, v16, i + 8, a4, i, v14, v20, v21, v10, v37, v38);
    if ( v23 < v21 )
      runtime_panicSliceB(i + 4, v16, i + 8);
    v24 = *(unsigned int *)((char *)v11 + (((__int64)(4 - v22) >> 63) & v21));
    if ( v15 < v20 )
      runtime_panicSliceAcap((__int64)result, v16, i + 12, a4, i, v14, v20, v24, v10, v37, v38);
    if ( v23 > v20 )
      runtime_panicSliceB(i + 8, v16, i + 12);
    v25 = ((__int64)(8 - v22) >> 63) & v23;
    v26 = *((_QWORD *)result + 4);
    v27 = *((_QWORD *)result + 3) + 1LL;
    v28 = *((_QWORD *)result + 2);
    v29 = *(unsigned int *)((char *)v11 + v25);
    if ( v26 < v27 )
    {
      v40 = v10;
      v41 = v20;
      v39 = v24;
      a4 = 1;
      v30 = runtime_growslice(v28, v27, v26, 1, (unsigned int)&RTYPE_main_ActionRecord, v14, v20, v24, v10);
      v31 = v42;
      *((_QWORD *)v42 + 4) = v32;
      if ( runtime_writeBarrier )
      {
        v30 = runtime_gcWriteBarrier2(v30);
        *v33 = v30;
        v33[1] = *((_QWORD *)v31 + 2);
      }
      *((_QWORD *)v31 + 2) = v30;
      v11 = a1;
      v15 = a3;
      v14 = a2;
      v20 = v41;
      v24 = v39;
      v10 = v40;
      v28 = v30;
      result = v42;
    }
    *((_QWORD *)result + 3) = v27;
    v18 = 3 * v27;
    *(_DWORD *)(v28 + 4 * v18 - 12) = v10;
    *(_DWORD *)(v28 + 4 * v18 - 8) = v24;
    *(_DWORD *)(v28 + 4 * v18 - 4) = v29;
    v16 = (unsigned int)(v16 + 1);
  }
  v34 = *((_QWORD *)result + 2);
  for ( j = *((_QWORD *)result + 3); j > 0; --j )
  {
    v36 = *(unsigned __int8 *)(v34 + 8) ^ *(_DWORD *)(v34 + 4) ^ *(_DWORD *)v34;
    v34 += 12;
    v19 ^= v36;
  }
  if ( result[3] != v19 )
    return 0;
  return result;
}
```

Analysis:

- Function takes in HTTP POST data payload
- Performs some transformation on the data payload
- Returns result, which is a MetricsData object

#### MetricsData Object

MetricsData struct object:

```c
// MetricsData: 40 bytes total (0x28)
typedef struct {
    MetricsHeader Header;        // 16 bytes at offset 0
    ActionRecordSlice Actions;   // 24 bytes at offset 16
} main_MetricsData;
```

Analysis:

- main_MetricsData struct object that has 2 fields
- Field 1 contains a Runtime defined struct object main_MetricsHeader
    
    ```c
    // MetricsHeader: 16 bytes total
    typedef struct {
        uint8_t  Magic[8];  // 8 bytes at offset 0
        uint32_t Field1;    // 4 bytes at offset 8
        uint32_t Field2;    // 4 bytes at offset 12
    } main_MetricsHead
    ```
    
- Field 2 contains a Runtime defined slice object slice_main_ActionRecord that is 24 bytes, and it is a variable length array of main_ActionRecord objects
    
    ```c
    // Slice of ActionRecords: 24 bytes (Go slice structure)
    typedef struct {
        ActionRecord* Data; // 8 bytes: pointer to array
        uint64_t Length;    // 8 bytes: number of elements
        uint64_t Capacity;  // 8 bytes: allocated capacity
    } slice_main_ActionRecord
    ```
    
    Runtime defined struct main_ActionRecord storing a 4 byte and a 8 byte value:
    
    ```c
    // ActionRecord: 12 bytes total
    typedef struct {
        uint32_t Type;      // 4 bytes at offset 0
        uint64_t Value;     // 8 bytes at offset 4
    } main_ActionRecord;
    ```
    

Overall Structure of main_MetricsData

```
MetricsData (0x28)
├─ MetricsHeader           @0x00 .. 0x0F   (struct, 16 B)
└─ Actions (slice)         @0x10 .. 0x27   (24 B total)
   ├─ data ( *ActionRecord )  @0x10
   ├─ len (int)               @0x18
   └─ cap (int)               @0x20
```

#### main.determineAudioResource function:

Subsequently, after the `MetricsData` function, the `main.determineAudioResource` function is executed. Immediately, an if statement that returns `assets/flag.mp3` catches my eye.

If statement `flag.mp3`:

```c
  if ( (unsigned __int8)main_evaluateMetricsQuality(a1, a2, a3, a4, a5, a6, a7, a8, a9) )
    return "assets/flag.mp3HalfClosedLocal";
```

 Analysis:

- If the `main_evaluateMetricsQuality` function returns a non-zero value, then the `"assets/flag.mp3HalfClosedLocal"` string will be returned, which is seemingly the win condition

#### main_evaluateMetricsQuality function:

**Baseline Metric variable:**

Taking a look at the `evaluateMetricsQuality` function, we see the `main_computeMetricsBaseline()` function. It see

Example:

```
v9 = (_DWORD *)main_computeMetricsBaseline(a1, a2, a3, a4, a5, a6, a7, a8, a9);
```

Analysis:

- Since this baseline metric value is constant, I chose to it derive it from dynamic analysis in ida.

Dynamic analysis:

Looking at v9 variable intialization:

```
_DWORD *v9; // rax
```

Setting a breakpoint before and after main_computeMetricsBaseline:

![image.png](assets/img/TISC_2025/Set_Breakpoint.png)

Stepping through the function and observing the RAX register:

![image.png](assets/img/TISC_2025/RAX_register.png)

Looking at `debug003:000000C000452000` memory address:

```
debug003:000000C000452000 db    1    
debug003:000000C000452001 db    0
debug003:000000C000452002 db    0
debug003:000000C000452003 db    0
debug003:000000C000452004 db    0
debug003:000000C000452005 db    0
debug003:000000C000452006 db    0
debug003:000000C000452007 db    0
debug003:000000C000452008 db    0
debug003:000000C000452009 db    0
debug003:000000C00045200A db    0
debug003:000000C00045200B db    0
debug003:000000C00045200C db    5
debug003:000000C00045200D db    0
```

Keeping `12 * 3` DWORDs worth of values:

```
0:  (1, 0, 0)
1:  (5, 3, 0)
2:  (6, 7, 0)
3:  (2, 0, 0)
4:  (5, 1, 0)
5:  (6, 2, 0)
6:  (1, 0, 0)
7:  (5, 6, 0)
8:  (6, 5, 0)
9:  (3, 0, 0)
10: (5, 4, 0)
11: (6, 0, 0)
```
Note that this will be important and elaborated later on

**User input derived ActionRecord Array:**

Overall Structure of main_MetricsData

```
MetricsData (0x28)
├─ MetricsHeader           @0x00 .. 0x0F   (struct, 16 B)
└─ Actions (slice)         @0x10 .. 0x27   (24 B total)
   ├─ data ( *ActionRecord )  @0x10
   ├─ len (int)               @0x18
   └─ cap (int)               @0x20
```

Initializing pointer to the slice:

```c
// Value of the len attribute (int) within the Actions slice object 
// An integer indicating number of ActionRecord entries
v11 = *(_QWORD *)(a1 + 24);
// Value of the data attribute (Pointer) of the Actions slice object
// A pointer to an array like object of ActionRecord entries
v12 = *(_QWORD *)(a1 + 16);

// checking if there are at least a2 or 12 number of ActionRecord entries
if ( a2 > v11 )
  return 0;
```

Building `v15` ActionRecord Array:

```c
v13 = v11 - 1;  // Start at last index 11 (most recent action)
while ( v13 >= 0 && v16 < a2 + 5 )
{
    v18 = *(_DWORD *)(v12 + 12 * v13);  // Get Type of action at index v13
    if ( v18 != 4 )  // Filter out Type-4 Actions
        {
                // Creating a new ActionRecord array Type (4 bytes) Value (8 bytes)
                p__1_main_ActionRecord = (_1_main_ActionRecord *)runtime_newobject(
                                                   &RTYPE__1_main_ActionRecord,
                                                   a2,
                                                   v14,
                                                   (int)v15,
                                                   v12,
                                                   v16,
                                                   3 * (int)v13,
                                                   v18,
                                                   v10);
                v34 = 3 * v13; 
                v25 = *(_QWORD *)(v12 + 4 * v34 + 4);  // Read 8-byte Value
                *(_DWORD *)p__1_main_ActionRecord = *(_DWORD *)(v12 + 4 * v34);  // Copy Type
                *(_QWORD *)&(*p__1_main_ActionRecord)[0].Value = v25;  // Copy Value
                v38 = (main_ActionRecord *)p__1_main_ActionRecord;  // v38 is a pointer to new p__1_main_ActionRecord
          runtime_memmove(&(*p__1_main_ActionRecord)[1], v15, 12 * v24);  // prepending v15 (old p__1_main_ActionRecord) behind v38
          v15 = v38;  // updating v15 to the updated p__1_main_ActionRecord array
          
        }
}
```

Analysis:

- This code, uses 2 variables `v11` and `v12`, which `v11` is an integer indicating number of ActionRecord entries and `v12` is a pointer to an array like object of ActionRecord entries
- These 2 records, which extracted from `a1`, is a MetricsData struct object, which was previously initialized using HTTP POST request binary data

Reading in data:

- This code, proceeds to read both the 4 byte `uint32_t Type` and the 8 byte `uint64_t Value` attribute from each of the ActionRecord struct entries (ignoring the ActionRecord entries with the Type attribute set to ‘4’)

Writing the data:

- Then proceeds to copy the 4 byte Type and 8 byte Value values into a `RTYPE__1_main_ActionRecord` object, which is an array like object

**User ActionRecord Slice validated against Baseline Metrics Slice**

Validation feature:

```c
v27 = v14 - a2;
for ( i = 0; a2 > i; ++i )
  { 
    if ( v14 <= (unsigned __int64)(i + v27) )
      runtime_panicIndex(i + v27);
    v29 = *v9;
    if ( v15[i + v27].Type != *v9 )
      return 0;
    if ( (v29 == 5 || v29 == 6) && v15[i + v27].Value != v9[1] )
      return 0;
    v9 += 3;
  }
```

Analysis:

- The above is the extract of code that implements the validation feature that determines if the function returns 1 and subsequently prompts sending over the `flag.mp3`
- Iterates `a2` times, which through dynamic analysis reveals that `a2 = 12`, meaning 12 comparisons are made
- As observed above, `v9` is the baseline metric and `v15` is the user derived ActionRecord array both containing “Type Value” pair values
- Comparison 1: Collected action Type `v15[i + v27].Type` compared against `*v9`
    - The i-th recent action’s Type must match the i-th expected baseline Type
- Comparison 2: For `*v9 == 5 || *v9 == 6`, Collected action Value `v15[i + v27].Value` compared against `v9[1]`
    - For the i-th recent action’s Type 5 and 6, both the i-th recent action’s Value and the i-th expected baseline Value must match.
- `v9` pointer then increments by 3 (For every 3 values stored at the v9 pointer, only the first 2 correspond to Type and Value respectively, the 3rd value is a dummy)

Conclusions:

- This means that both `v15`'s action slice and `v9`’s baseline metric slice should contain a minimum of 12  total pairs of “Type Value” pair of values, excluding Type = 4 entries.
- As for the baseline metrics `v9`, this is why i collected `12 * 3` DWORDs of data from above
- As for the ActionRecords array `v15`, the baseline metric `v9` will dictate what is sent over via the HTTP POST request data payload.

### Building the Payload

User input:

```
Format: (Type, Value)
0:  (1, 0)
1:  (5, 3)
2:  (6, 7)
3:  (2, 0)
4:  (5, 1)
5:  (6, 2)
6:  (1, 0)
7:  (5, 6)
8:  (6, 5)
9:  (3, 0)
10: (5, 4)
11: (6, 0)
```

Analysis:

- As explained above, since the ActionRecords array is constructed using the user input, and then compared with the baseline metric, the user input has to be constructed with the baseline metric data in mind
- As we determined from above as well, since the baseline metric has a redundant row of information (ie. every increment of 3 positions only the first 2 values represent Type and Value), hence the last row of value can be deleted
- We are now left with the raw unformatted data that when formatted correctly and sent to the server should be enough to return the `flag.mp3`

#### Building the script with GPT:

Understanding that the main_parseMetrics function is highly complicated, I decided to rely on ChatGPT to produce the POC script used to convert the array like unformatted data into a binary payload that can be sent to the server to extract file.

Generated code:

```python
#!/usr/bin/env python3
import struct, sys, os

## Actions in the exact order you gave (type, value)
ACTIONS = [
    (1,  0),
    (5,  3),
    (6,  7),
    (2,  0),
    (5,  1),
    (6,  2),
    (1,  0),
    (5,  6),
    (6,  5),
    (3,  0),
    (5,  4),
    (6,  0),
]

def checksum(actions):
    v = len(actions) & 0xFFFFFFFF
    for t, val in actions:
        lo = val & 0xFFFFFFFF
        hi = (val >> 32) & 0xFFFFFFFF
        mix = (t ^ lo ^ (hi & 0xFF)) & 0xFFFFFFFF
        v ^= mix
        v &= 0xFFFFFFFF
    return v

def build(actions, hdr0=0, hdr1=0):
    cnt = len(actions)
    chk = checksum(actions)
    data = struct.pack('<IIII', hdr0, hdr1, cnt, chk)
    for t, val in actions:
        lo = val & 0xFFFFFFFF
        hi = (val >> 32) & 0xFFFFFFFF
        data += struct.pack('<III', t, lo, hi)
    return data, chk

if __name__ == '__main__':
    payload, chk = build(ACTIONS)
    out = 'payload.bin'
    with open(out, 'wb') as f:
        f.write(payload)
    print(f'Wrote {out} ({len(payload)} bytes)')
    print(f'count={len(ACTIONS)}, checksum=0x{chk:08X}')
    ## Handy one-liners to send it:
    url = os.environ.get('URL', 'http://127.0.0.1:8080/your-endpoint')
    print('\nSend with curl (file):')
    print(f"curl -X POST '{url}' -H 'Content-Type: application/octet-stream' --data-binary '@{out}'")
    print('\nSend with curl (no temp file, process substitution):')
    print(f"curl -X POST '{url}' -H 'Content-Type: application/octet-stream' --data-binary @<(python3 {os.path.basename(__file__) } --emit)")

```

#### Sending the payload:

After obtaining the payload, and crafting the HTTP POST request. I sent the request and received an mp3 file that read out the flag in full

HTTP POST Request:

```bash
$ curl 'http://chals.tisc25.ctf.sg:57190/?t=1758962810033' \   
  -H 'Accept: */*' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  -H 'Connection: keep-alive' \
  -H 'DNT: 1' \
  -H 'H: 52' \
  -H 'Origin: http://chals.tisc25.ctf.sg:57190' \
  -H 'R: application/octet-stream' \
  -H 'Referer: http://chals.tisc25.ctf.sg:57190/' \
  -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36' \
  --data-binary @payload.bin --output output.mp3
```

Flag: `TISC{PR3551NG_BUTT0N5_4ND_TURN1NG_KN0B5_4_S3CR3T_S0NG_FL4G}`

### Thoughts:

This was one of the first reverse engineering challenges I embarked on. To be honest, I felt slightly overwhelmed and lost when I first looked at the decompiled binary. However, with a bit of determination (and some help from AI XD) I managed to find my way through.

One key takeaway from this challenge was the importance of leveraging IDA’s dynamic analysis features to understand the binary’s behavior. This approach fortunately saved me the effort of going through certain sections line by line.

One area I still struggle with is confidently renaming variables and interpreting runtime-generated functions and variables, as these remain the most intimidating aspects of reverse engineering challenges for me.