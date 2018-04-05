starce ./hello

Output :

```
execve("./hello", ["./hello"], [/* 15 vars */]) = 0
brk(NULL)                               = 0x680000
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
open("/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=15584, ...}) = 0
mmap(NULL, 15584, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f90006e6000
close(3)                                = 0
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0P\t\2\0\0\0\0\0"..., 832) = 832
fstat(3, {st_mode=S_IFREG|0755, st_size=1868984, ...}) = 0
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f90006e5000
mmap(NULL, 3971488, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f90000fb000
mprotect(0x7f90002bb000, 2097152, PROT_NONE) = 0
mmap(0x7f90004bb000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1c0000) = 0x7f90004bb000
mmap(0x7f90004c1000, 14752, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f90004c1000
close(3)                                = 0
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f90006e4000
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f90006e3000
arch_prctl(ARCH_SET_FS, 0x7f90006e4700) = 0
mprotect(0x7f90004bb000, 16384, PROT_READ) = 0
mprotect(0x600000, 4096, PROT_READ)     = 0
mprotect(0x7f90006ea000, 4096, PROT_READ) = 0
munmap(0x7f90006e6000, 15584)           = 0
write(1, "Hello", 5Hello)                    = 5
exit_group(0)                           = ?
+++ exited with 0 +++
```

```
syscall_name() + padding + = + ret value
```

```
Note : padding with at least 32 space charactere
```

```
exit_group(0) = ? # value returned
```

and

```
+++ exit with 0 +++ # value returned in uint8_t (can overflow)
```
