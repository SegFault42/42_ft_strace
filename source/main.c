#include "../include/ft_strace.h"

const t_syscall	g_syscall_table[45] =
{
	{"read", 0, U_INT, CHAR_PTR, SIZE_T, NONE, NONE, NONE, {NONE}},
	{"write", 1, U_INT, CONST_CHAR_PTR, SIZE_T, NONE, NONE, NONE, {NONE}},
	{"open", 2, CONST_CHAR_PTR, INT, INT, NONE, NONE, NONE, {NONE}},
	{"close", 3, U_INT, NONE, NONE, NONE, NONE, NONE, {NONE}},
	{"stat", 4, CONST_CHAR_PTR, STRUCT_STAT_PTR, NONE, NONE, NONE, NONE, {NONE}},
	{"fstat", 5, U_INT, STRUCT_STAT_PTR, NONE, NONE, NONE, NONE, {NONE}},
	{"lstat", 6, FCONST_CHAR_PTR, STRUCT_STAT_PTR, NONE, NONE, NONE, NONE, {NONE}},
	{"poll", 7, STRUCT_POLL_FD_PTR, U_INT, LONG, NONE, NONE, NONE, {NONE}},
	{"lseek", 8, U_INT, OFF_T, U_INT, NONE, NONE, NONE, {NONE}},
	{"mmap", 9, U_LONG, U_LONG, U_LONG, U_LONG, U_LONG, U_LONG, {NONE}},
	{"mprotect", 10, U_LONG, SIZE_T, U_LONG, NONE, NONE, NONE, {NONE}},
	{"munmap", 11, U_LONG, SIZE_T, NONE, NONE, NONE, NONE, {NONE}},
	{"brk", 12, U_LONG, NONE, NONE, NONE, NONE, NONE, {NONE}},
	{"rt_sigaction", 13, INT, CONST_STRUCT_SIGACTION_PTR, STRUCT_SIG_ACTION_PTR, SIZE_T, NONE, NONE, {NONE}},
	{"rt_sigprocmask", 14, INT, SIGSET_T_PTR, SIGSET_T_PTR, SIZE_T, NONE, NONE, {NONE}},
	{"rt_sigreturn", 15, U_LONG, NONE, NONE, NONE, NONE, NONE, {NONE}},
	{"ioctl", 16, U_INT, U_INT, U_LONG, NONE, NONE, NONE, {NONE}},
	{"pread64", 17, U_LONG, CHAR_PTR, SIZE_T, LOFF_T, NONE, NONE, {NONE}},
	{"pwrite64", 18, U_INT, CONST_CHAR_PTR, SIZE_T, LOFF_T, NONE, NONE, {NONE}},
	{"readv", 19, U_LONG, CONST_STRUCT_IOVEC_PTR, U_LONG, NONE, NONE, NONE, {NONE}},
	{"writev", 20, U_LONG, CONST_STRUCT_IOVEC_PTR, U_LONG, NONE, NONE, NONE, {NONE}},
	{"access", 21, CONST_CHAR_PTR, INT, NONE, NONE, NONE, NONE, {NONE}},
	{"pipe", 22, INT_PTR, NONE, NONE, NONE, NONE, NONE, {NONE}},
	{"select", 23, INT, FD_SET_PTR, FD_SET_PTR, FD_SET_PTR, STRUCT_TIMEVAL_PTR, NONE, {NONE}},
	{"sched_yield", 24, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}},
	{"mremap", 25, U_LONG, U_LONG, U_LONG, U_LONG, U_LONG, NONE, {NONE}},
	{"msync", 26, U_LONG, SIZE_T, INT, NONE, NONE, NONE, {NONE}},
	{"mincore", 27, U_LONG, SIZE_T, U_CHAR_PTR, NONE, NONE, NONE, {NONE}},
	{"madvise", 28, U_LONG, SIZE_T, INT, NONE, NONE, NONE, {NONE}},
	{"shmget", 29, KEY_T, SIZE_T, INT, NONE, NONE, NONE, {NONE}},
	{"shmat", 30, INT, CHAR_PTR, INT, NONE, NONE, NONE, {NONE}},
	{"shmctl", 31, INT, INT, STRUCT_SCHMID_DS_PTR, NONE, NONE, NONE, {NONE}},
	{"dup", 32, U_INT, NONE, NONE, NONE, NONE, NONE, {NONE}},
	{"dup2", 33, U_INT, U_INT, NONE, NONE, NONE, NONE, {NONE}},
	{"pause", 34, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}},
	{"nanosleep", 35, STRUCT_TIMESPEC_PTR, STRUCT_TIMESPEC_PTR, NONE, NONE, NONE, NONE, {NONE}},
	{"getitimer", 36, INT, STRUCT_ITIMERVAL_PTR, NONE, NONE, NONE, NONE, {NONE}},
	{"alarm", 37, U_INT, NONE, NONE, NONE, NONE, NONE, {NONE}},
	{"setitimer", 38, INT, STRUCT_ITIMERVAL_PTR, STRUCT_ITIMERVAL_PTR, NONE, NONE, NONE, {NONE}},
	{"getpid", 39, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}},
	{"sendfile", 40, INT, INT, OFF_T_PTR, SIZE_T, NONE, NONE, {NONE}},
	{"socket", 41, INT, INT, INT, NONE, NONE, NONE, {NONE}},
	{"connect", 42, INT, STURCT_SOCKADDR_PTR, INT, NONE, NONE, NONE, {NONE}},
	{"accept", 43, INT, STURCT_SOCKADDR_PTR, INT_PTR, NONE, NONE, NONE, {NONE}},
	/*{"sendto", 44, INT, VOID_PTR, SIZE_T, unsigned, STURCT_SOCKADDR_PTR, INT},*/
	/*{"recvfrom", 45, INT, VOID_PTR, SIZE_T, unsigned, STURCT_SOCKADDR_PTR, INT_PTR},*/
	/*{"sendmsg", 46, INT, struct msghdr *, unsigned, NONE, NONE, NONE, {NONE}},*/
	/*{"recvmsg", 47, INT, struct msghdr *, U_INT, NONE, NONE, NONE, {NONE}},*/
	/*{"shutdown", 48, INT, INT, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"bind", 49, INT, struct sokaddr *, INT, NONE, NONE, NONE, {NONE}},*/
	/*{"listen", 50, INT, INT, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"getsockname", 51, INT, STURCT_SOCKADDR_PTR, INT_PTR, NONE, NONE, NONE, {NONE}},*/
	/*{"getpeername", 52, INT, STURCT_SOCKADDR_PTR, INT_PTR, NONE, NONE, NONE, {NONE}},*/
	/*{"socketpair", 53, INT, INT, INT, INT_PTR, NONE, NONE, {NONE}},*/
	/*{"setsockopt", 54, INT, INT, INT, CHAR_PTR, INT, NONE, {NONE}},*/
	/*{"getsockopt", 55, INT, INT, INT, CHAR_PTR, INT_PTR, NONE, {NONE}},*/
	/*{"clone", 56, U_LONG, U_LONG, VOID_PTR, VOID_PTR, NONE, NONE, {NONE}},*/
	/*{"fork", 57, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"vfork", 58, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"execve", 59, CONST_CHAR_PTR, CONST_CHAR_PTR, CONST_CHAR_PTR, NONE, NONE, NONE, {NONE}},*/
	/*{"exit", 60, INT, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"wait4", 61, PID_T, INT_PTR, INT, struct rusage *, NONE, NONE, {NONE}},*/
	/*{"kill", 62, PID_T, INT, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"uname", 63, struct old_utsname *, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"semget", 64, KEY_T, INT, INT, NONE, NONE, NONE, {NONE}},*/
	/*{"semop", 65, INT, struct sembuf *, unsigned, NONE, NONE, NONE, {NONE}},*/
	/*{"semctl", 66, INT, INT, INT, union semun, NONE, NONE, {NONE}},*/
	/*{"shmdt", 67, CHAR_PTR, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"msgget", 68, KEY_T, INT, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"msgsnd", 69, INT, struct msgbuf *, SIZE_T, INT, NONE, NONE, {NONE}},*/
	/*{"msgrcv", 70, INT, struct msgbuf *, SIZE_T, LONG, INT, NONE, {NONE}},*/
	/*{"msgctl", 71, INT, INT, struct msqid_ds *, NONE, NONE, NONE, {NONE}},*/
	/*{"fcntl", 72, U_INT, U_INT, U_LONG, NONE, NONE, NONE, {NONE}},*/
	/*{"flock", 73, U_INT, U_INT, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"fsync", 74, U_INT, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"fdatasync", 75, U_INT, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"truncate", 76, CONST_CHAR_PTR, LONG, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"ftruncate", 77, U_INT, U_LONG, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"getdents", 78, U_INT, struct linux_dirent *, U_INT, NONE, NONE, NONE, {NONE}},*/
	/*{"getcwd", 79, CHAR_PTR, U_LONG, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"chdir", 80, CONST_CHAR_PTR, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"fchdir", 81, U_INT, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"rename", 82, CONST_CHAR_PTR, CONST_CHAR_PTR, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"mkdir", 83, CONST_CHAR_PTR, INT, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"rmdir", 84, CONST_CHAR_PTR, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"creat", 85, CONST_CHAR_PTR, INT, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"link", 86, CONST_CHAR_PTR, CONST_CHAR_PTR, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"unlink", 87, CONST_CHAR_PTR, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"symlink", 88, CONST_CHAR_PTR, CONST_CHAR_PTR, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"readlink", 89, CONST_CHAR_PTR, CHAR_PTR, INT, NONE, NONE, NONE, {NONE}},*/
	/*{"chmod", 90, CONST_CHAR_PTR, mode_t, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"fchmod", 91, U_INT, mode_t, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"chown", 92, CONST_CHAR_PTR, uid_t, gid_t, NONE, NONE, NONE, {NONE}},*/
	/*{"fchown", 93, U_INT, uid_t, gid_t, NONE, NONE, NONE, {NONE}},*/
	/*{"lchown", 94, CONST_CHAR_PTR, uid_t, gid_t, NONE, NONE, NONE, {NONE}},*/
	/*{"umask", 95, INT, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"gettimeofday", 96, STRUCT_TIMEVAL_PTR, struct timezone *, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"getrlimit", 97, U_INT, struct rlimit *, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"getrusage", 98, INT, struct rusage *, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"sysinfo", 99, struct sysinfo *, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"times", 100, struct sysinfo *, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"ptrace", 101, LONG, LONG, U_LONG, U_LONG, NONE, NONE, {NONE}},*/
	/*{"getuid", 102, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"syslog", 103, INT, CHAR_PTR, INT, NONE, NONE, NONE, {NONE}},*/
	/*{"getgid", 104, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"setuid", 105, uid_t, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"setgid", 106, gid_t, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"geteuid", 107, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"getegid", 108, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"setpgid", 109, PID_T, PID_T, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"getppid", 110, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"getpgrp", 111, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"setsid", 112, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"setreuid", 113, uid_t, uid_t, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"setregid", 114, gid_t, gid_t, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"getgroups", 115, INT, gid_t *, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"setgroups", 116, INT, gid_t *, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"setresuid", 117, uid_t *, uid_t *, uid_t *, NONE, NONE, NONE, {NONE}},*/
	/*{"getresuid", 118, uid_t *, uid_t *, uid_t *, NONE, NONE, NONE, {NONE}},*/
	/*{"setresgid", 119, gid_t, gid_t, gid_t, NONE, NONE, NONE, {NONE}},*/
	/*{"getresgid", 120, gid_t *, gid_t *, gid_t *, NONE, NONE, NONE, {NONE}},*/
	/*{"getpgid", 121, PID_T, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"setfsuid", 122, uid_t, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"setfsgid", 123, gid_t, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"getsid", 124, PID_T, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"capget", 125, cap_user_header_t, cap_user_data_t, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"capset", 126, cap_user_header_t, const cap_user_data_t, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"rt_sigpending", 127, SIGSET_T_PTR, SIZE_T, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"rt_sigtimedwait", 128, const sigset_t *, siginfo_t *, const struct timespec *, SIZE_T, NONE, NONE, {NONE}},*/
	/*{"rt_sigqueueinfo", 129, PID_T, INT, siginfo_t *, NONE, NONE, NONE, {NONE}},*/
	/*{"rt_sigsuspend", 130, SIGSET_T_PTR, SIZE_T, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"sigaltstack", 131, const stack_t *, stack_t *, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"utime", 132, CHAR_PTR, struct utimbuf *, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"mknod", 133, CONST_CHAR_PTR, umode_t, unsigned, NONE, NONE, NONE, {NONE}},*/
	/*{"uselib", 134, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"personality", 135, U_INT, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"ustat", 136, unsigned, struct ustat *, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"statfs", 137, CONST_CHAR_PTR, struct statfs *, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"fstatfs", 138, U_INT, struct statfs *, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"sysfs", 139, INT, U_LONG, U_LONG, NONE, NONE, NONE, {NONE}},*/
	/*{"getpriority", 140, INT, INT, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"setpriority", 141, INT, INT, INT, NONE, NONE, NONE, {NONE}},*/
	/*{"sched_setparam", 142, PID_T, struct sched_param *, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"sched_getparam", 143, PID_T, struct sched_param *, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"sched_setscheduler", 144, PID_T, INT, struct sched_param *, NONE, NONE, NONE, {NONE}},*/
	/*{"sched_getscheduler", 145, PID_T, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"sched_get_priority_max", 146, INT, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"sched_get_priority_min", 147, INT, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"sched_rr_get_interval", 148, PID_T, STRUCT_TIMESPEC_PTR, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"mlock", 149, U_LONG, SIZE_T, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"munlock", 150, U_LONG, SIZE_T, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"mlockall", 151, INT, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"munlockall", 152, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"vhangup", 153, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"modify_ldt", 154, INT, VOID_PTR, U_LONG, NONE, NONE, NONE, {NONE}},*/
	/*{"pivot_root", 155, CONST_CHAR_PTR, CONST_CHAR_PTR, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"_sysctl", 156, struct __sysctl_args *, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"prctl", 157, INT, U_LONG, U_LONG, U_LONG, NONE, U_LONG},*/
	/*{"arch_prctl", 158, struct task_struct *, INT, U_LONG *, NONE, NONE, NONE, {NONE}},*/
	/*{"adjtimex", 159, struct timex *, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"setrlimit", 160, U_INT, struct rlimit *, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"chroot", 161, CONST_CHAR_PTR, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"sync", 162, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"acct", 163, CONST_CHAR_PTR, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"settimeofday", 164, STRUCT_TIMEVAL_PTR, struct timezone *, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"mount", 165, CHAR_PTR, CHAR_PTR, CHAR_PTR, U_LONG, VOID_PTR, NONE, {NONE}},*/
	/*{"umount2", 166, CONST_CHAR_PTR, INT, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"swapon", 167, CONST_CHAR_PTR, INT, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"swapoff", 168, CONST_CHAR_PTR, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"reboot", 169, INT, INT, U_INT, VOID_PTR, NONE, NONE, {NONE}},*/
	/*{"sethostname", 170, CHAR_PTR, INT, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"setdomainname", 171, CHAR_PTR, INT, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"iopl", 172, U_INT, struct pt_regs *, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"ioperm", 173, U_LONG, U_LONG, INT, NONE, NONE, NONE, {NONE}},*/
	/*{"create_module", 174, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"init_module", 175, VOID_PTR, U_LONG, CONST_CHAR_PTR, NONE, NONE, NONE, {NONE}},*/
	/*{"delete_module", 176, const chat *, U_INT, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"get_kernel_syms", 177, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"query_module", 178, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"quotactl", 179, U_INT, CONST_CHAR_PTR, qid_t, VOID_PTR, NONE, NONE, {NONE}},*/
	/*{"nfsservctl", 180, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"getpmsg", 181, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"putpmsg", 182, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"afs_syscall", 183, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"tuxcall", 184, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"security", 185, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"gettid", 186, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"readahead", 187, INT, LOFF_T, SIZE_T, NONE, NONE, NONE, {NONE}},*/
	/*{"setxattr", 188, CONST_CHAR_PTR, CONST_CHAR_PTR, const void *, SIZE_T, INT, NONE, {NONE}},*/
	/*{"lsetxattr", 189, CONST_CHAR_PTR, CONST_CHAR_PTR, const void *, SIZE_T, INT, NONE, {NONE}},*/
	/*{"fsetxattr", 190, INT, CONST_CHAR_PTR, const void *, SIZE_T, INT, NONE, {NONE}},*/
	/*{"getxattr", 191, CONST_CHAR_PTR, CONST_CHAR_PTR, VOID_PTR, SIZE_T, NONE, NONE, {NONE}},*/
	/*{"lgetxattr", 192, CONST_CHAR_PTR, CONST_CHAR_PTR, VOID_PTR, SIZE_T, NONE, NONE, {NONE}},*/
	/*{"fgetxattr", 193, INT, const har *, VOID_PTR, SIZE_T, NONE, NONE, {NONE}},*/
	/*{"listxattr", 194, CONST_CHAR_PTR, CHAR_PTR, SIZE_T, NONE, NONE, NONE, {NONE}},*/
	/*{"llistxattr", 195, CONST_CHAR_PTR, CHAR_PTR, SIZE_T, NONE, NONE, NONE, {NONE}},*/
	/*{"flistxattr", 196, INT, CHAR_PTR, SIZE_T, NONE, NONE, NONE, {NONE}},*/
	/*{"removexattr", 197, CONST_CHAR_PTR, CONST_CHAR_PTR, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"lremovexattr", 198, CONST_CHAR_PTR, CONST_CHAR_PTR, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"fremovexattr", 199, INT, CONST_CHAR_PTR, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"tkill", 200, PID_T, ing, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"time", 201, time_t *, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"futex", 202, u32 *, INT, u32, STRUCT_TIMESPEC_PTR, u32 *, u32},*/
	/*{"sched_setaffinity", 203, PID_T, U_INT, U_LONG *, NONE, NONE, NONE, {NONE}},*/
	/*{"sched_getaffinity", 204, PID_T, U_INT, U_LONG *, NONE, NONE, NONE, {NONE}},*/
	/*{"set_thread_area", 205, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"io_setup", 206, unsigned, aio_context_t *, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"io_destroy", 207, aio_context_t, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"io_getevents", 208, aio_context_t, LONG, LONG, struct io_event *, NONE, NONE, {NONE}},*/
	/*{"io_submit", 209, aio_context_t, LONG, struct iocb *, NONE, NONE, NONE, {NONE}},*/
	/*{"io_cancel", 210, aio_context_t, struct iocb *, struct io_event *, NONE, NONE, NONE, {NONE}},*/
	/*{"get_thread_area", 211, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"lookup_dcookie", 212, u64, LONG, LONG, NONE, NONE, NONE, {NONE}},*/
	/*{"epoll_create", 213, INT, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"epoll_ctl_old", 214, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"epoll_wait_old", 215, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"remap_file_pages", 216, U_LONG, U_LONG, U_LONG, U_LONG, U_LONG, NONE, {NONE}},*/
	/*{"getdents64", 217, U_INT, struct linux_dirent64 *, U_INT, NONE, NONE, NONE, {NONE}},*/
	/*{"set_tid_address", 218, INT_PTR, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"restart_syscall", 219, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"semtimedop", 220, INT, struct sembuf *, unsigned, const struct timespec *, NONE, NONE, {NONE}},*/
	/*{"fadvise64", 221, INT, LOFF_T, SIZE_T, INT, NONE, NONE, {NONE}},*/
	/*{"timer_create", 222, const clockid_t, struct sigevent *, timer_t *, NONE, NONE, NONE, {NONE}},*/
	/*{"timer_settime", 223, timer_t, INT, const struct itimerspec *, struct itimerspec *, NONE, NONE, {NONE}},*/
	/*{"timer_gettime", 224, timer_t, struct itimerspec *, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"timer_getoverrun", 225, timer_t, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"timer_delete", 226, timer_t, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"clock_settime", 227, const clockid_t, const struct timespec *, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"clock_gettime", 228, const clockid_t, STRUCT_TIMESPEC_PTR, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"clock_getres", 229, const clockid_t, STRUCT_TIMESPEC_PTR, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"clock_nanosleep", 230, const clockid_t, INT, const struct timespec *, STRUCT_TIMESPEC_PTR, NONE, NONE, {NONE}},*/
	/*{"exit_group", 231, INT, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"epoll_wait", 232, INT, struct epoll_event *, INT, INT, NONE, NONE, {NONE}},*/
	/*{"epoll_ctl", 233, INT, INT, INT, struct epoll_event *, NONE, NONE, {NONE}},*/
	/*{"tgkill", 234, PID_T, PID_T, INT, NONE, NONE, NONE, {NONE}},*/
	/*{"utimes", 235, CHAR_PTR, STRUCT_TIMEVAL_PTR, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"vserver", 236, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"mbind", 237, U_LONG, U_LONG, U_LONG, U_LONG *, U_LONG, unsigned},*/
	/*{"set_mempolicy", 238, INT, U_LONG *, U_LONG, NONE, NONE, NONE, {NONE}},*/
	/*{"get_mempolicy", 239, INT_PTR, U_LONG *, U_LONG, U_LONG, U_LONG, NONE, {NONE}},*/
	/*{"mq_open", 240, CONST_CHAR_PTR, INT, mode_t, struct mq_attr *, NONE, NONE, {NONE}},*/
	/*{"mq_unlink", 241, CONST_CHAR_PTR, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"mq_timedsend", 242, mqd_t, CONST_CHAR_PTR, SIZE_T, U_INT, const stuct timespec *, NONE, {NONE}},*/
	/*{"mq_timedreceive", 243, mqd_t, CHAR_PTR, SIZE_T, U_INT *, const struct timespec *, NONE, {NONE}},*/
	/*{"mq_notify", 244, mqd_t, const struct sigevent *, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"mq_getsetattr", 245, mqd_t, const struct mq_attr *, struct mq_attr *, NONE, NONE, NONE, {NONE}},*/
	/*{"kexec_load", 246, U_LONG, U_LONG, struct kexec_segment *, U_LONG, NONE, NONE, {NONE}},*/
	/*{"waitid", 247, INT, PID_T, struct siginfo *, INT, struct rusage *, NONE, {NONE}},*/
	/*{"add_key", 248, CONST_CHAR_PTR, CONST_CHAR_PTR, const void *, SIZE_T, NONE, NONE, {NONE}},*/
	/*{"request_key", 249, CONST_CHAR_PTR, CONST_CHAR_PTR, CONST_CHAR_PTR, key_serial_t, NONE, NONE, {NONE}},*/
	/*{"keyctl", 250, INT, U_LONG, U_LONG, U_LONG, U_LONG, NONE, {NONE}},*/
	/*{"ioprio_set", 251, INT, INT, INT, NONE, NONE, NONE, {NONE}},*/
	/*{"ioprio_get", 252, INT, INT, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"inotify_init", 253, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"inotify_add_watch", 254, INT, CONST_CHAR_PTR, u32, NONE, NONE, NONE, {NONE}},*/
	/*{"inotify_rm_watch", 255, INT, __s32, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"migrate_pages", 256, PID_T, U_LONG, const unsigned long *, const unsigned long *, NONE, NONE, {NONE}},*/
	/*{"openat", 257, INT, CONST_CHAR_PTR, INT, INT, NONE, NONE, {NONE}},*/
	/*{"mkdirat", 258, INT, CONST_CHAR_PTR, INT, NONE, NONE, NONE, {NONE}},*/
	/*{"mknodat", 259, INT, CONST_CHAR_PTR, INT, unsigned, NONE, NONE, {NONE}},*/
	/*{"fchownat", 260, INT, CONST_CHAR_PTR, uid_t, gid_t, INT, NONE, {NONE}},*/
	/*{"futimesat", 261, INT, CONST_CHAR_PTR, STRUCT_TIMEVAL_PTR, NONE, NONE, NONE, {NONE}},*/
	/*{"newfstatat", 262, INT, CONST_CHAR_PTR, STRUCT_STAT_PTR, INT, NONE, NONE, {NONE}},*/
	/*{"unlinkat", 263, INT, CONST_CHAR_PTR, INT, NONE, NONE, NONE, {NONE}},*/
	/*{"renameat", 264, INT, CONST_CHAR_PTR, INT, CONST_CHAR_PTR, NONE, NONE, {NONE}},*/
	/*{"linkat", 265, INT, CONST_CHAR_PTR, INT, CONST_CHAR_PTR, INT, NONE, {NONE}},*/
	/*{"symlinkat", 266, CONST_CHAR_PTR, INT, CONST_CHAR_PTR, NONE, NONE, NONE, {NONE}},*/
	/*{"readlinkat", 267, INT, CONST_CHAR_PTR, CHAR_PTR, INT, NONE, NONE, {NONE}},*/
	/*{"fchmodat", 268, INT, CONST_CHAR_PTR, mode_t, NONE, NONE, NONE, {NONE}},*/
	/*{"faccessat", 269, INT, CONST_CHAR_PTR, INT, NONE, NONE, NONE, {NONE}},*/
	/*{"pselect6", 270, INT, FD_SET_PTR, FD_SET_PTR, FD_SET_PTR, STRUCT_TIMESPEC_PTR, VOID_PTR},*/
	/*{"ppoll", 271, struct pollfd *, U_INT, STRUCT_TIMESPEC_PTR, const sigset_t *, SIZE_T, NONE, {NONE}},*/
	/*{"unshare", 272, U_LONG, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"set_robust_list", 273, struct robust_list_head *, SIZE_T, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"get_robust_list", 274, INT, struct robust_list_head *, SIZE_T *, NONE, NONE, NONE, {NONE}},*/
	/*{"splice", 275, INT, LOFF_T *, INT, LOFF_T *, SIZE_T, U_INT},*/
	/*{"tee", 276, INT, INT, SIZE_T, U_INT, NONE, NONE, {NONE}},*/
	/*{"sync_file_range", 277, LONG, LOFF_T, LOFF_T, LONG, NONE, NONE, {NONE}},*/
	/*{"vmsplice", 278, INT, CONST_STRUCT_IOVEC_PTR, U_LONG, U_INT, NONE, NONE, {NONE}},*/
	/*{"move_pages", 279, PID_T, U_LONG, const void *, const int *, INT_PTR, INT},*/
	/*{"utimensat", 280, INT, CONST_CHAR_PTR, STRUCT_TIMESPEC_PTR, INT, NONE, NONE, {NONE}},*/
	/*{"epoll_pwait", 281, INT, struct epoll_event *, INT, INT, const sigset_t *, SIZE_T},*/
	/*{"signalfd", 282, INT, SIGSET_T_PTR, SIZE_T, NONE, NONE, NONE, {NONE}},*/
	/*{"timerfd_create", 283, INT, INT, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"eventfd", 284, U_INT, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"fallocate", 285, LONG, LONG, LOFF_T, LOFF_T, NONE, NONE, {NONE}},*/
	/*{"timerfd_settime", 286, INT, INT, const struct itimerspec *, struct itimerspec *, NONE, NONE, {NONE}},*/
	/*{"timerfd_gettime", 287, INT, struct itimerspec *, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"accept4", 288, INT, STURCT_SOCKADDR_PTR, INT_PTR, INT, NONE, NONE, {NONE}},*/
	/*{"signalfd4", 289, INT, SIGSET_T_PTR, SIZE_T, INT, NONE, NONE, {NONE}},*/
	/*{"eventfd2", 290, U_INT, INT, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"epoll_create1", 291, INT, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"dup3", 292, U_INT, U_INT, INT, NONE, NONE, NONE, {NONE}},*/
	/*{"pipe2", 293, INT_PTR, INT, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"inotify_init1", 294, INT, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"preadv", 295, U_LONG, CONST_STRUCT_IOVEC_PTR, U_LONG, U_LONG, U_LONG, NONE, {NONE}},*/
	/*{"pwritev", 296, U_LONG, CONST_STRUCT_IOVEC_PTR, U_LONG, U_LONG, U_LONG, NONE, {NONE}},*/
	/*{"rt_tgsigqueueinfo", 297, PID_T, PID_T, INT, siginfo_t *, NONE, NONE, {NONE}},*/
	/*{"perf_event_open", 298, struct perf_event_attr *, PID_T, INT, INT, U_LONG, NONE, {NONE}},*/
	/*{"recvmmsg", 299, INT, struct msghdr *, U_INT, U_INT, STRUCT_TIMESPEC_PTR, NONE, {NONE}},*/
	/*{"fanotify_init", 300, U_INT, U_INT, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"fanotify_mark", 301, LONG, LONG, __u64, LONG, LONG, NONE, {NONE}},*/
	/*{"prlimit64", 302, PID_T, U_INT, const struct rlimit64 *, struct rlimit64 *, NONE, NONE, {NONE}},*/
	/*{"name_to_handle_at", 303, INT, CONST_CHAR_PTR, struct file_handle *, INT_PTR, INT, NONE, {NONE}},*/
	/*{"open_by_handle_at", 304, INT, CONST_CHAR_PTR, struct file_handle *, INT_PTR, INT, NONE, {NONE}},*/
	/*{"clock_adjtime", 305, clockid_t, struct timex *, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"syncfs", 306, INT, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"sendmmsg", 307, INT, struct mmsghdr *, U_INT, U_INT, NONE, NONE, {NONE}},*/
	/*{"setns", 308, INT, INT, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"getcpu", 309, unsigned *, unsigned *, struct getcpu_cache *, NONE, NONE, NONE, {NONE}},*/
	/*{"process_vm_readv", 310, PID_T, CONST_STRUCT_IOVEC_PTR, U_LONG, CONST_STRUCT_IOVEC_PTR, U_LONG, U_LONG},*/
	/*{"process_vm_writev", 311, PID_T, CONST_STRUCT_IOVEC_PTR, U_LONG, const struct iovcc *, U_LONG, U_LONG},*/
	/*{"kcmp", 312, PID_T, PID_T, INT, U_LONG, U_LONG, NONE, {NONE}},*/
	/*{"finit_module", 313, INT, const char __user *, INT, NONE, NONE, NONE, {NONE}},*/
	/*{"sched_setattr", 314, PID_T, struct sched_attr __user *, U_INT, NONE, NONE, NONE, {NONE}},*/
	/*{"sched_getattr", 315, PID_T, struct sched_attr __user *, U_INT, U_INT, NONE, NONE, {NONE}},*/
	/*{"renameat2", 316, INT, const char __user *, INT, const char __user *, U_INT, NONE, {NONE}},*/
	/*{"seccomp", 317, U_INT, U_INT, const char __user *, NONE, NONE, NONE, {NONE}},*/
	/*{"getrandom", 318, char __user *, SIZE_T, U_INT, NONE, NONE, NONE, {NONE}},*/
	/*{"memfd_create", 319, const char __user *, U_INT, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"kexec_file_load", 320, INT, INT, U_LONG, const char __user *, U_LONG, NONE, {NONE}},*/
	/*{"bpf", 321, INT, union bpf_attr *, U_INT, NONE, NONE, NONE, {NONE}},*/
	/*{"stub_execveat", 322, INT, const char __user *, const char __user *, const char __user *, INT, NONE, {NONE}},*/
	/*{"userfaultfd", 323, INT, NONE, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"membarrier", 324, INT, INT, NONE, NONE, NONE, NONE, {NONE}},*/
	/*{"mlock2", 325, U_LONG, SIZE_T, INT, NONE, NONE, NONE, {NONE}},*/
	/*{"copy_file_range", 326, INT, LOFF_T __user *, INT, LOFF_T __user *, SIZE_T, U_INT},*/
	/*{"preadv2", 327, U_LONG, const struct iovec __user *, U_LONG, U_LONG, U_LONG, INT},*/
	/*{"pwritev2", 328, U_LONG, const struct iovec __user *, U_LONG, U_LONG, U_LONG, INT},*/


	{NULL, NONE, NONE, NONE, NONE, NONE, NONE, NONE, {NONE}}
};

void	usage(int argc)
{
	if (argc == 1) {
		fprintf(stderr,
		"ft_strace: must have PROG [ARGS]\nTry 'strace -h' for more information.\n");
		exit (EXIT_FAILURE);
	}
}

int	main(int argc, char **argv)
{
	pid_t					child = 0;
	char					*const args[] = {NULL};
	int						status = 0;
	struct user_regs_struct	regs;
	uint64_t				old = 0;
	char message[1000];
	char* temp_char2 = message;

	usage(argc);
	child = fork();
	if (child == -1) {
		perror("fork()");
	}
	else if (child == 0) {
		execvp(argv[1], args);
	} else {
		kill(child, SIGSTOP);
		ptrace(PTRACE_SEIZE, child, NULL, NULL);
		waitpid(child, &status, 0);
		while (1) {
			ptrace(PTRACE_SYSCALL, child, NULL, NULL);
			waitpid(child, &status, 0);
			ptrace(PTRACE_GETREGS, child, NULL, &regs);
			/*printf("orig_rax : 0x%llx\t | ", regs.orig_rax);*/
			/*if (regs.rdi != 0x0) {*/
				/*printf("rdi : %llx\t |", regs.rdi);*/
			/*} else {*/
				/*printf("NULL |");*/
			/*}*/

			/*if (regs.orig_rax == 0x0) {*/
				/*if ()*/
				/*[>sprintf(fdpath,"/proc/%u/fd/%llu", child, regs.rdi);<]*/
				/*[>size = readlink(fdpath, &filepath, 256);<]*/
				/*[>filepath[size] = '\0';<]*/
				/*[>printf("File-%s-\n", filepath);<]*/
			/*}*/
				printf("Syscall = %s\t| ", g_syscall_table[regs.orig_rax].name);
				if (g_syscall_table[regs.orig_rax].rdi == U_INT) {
					printf("rdi = %lld\t| ", regs.rdi);
				}
				if (g_syscall_table[regs.orig_rax].rsi == CHAR_PTR) {
					printf("rsi = %llu", regs.rsi);
				}
			old = regs.orig_rax;
			puts("");
			ptrace(PTRACE_SYSCALL, child, NULL, NULL);
			waitpid(child, &status, 0);
			if (WIFEXITED(status))
				break ;
		}
	}
	return (0);
}
