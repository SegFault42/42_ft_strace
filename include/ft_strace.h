#ifndef FT_STRACE
#define FT_STRACE

#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/reg.h>

#define BUFF_MAX	4096

//['struct ustat *', 'mqd_t', 'struct linux_dirent *', 'loff_t __user *', 'struct pollfd *', 'mode_t', 'size_t', 'timer_t *', 'unsigned int *', 'struct io_event *', 'gid_t *', 'unsigned', 'const struct itimerspec *', 'struct getcpu_cache *', 'const char *', 'const struct iovcc *', 'const cap_user_data_t', 'const stuct timespec *', 'const struct rlimit64 *', 'struct msgbuf *', 'const struct timespec *', 'struct pt_regs *', 'size_t *', 'unsigned *', 'struct msghdr *', 'const clockid_t', 'const char __user *', 'struct stat *', 'uid_t', 'struct msqid_ds *', 'struct rusage *', 'struct __sysctl_args *', 'fd_set*', 'umode_t', 'struct old_utsname *', 'qid_t', 'struct mmsghdr *', 'cap_user_header_t', 'aio_context_t', 'const har *', 'const unsigned long *', 'const int *', 'NONE', 'fd_set *', 'struct itimerspec *', 'struct sokaddr *', 'u32', 'key_serial_t', 'stack_t *', 'siginfo_t *', 'struct perf_event_attr *', 'char __user *', 'struct sigevent *', 'struct poll_fd *', 'struct timespec *', 'struct shmid_ds *', 'struct robust_list_head *', 'unsigned int', 'struct epoll_event *', 'clockid_t', '__u64', 'const chat *', 'const void *', 'int *', 'off_t *', 'const struct mq_attr *', 'struct utimbuf *', 'struct sched_param *', 'struct timex *', 'struct rlimit64 *', 'sigset_t *', 'struct statfs *', 'unsigned long *', 'uid_t *', 'u32 *', 'long', 'struct sockaddr *', 'struct sembuf *', 'struct siginfo *', 'cap_user_data_t', 'struct sigaction *', 'time_t *', 'const sigset_t *', 'gid_t', 'struct kexec_segment *', 'struct file_handle *', 'pid_t', 'timer_t', 'struct sysinfo *', 'const struct iovec *', 'void *', 'const struct sigevent *', 'loff_t', 'int', 'u64', 'struct iocb *', 'off_t', 'struct task_struct *', 'struct rlimit *', 'struct timeval *', 'ing', 'fconst char *', 'const struct sigaction *', 'unsigned long', '__s32', 'const struct iovec __user *', 'union bpf_attr *', 'struct linux_dirent64 *', 'const stack_t *', 'unsigned\nint', 'union semun', 'key_t', 'struct sched_attr __user *', 'struct mq_attr *', 'struct itimerval *', 'loff_t *', 'char *', 'aio_context_t *', 'unsigned char *', 'struct timezone *']

#define PTR 0
#define STR 1
#define NUMBER 2

enum
{
	STRUCT_ITIMERSPEC_PTR = PTR,
	CONST_CHAR_PTR = PTR,
	CONST_SIGSET_T_PTR = PTR,
	STRUCT_LINUX_DIRENT_PTR = PTR,
	UID_T,
	STRUCT_SIGINFO_PTR = PTR,
	STRUCT_SEMBUF_PTR = PTR,
	CONST_STRUCT_MQ_ATTR_PTR = PTR,
	LONG,
	AIO_CONTEXT_T,
	STRUCT_IO_EVENT_PTR = PTR,
	AIO_CONTEXT_T_PTR = PTR,
	STRUCT_PT_REGS_PTR = PTR,
	STRUCT_RLIMIT_PTR = PTR,
	STRUCT_KEXEC_SEGMENT_PTR = PTR,
	STRUCT_RUSAGE_PTR = PTR,
	OFF_T_PTR = PTR,
	STRUCT_STATFS_PTR = PTR,
	STRUCT_POLL_FD_PTR = PTR,
	LOFF_T_PTR = PTR,
	UNSIGNED_CHAR_PTR = PTR,
	STRUCT_SIGACTION_PTR = PTR,
	VOID_PTR = PTR,
	QID_T,
	MODE_T,
	STRUCT_UTIMBUF_PTR = PTR,
	CONST_CAP_USER_DATA_T,
	MQD_T,
	STRUCT_MQ_ATTR_PTR = PTR,
	STRUCT_EPOLL_EVENT_PTR = PTR,
	UNSIGNED_INT_PTR = PTR,
	STRUCT_SIGEVENT_PTR = PTR,
	OFF_T,
	CONST_STRUCT_RLIMIT64_PTR = PTR,
	TIMER_T_PTR = PTR,
	U32,
	UNSIGNED_LONG = 42,
	NONE,
	STRUCT_TIMESPEC_PTR = PTR,
	UMODE_T,
	TIMER_T,
	CONST_CLOCKID_T,
	UNSIGNED,
	CONST_STRUCT_SIGEVENT_PTR = PTR,
	CONST_STRUCT_ITIMERSPEC_PTR = PTR,
	STRUCT_SCHED_ATTR___USER_PTR = PTR,
	STRUCT_SOCKADDR_PTR = PTR,
	SIGSET_T_PTR = PTR,
	FD_SET_PTR = PTR,
	INT_PTR = PTR,
	UID_T_PTR = PTR,
	STRUCT_PERF_EVENT_ATTR_PTR = PTR,
	__U64,
	CONST_STRUCT_IOVCC_PTR = PTR,
	CONST_UNSIGNED_LONG_PTR = PTR,
	PID_T,
	INT,
	STRUCT_SYSINFO_PTR = PTR,
	ING,
	STRUCT_ITIMERVAL_PTR = PTR,
	STACK_T_PTR = PTR,
	STRUCT_POLLFD_PTR = PTR,
	STRUCT_TIMEZONE_PTR = PTR,
	STRUCT_IOCB_PTR = PTR,
	KEY_T,
	CONST_STACK_T_PTR = PTR,
	CONST_INT_PTR = PTR,
	LOFF_T,
	CHAR_PTR = PTR,
	STRUCT_FILE_HANDLE_PTR = PTR,
	CLOCKID_T,
	CONST_STUCT_TIMESPEC_PTR = PTR,
	KEY_SERIAL_T,
	LOFF_T___USER_PTR = PTR,
	STRUCT_TIMEVAL_PTR = PTR,
	STRUCT_USTAT_PTR = PTR,
	CHAR___USER_PTR = PTR,
	CONST_STRUCT_SIGACTION_PTR = PTR,
	CAP_USER_DATA_T,
	U32_PTR = PTR,
	STRUCT_RLIMIT64_PTR = PTR,
	STRUCT_SOKADDR_PTR = PTR,
	STRUCT_SCHED_PARAM_PTR = PTR,
	UNSIGNED_PTR = PTR,
	__S32,
	CONST_STRUCT_IOVEC_PTR = PTR,
	STRUCT_LINUX_DIRENT64_PTR = PTR,
	STRUCT_ROBUST_LIST_HEAD_PTR = PTR,
	CONST_VOID_PTR = PTR,
	STRUCT_MSQID_DS_PTR = PTR,
	CONST_STRUCT_IOVEC___USER_PTR = PTR,
	GID_T,
	FCONST_CHAR_PTR = PTR,
	SIZE_T_PTR = PTR,
	GID_T_PTR = PTR,
	STRUCT_STAT_PTR = PTR,
	STRUCT_OLD_UTSNAME_PTR = PTR,
	CONST_CHAT_PTR = PTR,
	STRUCT_TASK_STRUCT_PTR = PTR,
	STRUCT_MSGHDR_PTR = PTR,
	CONST_CHAR___USER_PTR = PTR,
	STRUCT___SYSCTL_ARGS_PTR = PTR,
	CAP_USER_HEADER_T,
	TIME_T_PTR = PTR,
	STRUCT_TIMEX_PTR = PTR,
	CONST_STRUCT_TIMESPEC_PTR = PTR,
	SIZE_T,
	UNSIGNED_INT = 42,
	STRUCT_SHMID_DS_PTR = PTR,
	STRUCT_MSGBUF_PTR = PTR,
	UNION_BPF_ATTR_PTR = PTR,
	U64,
	STRUCT_MMSGHDR_PTR = PTR,
	STRUCT_GETCPU_CACHE_PTR = PTR,
	FD_SETPTR = PTR,
	UNSIGNED_LONG_PTR = PTR,
	UNION_SEMUN,
	SIGINFO_T_PTR
}e_syscall;

typedef struct		s_syscall
{
	char			*name; // Name of syscall
	uint16_t		rax; // Syscall number
	uint8_t			rdi;
	uint8_t			rsi;
	uint8_t			rdx;
	uint8_t			r10;
	uint8_t			r8;
	uint8_t			r9;
}					t_syscall;

void	usage(int argc);



#endif
