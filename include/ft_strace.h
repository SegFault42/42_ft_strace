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
#include <errno.h>
#include <sys/reg.h>

#define BUFF_MAX	4096

#define PTR		0
#define STRING	1
#define NUMBER	2
#define NONE	3

#define UINT8	1
#define UINT16	2
#define UINT32	4
#define UINT64	8
#define INT8	16
#define INT16	32
#define INT32	64
#define INT64	128

#define SIGNED		4
#define UNSIGNED	5

// store type for each syscall param

typedef struct		s_syscall
{
	char			*name;		// Name of syscall
	uint16_t		orig_rax;	// Syscall number
	uint8_t			rdi;		// first pa
	uint8_t			rsi;		// seconde param
	uint8_t			rdx;		// third param
	uint8_t			r10;		// four param
	uint8_t			r8;			// five param
	uint8_t			r9;			// six param
	//uint8_t			rax;		// ret_value
}					t_syscall;

void	usage(int argc);
void	print(struct user_regs_struct *regs, int loop);
void	print_rdi(struct user_regs_struct *regs);
void	print_rsi(struct user_regs_struct *regs);
void	print_rdx(struct user_regs_struct *regs);
void	print_r10(struct user_regs_struct *regs);
void	print_r8(struct user_regs_struct *regs);
void	print_r9(struct user_regs_struct *regs);
char	*get_path_bin(char *str);

#endif
