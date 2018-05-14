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

#define PTR 0
#define STRING 1
#define NUMBER 2
#define NONE 3


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
void	print(struct user_regs_struct *regs);
void	print_rdi(struct user_regs_struct *regs);
void	print_rsi(struct user_regs_struct *regs);
void	print_rdx(struct user_regs_struct *regs);
void	print_r10(struct user_regs_struct *regs);
void	print_r8(struct user_regs_struct *regs);
void	print_r9(struct user_regs_struct *regs);

#endif
