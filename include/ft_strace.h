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

enum
{
	NONE,
	INT,
	U_INT,
	LONG,
	SIZE_T,
	CHAR_PTR
}			e_syscall;

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
	uint8_t			pad[1];
}					t_syscall;

void	usage(int argc);



#endif
