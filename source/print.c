#include "../include/ft_strace.h"

extern const t_syscall	g_syscall_table[330];
extern const t_errno	g_errno_table[134];

static void	print_rdi(struct user_regs_struct *regs, int child, char *buffer)
{
	long	addr = 0;
	uint64_t	incr = 0;

	if (g_syscall_table[regs->orig_rax].rdi == SIGNED)
		sprintf(buffer, "%d", (int)regs->rdi);
	else if (g_syscall_table[regs->orig_rax].rdi == UNSIGNED)
		sprintf(buffer, "%llu", regs->rdi);
	else if (g_syscall_table[regs->orig_rax].rdi == PTR)
		sprintf(buffer, "0x%llx", regs->rdi);
	else if (g_syscall_table[regs->orig_rax].rdi == STRING) {
		sprintf(buffer, "\"");
		++buffer;
		while (true) {
			addr = ptrace(PTRACE_PEEKDATA, child, regs->rdi + incr, NULL);
			if (addr == -1)
				break;
			sprintf(buffer, "%s", (char *)&addr);
			if (memchr(&addr, 0, sizeof(addr))) {
				buffer += strlen((char *)&addr);
				break ;
			}
			buffer += sizeof(addr);
			incr += sizeof(addr);
		}
		sprintf(buffer, "\"");
		/*print_reg_as_str(regs, child);*/ // Why output differ when i call the function ?
	}
	else if (g_syscall_table[regs->orig_rax].rdi == NONE)
		__asm__("nop");
	else
		printf("?");
}

static void	print_rsi(struct user_regs_struct *regs, int child, char *buffer)
{
	long		addr = 0;
	uint64_t	incr = 0;

	memset(buffer, 0, 256);
	if (g_syscall_table[regs->orig_rax].rsi == SIGNED)
		sprintf(buffer, ", %d", (int)regs->rsi);
	else if (g_syscall_table[regs->orig_rax].rsi == UNSIGNED)
		sprintf(buffer, ", %llu", regs->rsi);
	else if (g_syscall_table[regs->orig_rax].rsi == PTR)
		sprintf(buffer, ", 0x%llx", regs->rsi);
	else if (g_syscall_table[regs->orig_rax].rsi == STRING) {
		strcat(buffer, ", \"");
		while (true) {
			addr = ptrace(PTRACE_PEEKDATA, child, regs->rsi + incr, NULL);
			if (addr == -1)
				break;
			strncat(buffer, (char *)&addr, sizeof(addr));
			if (memchr(&addr, 0, sizeof(addr)) || incr > 23) {
				buffer += strlen((char *)&addr);
				break ;
			}
			incr += sizeof(addr);
		}
		if (regs->rax > 32)
			strcat(buffer, "\"...");
		else
			strcat(buffer, "\"");
		/*sprintf(buffer, "\"");*/
		/*print_reg_as_str(regs, child);*/ // Why output differ when i call the function ?
	}
	else if (g_syscall_table[regs->orig_rax].rsi == NONE)
		__asm__("nop");
	else
		sprintf(buffer, ", ?");
}

static void	print_rdx(struct user_regs_struct *regs, int child, char *buffer)
{
	long	addr = 0;

	if (g_syscall_table[regs->orig_rax].rdx == SIGNED)
		sprintf(buffer, ", %d", (int)regs->rdx);
	else if (g_syscall_table[regs->orig_rax].rdx == UNSIGNED)
		sprintf(buffer, ", %llu", regs->rdx);
	else if (g_syscall_table[regs->orig_rax].rdx == PTR)
		sprintf(buffer, ", 0x%llx", regs->rdx);
	else if (g_syscall_table[regs->orig_rax].rdx == STRING) {
		addr = ptrace(PTRACE_PEEKDATA, child, regs->rdx, NULL);
		sprintf(buffer, ", \"%s\"", (char *)&addr);
	}
	else if (g_syscall_table[regs->orig_rax].rdx == NONE)
		__asm__("nop");
	else
		sprintf(buffer, ", ?");
}

static void	print_r10(struct user_regs_struct *regs, int child, char *buffer)
{
	long	addr = 0;

	if (g_syscall_table[regs->orig_rax].r10 == SIGNED)
		sprintf(buffer, ", %d", (int)regs->r10);
	else if (g_syscall_table[regs->orig_rax].r10 == UNSIGNED)
		sprintf(buffer, ", %llu", regs->r10);
	else if (g_syscall_table[regs->orig_rax].r10 == PTR)
		sprintf(buffer, ", 0x%llx", regs->r10);
	else if (g_syscall_table[regs->orig_rax].r10 == STRING) {
		addr = ptrace(PTRACE_PEEKDATA, child, regs->r10, NULL);
		sprintf(buffer, ", \"%s\"", (char *)&addr);
	}
	else if (g_syscall_table[regs->orig_rax].r10 == NONE)
		__asm__("nop");
	else
		sprintf(buffer, ", ?");
}

static void	print_r8(struct user_regs_struct *regs, int child, char *buffer)
{
	long	addr = 0;

	if (g_syscall_table[regs->orig_rax].r8 == SIGNED) {
		sprintf(buffer, ", %d", (int)regs->r8);
	}
	else if (g_syscall_table[regs->orig_rax].r8 == UNSIGNED) {
		sprintf(buffer, ", %llu", regs->r8);
	}
	else if (g_syscall_table[regs->orig_rax].r8 == PTR)
		sprintf(buffer, ", 0x%llx", regs->r8);
	else if (g_syscall_table[regs->orig_rax].r8 == STRING) {
		addr = ptrace(PTRACE_PEEKDATA, child, regs->r8, NULL);
		sprintf(buffer, ", \"%s\"", (char *)&addr);
	}
	else if (g_syscall_table[regs->orig_rax].r8 == NONE)
		__asm__("nop");
	else
		sprintf(buffer, ", ?");
}

static void	print_r9(struct user_regs_struct *regs, int child, char *buffer)
{
	long	addr = 0;

	if (g_syscall_table[regs->orig_rax].r9 == SIGNED)
		sprintf(buffer, ", %d", (int)regs->r9);
	else if (g_syscall_table[regs->orig_rax].r9 == UNSIGNED)
		sprintf(buffer, ", %llu", regs->r9);
	else if (g_syscall_table[regs->orig_rax].r9 == PTR)
		sprintf(buffer, ", 0x%llx", regs->r9);
	else if (g_syscall_table[regs->orig_rax].r9 == STRING) {
		addr = ptrace(PTRACE_PEEKDATA, child, regs->r9, NULL);
		sprintf(buffer, ", \"%s\"", (char *)&addr);
	}
	else if (g_syscall_table[regs->orig_rax].r9 == NONE)
		__asm__("nop");
	else
		sprintf(buffer, ", ?");
}

static void	print_rax(struct user_regs_struct *regs, char *buffer)
{
	if (regs->orig_rax == EXIT_GROUP)
		sprintf(buffer, "\t= ?");
	else if ((long long int)regs->rax < 0)
		sprintf(buffer, "\t= -1 %s (%s)", g_errno_table[((long long int)regs->rax * -1)].define,
									g_errno_table[((long long int)regs->rax * -1)].desc);
	else
		sprintf(buffer, "\t= %lld", (long long int)regs->rax);
}

void	print(struct user_regs_struct *regs, int loop, int child)
{
	static char	*array[11];
	if (loop == 0) {
		for (int i = 0; i < 11; i++)
			array[i] = (char *)calloc(sizeof(char), 256);
	}

	if (!(loop % 2)) { // first time getting all param register and seconde time to get ret stored in rax

		sprintf(array[0], "%s", g_syscall_table[regs->orig_rax].name);
		sprintf(array[1], "(");
		print_rdi(regs, child, array[2]);
		if (regs->orig_rax != 0 || regs->orig_rax != 1)
			print_rsi(regs, child, array[3]);
		print_rdx(regs, child, array[4]);
		print_r10(regs, child, array[5]);
		print_r8(regs, child, array[6]);
		print_r9(regs, child, array[7]);
		sprintf(array[8], ")");
	}
	else {
		if (regs->orig_rax == 0 || regs->orig_rax == 1) {
			print_rsi(regs, child, array[3]);
		}
		print_rax(regs, array[10]);
		for (int i = 0; i < 11; i++) {
			dprintf(2, "%s", array[i]);
			memset(array[i], 0, 256);
		}
		dprintf(2, "\n");
	}
}
