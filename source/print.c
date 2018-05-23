#include "../include/ft_strace.h"

extern const t_syscall	g_syscall_table[330];

void	print_rdi(struct user_regs_struct *regs)
{
	if (g_syscall_table[regs->orig_rax].rdi == SIGNED) {
		printf("%d", (int)regs->rdi);
	}
	else if (g_syscall_table[regs->orig_rax].rdi == UNSIGNED) {
		printf("%llu", regs->rdi);
	}
	else if (g_syscall_table[regs->orig_rax].rdi == PTR)
		printf("0x%llx", regs->rdi);
	else if (g_syscall_table[regs->orig_rax].rdi == NONE)
		__asm__("nop");
	else
		printf("?");
}

void	print_rsi(struct user_regs_struct *regs)
{
	if (g_syscall_table[regs->orig_rax].rsi == SIGNED) {
		printf(", %d", (int)regs->rsi);
	}
	else if (g_syscall_table[regs->orig_rax].rsi == UNSIGNED) {
		printf(", %llu", regs->rsi);
	}
	else if (g_syscall_table[regs->orig_rax].rsi == PTR)
		printf(", 0x%llx", regs->rsi);
	else if (g_syscall_table[regs->orig_rax].rsi == NONE)
		__asm__("nop");
	else
		printf(", ?");
}

void	print_rdx(struct user_regs_struct *regs)
{
	if (g_syscall_table[regs->orig_rax].rdx == SIGNED) {
		printf(", %d", (int)regs->rdx);
	}
	else if (g_syscall_table[regs->orig_rax].rdx == UNSIGNED) {
		printf(", %llu", regs->rdx);
	}
	else if (g_syscall_table[regs->orig_rax].rdx == PTR)
		printf(", 0x%llx", regs->rdx);
	else if (g_syscall_table[regs->orig_rax].rdx == NONE)
		__asm__("nop");
	else
		printf(", ?");
}

void	print_r10(struct user_regs_struct *regs)
{
	if (g_syscall_table[regs->orig_rax].r10 == SIGNED) {
		printf(", %d", (int)regs->r10);
	}
	else if (g_syscall_table[regs->orig_rax].r10 == UNSIGNED) {
		printf(", %llu", regs->r10);
	}
	else if (g_syscall_table[regs->orig_rax].r10 == PTR)
		printf(", 0x%llx", regs->r10);
	else if (g_syscall_table[regs->orig_rax].r10 == NONE)
		__asm__("nop");
	else
		printf(", ?");
}

void	print_r8(struct user_regs_struct *regs)
{
	if (g_syscall_table[regs->orig_rax].r8 == SIGNED) {
		printf(", %d", (int)regs->r8);
	}
	else if (g_syscall_table[regs->orig_rax].r8 == UNSIGNED) {
		printf(", %llu", regs->r8);
	}
	else if (g_syscall_table[regs->orig_rax].r8 == PTR)
		printf(", 0x%llx", regs->r8);
	else if (g_syscall_table[regs->orig_rax].r8 == NONE)
		__asm__("nop");
	else
		printf(", ?");
}

void	print_r9(struct user_regs_struct *regs)
{
	if (g_syscall_table[regs->orig_rax].r9 == SIGNED) {
		printf(", %d", (int)regs->r9);
	}
	else if (g_syscall_table[regs->orig_rax].r9 == UNSIGNED) {
		printf(", %llu", regs->r9);
	}
	else if (g_syscall_table[regs->orig_rax].r9 == PTR)
		printf(", 0x%llx", regs->r9);
	else if (g_syscall_table[regs->orig_rax].r9 == NONE)
		__asm__("nop");
	else
		printf(", ?");
}

void	print(struct user_regs_struct *regs, int loop)
{
	if (!(loop % 2)) // first time getting all param register and seconde time to get ret stored in rax
	{
		printf("%s", g_syscall_table[regs->orig_rax].name);
		printf("(");
		print_rdi(regs);
		print_rsi(regs);
		print_rdx(regs);
		print_r10(regs);
		print_r8(regs);
		print_r9(regs);
		printf(")");
	}
	else
		printf("\t= %d\n", (long long int)regs->rax);

}
