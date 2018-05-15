#include "../include/ft_strace.h"

extern const t_syscall	g_syscall_table[330];

void	print_rdi(struct user_regs_struct *regs)
{
	if (g_syscall_table[regs->orig_rax].rdi == NUMBER) {
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
	if (g_syscall_table[regs->orig_rax].rsi == NUMBER) {
		printf(", %lld", regs->rsi);
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
	if (g_syscall_table[regs->orig_rax].rdx == NUMBER) {
		printf(", %lld", regs->rdx);
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
	if (g_syscall_table[regs->orig_rax].r10 == NUMBER) {
		printf(", %lld", regs->r10);
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
	if (g_syscall_table[regs->orig_rax].r8 == NUMBER) {
		printf(", %lld", regs->r8);
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
	if (g_syscall_table[regs->orig_rax].r9 == NUMBER) {
		printf(", %lld", regs->r9);
	}
	else if (g_syscall_table[regs->orig_rax].r9 == PTR)
		printf(", 0x%llx", regs->r9);
	else if (g_syscall_table[regs->orig_rax].r9 == NONE)
		__asm__("nop");
	else
		printf(", ?");
}

void	print(struct user_regs_struct *regs)
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
	printf("\t= %llu\n", regs->rax);
}
