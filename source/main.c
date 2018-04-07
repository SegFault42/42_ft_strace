#include "../include/ft_strace.h"

const t_syscall	g_syscall_table[2] =
{
	{"read", 0, U_INT, CHAR_PTR, SIZE_T, NONE, NONE, NONE, {NONE}},
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
			if (regs.orig_rax == 0x0) {
				printf("Syscall = %s\t| ", g_syscall_table[regs.orig_rax].name);
				if (g_syscall_table[regs.orig_rax].rdi == U_INT) {
					printf("rdi = %lld\t| ", regs.rdi);
				}
				if (g_syscall_table[regs.orig_rax].rsi == CHAR_PTR) {
					printf("rsi = %llu", regs.rsi);
				}
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
