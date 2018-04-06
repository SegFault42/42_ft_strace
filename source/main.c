#include "../include/ft_strace.h"

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
	uint64_t	old = 0;

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
			if (old != regs.orig_rax) {
				printf("orig_rax : 0x%llx\t | ", regs.orig_rax);
				if (regs.rdi != 0x0) {
					printf("rdi : %llx\t |", regs.rdi);
				} else {
					printf("NULL |");
				}
				old = regs.orig_rax;
				puts("");
			}
			ptrace(PTRACE_SYSCALL, child, NULL, NULL);
			waitpid(child, &status, 0);
			if (WIFEXITED(status))
				break ;
		}
	}
	return (0);
}
