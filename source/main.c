#include "../include/ft_strace.h"

extern const t_syscall	g_syscall_table[330];

void	usage(int argc)
{
	if (argc == 1) {
		fprintf(stderr,
				"ft_strace: must have PROG [ARGS]\nTry 'strace -h' for more information.\n");
		exit (EXIT_FAILURE);
	}
}

int	main(int argc, char **argv, char **env)
{
	pid_t					child = 0;
	int						status = 0;
	int						loop = 0;
	char					*path = NULL;
	struct user_regs_struct	regs;

	usage(argc);

	// If we don't have absolute path, we need to search the binary path
	if (argv[1][0] != '/' && argv[1][0] != '.') {
		path = get_path_bin(argv[1]);
		if (!path) {
			dprintf(2, "ft_strace: Can't stat '%s': No such file or directory\n", argv[1]);
			return (EXIT_FAILURE);
		}
	}

	child = fork();
	if (child == -1) {
		perror("fork()");
	}
	else if (child == 0) {
		if (path == NULL) {
			if (execve(argv[1], &argv[1], env) == -1) {
				perror("execve");
				return (EXIT_FAILURE);
			} else {
				if (execve(path, &argv[1], env) == -1) {
					perror("execve");
					return (EXIT_FAILURE);
				}
			}
		}
	} else {
		kill(child, SIGSTOP);
		ptrace(PTRACE_SEIZE, child, NULL, NULL);
		waitpid(child, &status, 0);
		while (1) {
			ptrace(PTRACE_SYSCALL, child, NULL, NULL);
			waitpid(child, &status, 0);
			ptrace(PTRACE_GETREGS, child, NULL, &regs);

			print(&regs, loop, child);

			if (WIFEXITED(status))
				break ;
			++loop;
		}
	}
	/*printf("+++ exited with %d +++\n", (uint8_t)regs.rax);*/
	if (path)
		free(path);
	return (0);
}
