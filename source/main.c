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
	struct user_regs_struct	regs;
	int						loop = 0;
	char					*path = NULL;

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
		if (path == NULL)
			execve(argv[1], &argv[1], env);
		else
			execve(path, &argv[1], env);
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
	if (path)
		free(path);
	return (0);
}
