#include "../include/ft_strace.h"

char	*get_path_bin(char *str)
{
	char	*path = NULL;

	path = getenv("PATH");
	if (!path) {
		perror("getenv");
		exit(errno);
	}
	printf("%s\n", path);
	return (NULL);
}
