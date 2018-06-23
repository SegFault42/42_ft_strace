#include "../include/ft_strace.h"

static size_t	ft_strclen(char *str, char c)
{
	char	*ptr = str;

	while (*ptr != c && *ptr != 0)
		++ptr;
	return ((size_t)(ptr - str));
}

static char	**strsplit(char *str, char c)
{
	size_t	i = 0;
	size_t	len = 0;
	size_t	elem = 1; // If str != NULL we have at least one element
	char	**tab = NULL;

	if (!str)
		return NULL;

	// Count number of elem (string separate by c variable)
	while (str[i]) {
		if (str[i] == c)
			++elem;
		++i;
	}

	i ^= i;
	tab = (char **)calloc(sizeof(char *), elem + 1);

	// loop for alloc each string separate by c variable
	while (elem) {
		len = ft_strclen(str, ':');
		tab[i] = strndup(str, (len + 1));
		tab[i][len] = '/';
		str += len + 1;
		++i;
		--elem;
	}

	return (tab);
}

char	*get_path_bin(char *bin)
{
	char	*path = NULL;
	char	**tab = NULL;
	char	*concat = NULL;
	size_t	i = 0;
	int		fd = 0;

	path = getenv("PATH");

	if (!path) {
		perror("getenv");
		exit(errno);
	}

	tab = strsplit(path, ':');

	// chek if binary exist
	if (tab) {
		while (tab[i]) {
			concat = (char *)calloc(sizeof(char), (strlen(tab[i]) + strlen(bin) + 1));
			strcat(concat, tab[i]);
			strcat(concat, bin);

			fd = open(concat, O_RDONLY);
			close(fd);

			if (fd == -1) {
				free(concat);
				concat = NULL;
			}
			else
				break;
			++i;
		}
	}

	// free tab
	for (int inc = 0; tab[inc]; inc++) {
		free(tab[inc]);
		tab[inc] = NULL;
	}
	free(tab);

	return (concat);
}
