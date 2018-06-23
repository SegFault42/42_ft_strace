#include <unistd.h>
#include <fcntl.h>

int	main()
{
	char buff[4096] = {0};

	write(1, "Hello", 5);
	int fd = open("./ressources/IamcurrentlydevelopingatoolinwhichIhavetotraceaprogramtoknow", O_RDONLY);
	read(fd, &buff, 4096);
	return -2;
}
