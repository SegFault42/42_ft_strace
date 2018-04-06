#include <unistd.h>
#include <sys/syscall.h>

int	main()
{
	write(1, "Hello", 5);
	return 256;
}
