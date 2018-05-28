#include <unistd.h>
#include <fcntl.h>

int	main()
{
	write(1, "Hello", 5);
	open("./ressources/IamcurrentlydevelopingatoolinwhichIhavetotraceaprogramtoknow", O_RDONLY);
	return 256;
}
