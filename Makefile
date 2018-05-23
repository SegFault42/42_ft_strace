##################################_COMPILATION_#################################
NAME	= ft_strace
CC		= clang
FLAG	= -Weverything
SRCS	=	./source/main.c\
			./source/syscall_tbl.c\
			./source/print.c\
			./source/path_bin.c

OBJS	= $(SRCS:.c=.o)

INCLUDE	= -I ./include/ \

###########################_RELINK_MODIFY_.h####################################
RELINK = ./include/ft_strace.h
################################################################################

all: $(NAME)

$(NAME): $(OBJS)
	@$(CC) $(FLAG) -o $(NAME) $(OBJS) $(INCLUDE)
	@printf "✅  Compilation done. \n"

%.o : %.c $(RELINK) ./Makefile
	@printf " ✅                                                              \r"
	@printf "✅  $(notdir $<)\r"
	@$(CC) -c $(FLAG) $< -o $@ $(INCLUDE)

clean:
	@printf "                                                               \r"
	@printf "✅  clean done ! n"
	@rm -f $(OBJS)

fclean:
	@printf "                                                               \r"
	@printf "✅  fclean done ! n"
	@rm -f $(NAME) $(OBJS)

re: fclean all

