##################################_COMPILATION_#################################
NAME	= ft_strace
CC		= clang
FLAG	= -Weverything
SRCS	=	./source/main.c\

OBJS	= $(SRCS:.c=.o)

INCLUDE	= -I ./include \
###########################_RELINK_MODIFY_.h####################################
RELINK = ./include/strace.h
################################################################################

all: $(NAME)

$(NAME): $(OBJS)
	@make -s -C ./libft/
	@$(CC) $(FLAG) -o $(NAME) $(OBJS) $(LFT)
	@printf "✅  Compilation done. \n"

%.o : %.c $(RELINK) ./Makefile
	@printf " ✅                                                              \r"
	@printf "✅  $(notdir $<)\r"
	@$(CC) -c $(FLAG) $< -o $@ $(INCLUDE)

clean:
	@printf "                                                               \r"
	@printf "✅  clean done ! n"
	@rm -f $(OBJS)
	@make -s clean -C ./libft/

fclean:
	@printf "                                                               \r"
	@printf "✅  fclean done ! n"
	@rm -f $(NAME) $(OBJS)
	@make -s fclean -C ./libft/

re: fclean all

