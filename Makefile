CFLAGS=-Wall -Wextra -Werror -ggdb

main: main.c
	gcc $(CFLAGS) -o main main.c && ./main
