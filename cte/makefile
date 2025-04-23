CC = gcc

CFLAGS = -std=c99 -Wall -Wextra -pedantic

LDFLAGS =

SRCS = cte.c test.c

OBJS = $(SRCS:.c=.o)

EXEC = test

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $(EXEC)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

run: all
	./$(EXEC)

clean:
	@echo "Cleaning up..."
	rm -f $(OBJS) $(EXEC)

.PHONY: all run clean
