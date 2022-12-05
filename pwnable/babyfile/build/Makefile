TARGET := chall
SRCS   := babyfile.c
OBJS   := $(SRCS:.c=.o)

CC     := gcc
CFLAGS := -Wall

.PHONY: all
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $<

.PHONY: clean
clean:
	$(RM) $(OBJS) $(TARGET)

.PHONY: run
run: $(TARGET)
	./$(TARGET)
