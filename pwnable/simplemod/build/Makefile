TARGET := chall
SRCS   := main.c
OBJS   := $(SRCS:.c=.o)
SLIB   := libmod.so

CC     := gcc
CFLAGS := -Wall

.PHONY: all
all: $(TARGET)

$(TARGET): $(OBJS) $(SLIB)
	$(CC) $(OBJS) -L. -lmod -Wl,-z,lazy -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $<

%.so: %.c
	$(CC) $(CFLAGS) -masm=intel -shared -fPIC $< -o $@

.PHONY: clean
clean:
	$(RM) $(OBJS) $(SLIB) $(TARGET)

.PHONY: run
run: $(TARGET)
	LD_LIBRARY_PATH=. ./$(TARGET)

