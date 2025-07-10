BPF_SRCS = xdp_main.c xdp_devmap.c
BPF_OBJS = $(BPF_SRCS:.c=.o)
INCLUDES = -I/usr/include/bpf

all: $(BPF_OBJS) xdp_loader

$(BPF_OBJS): %.o: %.c
	clang -O2 -g -Wall -target bpf $(INCLUDES) -c $< -o $@

xdp_loader: xdp_loader.c
	gcc xdp_loader.c $(INCLUDES) -o xdp_loader -lbpf

.PHONY: clean load unload
clean:
	rm -f *.o xdp_loader
