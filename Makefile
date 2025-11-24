CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

all: generate build

generate:
	go generate ./...

build:
	go build -o badfd .

clean:
	rm -f badfd
	rm -f bpf_bpf*.go bpf_bpf*.o
