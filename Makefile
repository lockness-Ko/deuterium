all: deuterium

bpf:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/vmlinux.h
	clang -g -O3 -target bpf -c src/deuterium.bpf.c -o build/deuterium.bpf.o
	bpftool gen skeleton build/deuterium.bpf.o name deuterium > src/deuterium.skel.h

deuterium: bpf
	clang src/deuterium.c -lbpf -lelf -o build/deuterium

run: deuterium
	sudo build/deuterium

clean:
	rm -rvf build/* src/vmlinux.h src/deuterium.skel.h
