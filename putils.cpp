#include "putils.h"

struct user_regs_struct __regs;
std::map<std::string, long int> regoffsets {
    {"rax",   ((unsigned char *) &__regs.rax)    - ((unsigned char *) &__regs)},
    {"rbx",   ((unsigned char *) &__regs.rbx)    - ((unsigned char *) &__regs)},
    {"rcx",   ((unsigned char *) &__regs.rcx)    - ((unsigned char *) &__regs)},
    {"rdx",   ((unsigned char *) &__regs.rdx)    - ((unsigned char *) &__regs)},
    {"r8",    ((unsigned char *) &__regs.r8)     - ((unsigned char *) &__regs)},
    {"r9",    ((unsigned char *) &__regs.r9)     - ((unsigned char *) &__regs)},
    {"r10",   ((unsigned char *) &__regs.r10)    - ((unsigned char *) &__regs)},
    {"r11",   ((unsigned char *) &__regs.r11)    - ((unsigned char *) &__regs)},
    {"r12",   ((unsigned char *) &__regs.r12)    - ((unsigned char *) &__regs)},
    {"r13",   ((unsigned char *) &__regs.r13)    - ((unsigned char *) &__regs)},
    {"r14",   ((unsigned char *) &__regs.r14)    - ((unsigned char *) &__regs)},
    {"r15",   ((unsigned char *) &__regs.r15)    - ((unsigned char *) &__regs)},
    {"rdi",   ((unsigned char *) &__regs.rdi)    - ((unsigned char *) &__regs)},
    {"rsi",   ((unsigned char *) &__regs.rsi)    - ((unsigned char *) &__regs)},
    {"rbp",   ((unsigned char *) &__regs.rbp)    - ((unsigned char *) &__regs)},
    {"rsp",   ((unsigned char *) &__regs.rsp)    - ((unsigned char *) &__regs)},
    {"rip",   ((unsigned char *) &__regs.rip)    - ((unsigned char *) &__regs)},
    {"flags", ((unsigned char *) &__regs.eflags) - ((unsigned char *) &__regs)},
};

bool getReg(pid_t pid, std::string regName, unsigned long &regVal) {
    auto iter = regoffsets.find(regName);
    if (iter == regoffsets.end()) { return false; }
    regVal = ptrace(PTRACE_PEEKUSER, pid, iter->second, 0);
    return true;
}

bool setReg(pid_t pid, std::string regName, unsigned long regVal) {
    auto iter = regoffsets.find(regName);
    if (iter == regoffsets.end()) { return false; }
    if (ptrace(PTRACE_POKEUSER, pid, iter->second, regVal) < 0) {
        perror("** pokeuser");
        return true;
    }
    return true;
}

bool patch_setBreakpoint(pid_t pid, unsigned long addressVal, unsigned long *oriByte) {
    unsigned long code = ptrace(PTRACE_PEEKTEXT, pid, addressVal, 0);
    if (oriByte != NULL) {
        *oriByte = code & 0xff;
    }
    if (ptrace(PTRACE_POKETEXT, pid, addressVal, (code & 0xffffffffffffff00) | 0xcc) != 0) {
        perror("** poketest");
        return false;
    }
    return true;
}

bool patch_clearBreakpoint(pid_t pid, unsigned long addressVal, unsigned long oriByte) {
    unsigned long code = ptrace(PTRACE_PEEKTEXT, pid, addressVal, 0);
    if (ptrace(PTRACE_POKETEXT, pid, addressVal, (code & 0xffffffffffffff00) | oriByte) != 0) {
        perror("** poketest");
        return false;
    }
    return true;
}