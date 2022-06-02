#include <string.h>
#include <capstone/capstone.h>

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

bool check_cc(pid_t pid, unsigned long addressVal) {
    unsigned long code = ptrace(PTRACE_PEEKTEXT, pid, addressVal, 0);
    return (code & 0xff) == 0xcc;
}

void printInstr(std::vector<Instruction> &instrs) {
    char bytes[128] = "";
    for (auto it=instrs.begin(); it!=instrs.end(); it++) {
        for(int i=0; i<it->size; i++) {
            snprintf(&bytes[i*3], 4, "%02x ", it->bytes[i]);
        }
        fprintf(stderr, "%12lx: %-32s\t%-10s%s\n", it->address, bytes, it->mnemonic.c_str(), it->op_str.c_str());
    }
}

void disAsmInstr(
        std::vector<Instruction> &instrs,
        std::vector<BPinfo> &breakpoints,
        AddressRange &textsection,
        pid_t pid,
        unsigned long startAddr,
        int num) {
    char codes[256] = { 0 };
    unsigned long peek, offset;
    // peek
    for (int i=0; i<num*2; i++) {
        if (textsection.checkRange(startAddr+i*8)) {
            errno = 0;
            peek = ptrace(PTRACE_PEEKTEXT, pid, startAddr+i*8, NULL);
            if (errno != 0) { break; }
            memcpy(&codes[i*8], &peek, sizeof(peek));
            // clear brackpoints
            for (auto it = breakpoints.begin(); it != breakpoints.end(); it++) {
                if ((startAddr+i*8) <= it->address && it->address < (startAddr+i*8+8)) {
                    offset = it->address - (startAddr+i*8);
                    codes[i*8+offset] = it->oriByte;
                }
            }
        }
    }
    // disassembly
    csh handle;
    cs_insn *insn;
    size_t count;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) { return; }
    count = cs_disasm(handle, (uint8_t*)codes, sizeof(codes), startAddr, 0, &insn);
    if (count > 0) {
        for (size_t j=0; j<count && j<num; j++) {
            if (textsection.checkRange(insn[j].address)) {
                instrs.push_back(Instruction(
                    insn[j].address,
                    insn[j].bytes,
                    insn[j].size,
                    insn[j].mnemonic,
                    insn[j].op_str
                ));
            }
        }
        cs_free(insn, count);
    }
    cs_close(&handle);
}
char* getCmd(char *cmd, FILE *filein) {
    if (filein == stdin) {
        fprintf(stderr, "sdb> ");
    }
    return fgets(cmd, 512, filein);
}
