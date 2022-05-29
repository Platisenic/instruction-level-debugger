#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <string.h>
#include <elf.h>
#include <ctype.h>
#include <capstone/capstone.h>

#include <map>
#include <string>
#include <vector>
#include <algorithm>

enum class State {
    NOT_LOADED,
    LOADED,
    RUNNING
};

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

class BPinfo {
public:
    unsigned long address;
    unsigned long oriByte;
    BPinfo():
        address(0), oriByte(0) {
    }
    BPinfo(unsigned long address, unsigned long oriByte):
        address(address), oriByte(oriByte) {
    }
};

class Instruction {
public:
    unsigned long address;
    unsigned char bytes[16];
    int size;
    std::string mnemonic;
    std::string op_str;
    Instruction(
        unsigned long address,
        unsigned char* bytesptr,
        int size,
        char *mnemonic,
        char *op_str
    ): address(address), size(size), mnemonic(mnemonic), op_str(op_str) {
        memcpy(bytes, bytesptr, size);
    }
};

std::vector<BPinfo> breakpoints;
unsigned long lastBpAddress = 0;

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

void printInstr(std::vector<Instruction> &instrs) {
    char bytes[128] = "";
    for (auto it=instrs.begin(); it!=instrs.end(); it++) {
        for(int i=0; i<it->size; i++) {
            snprintf(&bytes[i*3], 4, "%02x ", it->bytes[i]);
        }
        fprintf(stderr, "%12lx: %-32s\t%-10s%s\n", it->address, bytes, it->mnemonic.c_str(), it->op_str.c_str());
    }
}

void disAsmInstr(std::vector<Instruction> &instrs, pid_t pid, unsigned long startAddr, int num)  {
    char codes[256] = { 0 };
    unsigned long peek, offset;
    // peek
    for (int i=0; i<num*2; i++) {
        // todo check text ranges
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
    // disassembly
    csh handle;
    cs_insn *insn;
    size_t count;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) { return; }
    count = cs_disasm(handle, (uint8_t*)codes, sizeof(codes), startAddr, 0, &insn);
    if (count > 0) {
        for (size_t j=0; j<count && j<num; j++) {
            instrs.push_back(Instruction(
                insn[j].address,
                insn[j].bytes,
                insn[j].size,
                insn[j].mnemonic,
                insn[j].op_str
            ));
        }
        cs_free(insn, count);
    }
    cs_close(&handle);
}

pid_t CMD_startTracee(char *progName, State &state) {
    if (state != State::LOADED) {
        fprintf(stderr, "** state must be LOADED\n");
        return -1;
    }
    char *argv[] = {progName, NULL};
    pid_t child;
    int wait_State;
    unsigned long code;
    if ((child = fork()) < 0) {
        perror("** fork");
        return -1;
    }
    if (child == 0) {
		if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
            perror("** ptrace@child");
            exit(1);
        }
		execv(argv[0], argv);
        perror("** execv");
		exit(1);
	} else {
        if (waitpid(child, &wait_State, 0) < 0) {
            perror("** waitpid");
            return -1;
        }
		ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
        for (auto it = breakpoints.begin(); it != breakpoints.end(); it++) {
            patch_setBreakpoint(child, it->address, NULL);
        }
        state = State::RUNNING;
        fprintf(stderr, "** pid %d\n", child);
    }
    return child;
}

void CMD_stepTracee(pid_t pid, State &state) {
    if (state != State::RUNNING) {
        fprintf(stderr, "** state must be RUNNING\n");
        return;
    }
    int wait_status;
    if(ptrace(PTRACE_SINGLESTEP, pid, 0, 0) < 0) {
        perror("** singlestep");
        return;
    }
    waitpid(pid, &wait_status, 0);
    if (WIFEXITED(wait_status)) {
        fprintf(stderr, "** child process %d terminiated normally (code %d)\n",
            pid, WEXITSTATUS(wait_status));
        state = State::LOADED;
    } else if (WIFSTOPPED(wait_status)) {
        unsigned long address = lastBpAddress;
        auto it = std::find_if(breakpoints.begin(), breakpoints.end(), [address](const BPinfo &b) {
            return b.address == address;
        });
        if (it != breakpoints.end()) {
            patch_setBreakpoint(pid, it->address, NULL);
        }
        lastBpAddress = 0;
        unsigned long rip;
        getReg(pid, "rip", rip);
        it = std::find_if(breakpoints.begin(), breakpoints.end(), [rip](const BPinfo &b) {
            return b.address == (rip - 1);
        });
        if (it == breakpoints.end()) { return; }
        // hit breakpoint
        patch_clearBreakpoint(pid, it->address, it->oriByte);
        setReg(pid, "rip", rip-1);
        lastBpAddress = it->address;
        std::vector<Instruction> instrs;
        disAsmInstr(instrs, pid, it->address, 1);
        fprintf(stderr, "** breakpoint @");
        printInstr(instrs);
    }
}

void CMD_contTracee(pid_t pid, State &state) {
    if (state != State::RUNNING) {
        fprintf(stderr, "** state must be RUNNING\n");
        return;
    }
    if (lastBpAddress != 0) {
        CMD_stepTracee(pid ,state);
        if (lastBpAddress != 0) { // encounter breakpoints in stepTracee
            return;
        }
    }
    int wait_status;
    if(ptrace(PTRACE_CONT, pid, 0, 0) < 0) {
        perror("** cont");
        return;
    }
    waitpid(pid, &wait_status, 0);
    if (WIFEXITED(wait_status)) {
        fprintf(stderr, "** child process %d terminiated normally (code %d)\n",
            pid, WEXITSTATUS(wait_status));
        state = State::LOADED;
    } else if (WIFSTOPPED(wait_status)) {
        unsigned long rip;
        getReg(pid, "rip", rip);
        auto it = std::find_if(breakpoints.begin(), breakpoints.end(), [rip](const BPinfo &b) {
            return b.address == (rip - 1);
        });
        if (it == breakpoints.end()) { return; }
        // hit breakpoint
        patch_clearBreakpoint(pid, it->address, it->oriByte);
        setReg(pid, "rip", rip-1);
        lastBpAddress = it->address;
        std::vector<Instruction> instrs;
        disAsmInstr(instrs, pid, it->address, 1);
        fprintf(stderr, "** breakpoint @");
        printInstr(instrs);   
    }
}

void CMD_runTracee(char *progName, pid_t child, State &state) {
    if (state == State::NOT_LOADED) {
        fprintf(stderr, "** state must be LOADED or RUNNING\n");
    } else if (state == State::LOADED) {
        child = CMD_startTracee(progName, state);
        CMD_contTracee(child, state);
    } else if (state == State::RUNNING) {
        fprintf(stderr, "** program %s is already running\n", progName);
        CMD_contTracee(child, state);
    }
}

void CMD_loadProgram(State &state, char *progName) {
    if (state != State::NOT_LOADED) {
        fprintf(stderr, "** state must be NOT LOADED\n");
        return;
    }
    Elf64_Ehdr header;
    FILE *file = fopen(progName, "rb");
    if (file == NULL) {
        fprintf(stderr, "** '%s' no such file or directory\n", progName);
        return;
    }
    fread(&header, sizeof(header), 1, file);
    if (memcmp(header.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "** program '%s' is not ELF file\n", progName);
        fclose(file);
        return;
    }
    fprintf(stderr, "** program '%s' loaded. entry point 0x%lx\n", progName, header.e_entry);
    state = State::LOADED;
    fclose(file);
}

void CMD_getRegs(pid_t pid, State &state) {
    if (state != State::RUNNING) {
        fprintf(stderr, "** state must be RUNNING\n");
        return;
    }
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) != 0) {
        return;
    }
    fprintf(stderr, "RAX %-16llx RBX %-16llx  RCX %-16llx RDX %-16llx\n"
           "R8  %-16llx R9  %-16llx  R10 %-16llx R11 %-16llx\n"
           "R12 %-16llx R13 %-16llx  R14 %-16llx R15 %-16llx\n"
           "RDI %-16llx RSI %-16llx  RBP %-16llx RSP %-16llx\n"
           "RIP %-16llx FLAGS %016llx\n",
            regs.rax, regs.rbx, regs.rcx, regs.rdx,
            regs.r8, regs.r9, regs.r10, regs.r11,
            regs.r12, regs.r13, regs.r14, regs.r15,
            regs.rdi, regs.rsi, regs.rbp, regs.rsp,
            regs.rip, regs.eflags);
}

void CMD_get(pid_t pid, State &state, char *regName) {
    if (state != State::RUNNING) {
        fprintf(stderr, "** state must be RUNNING\n");
        return;
    }
    unsigned long regVal;
    std::string regNamestr(regName);
    if (getReg(pid, regNamestr, regVal)) {
        fprintf(stderr, "%s = %ld (0x%lx)\n", regName, regVal, regVal);
    } else {
        fprintf(stderr, "** undefined register\n");
    }
}

void CMD_set(pid_t pid, State &state, char *regName, char *regValptr) {
    if (state != State::RUNNING) {
        fprintf(stderr, "** state must be RUNNING\n");
        return;
    }
    unsigned long regVal = strtoul(regValptr, NULL, 16);
    std::string regNamestr(regName);
    if (!setReg(pid, regNamestr, regVal)) {
        fprintf(stderr, "** undefined register\n");
    }
}

void CMD_dump(pid_t child, State &state, char *address) {
    if (state != State::RUNNING) {
        fprintf(stderr, "** state must be RUNNING\n");
        return;
    }
    unsigned long addressVal = strtoul(address, NULL, 16);
    long ret;
    unsigned char *ptr = (unsigned char *) &ret;
    unsigned char strbuf[17];
    memset(strbuf, 0, 17);

    for (int i=0;i<10;i++) {
        if (i%2==0) { fprintf(stderr, "0x%12lx:", addressVal + i*8); }
        ret = ptrace(PTRACE_PEEKTEXT, child, addressVal + i*8, 0);
        for (int j=0;j<8;j++) {
            fprintf(stderr, " %2.2x", ptr[j]);
            strbuf[j + i%2*8] = (isprint(ptr[j]) == 0) ? '.' : ptr[j];
        }
        if (i%2==1) {
            fprintf(stderr, " |%s|\n", strbuf);
        }
    }
}

void CMD_vmmap(pid_t child, State &state) {
    if (state != State::RUNNING) {
        fprintf(stderr, "** state must be RUNNING\n");
        return;
    }
    char buf[512];
    char mmap_path[128];
    FILE *fp;
    long vm_begin, vm_end, offset;

    snprintf(mmap_path, sizeof(mmap_path), "/proc/%u/maps", child);
    if ((fp = fopen(mmap_path, "rt")) == NULL) { perror("** fopen"); return; }
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        int nargs = 0;
        char *token, *saveptr, *args[8], *ptr = buf;
        while (nargs < 8 && (token = strtok_r(ptr, " \t\n\r", &saveptr)) != NULL) {
			args[nargs++] = token;
			ptr = NULL;
		}
        if (nargs < 6) continue;
        if ((ptr = strchr(args[0], '-')) == NULL) { continue; }
        *ptr = '\0';
        vm_begin = strtol(args[0], NULL, 16);
        vm_end = strtol(ptr+1, NULL, 16);
    
        offset = strtol(args[2], NULL, 16);
        if (strlen(args[1]) < 4) { continue; }
        args[1][3] = '\0';
        fprintf(stderr, "%016lx-%016lx %s %-8lx %s\n", vm_begin, vm_end, args[1], offset, args[5]);
    }
}

void CMD_createBreakPoint(pid_t pid, State &state, char *address) {
    if (state != State::RUNNING) {
        fprintf(stderr, "** state must be RUNNING\n");
        return;
    }
    // check text range

    unsigned long addressVal = strtoul(address, NULL, 16);
    auto it = std::find_if(breakpoints.begin(), breakpoints.end(), [addressVal](const BPinfo &b) {
        return b.address == addressVal;
    });
    if (it != breakpoints.end()) {
        fprintf(stderr, "** the breakpoint is already exists. (breakpoint %ld)\n", std::distance(breakpoints.begin(), it));
        return;
    }
    unsigned long oriByte;
    if (patch_setBreakpoint(pid, addressVal, &oriByte)) {
        breakpoints.push_back(BPinfo(addressVal, oriByte));
    }
}

void CMD_listBreakPoints() {
    for (auto it = breakpoints.begin(); it != breakpoints.end(); it++) {
        fprintf(stderr, "%3ld: %8lx\n", std::distance(breakpoints.begin(), it), it->address);
    }
}

void CMD_deleteBreakPoint(pid_t pid, State &state, char *bpID) {
    if (state != State::RUNNING) {
        fprintf(stderr, "** state must be RUNNING\n");
        return;
    }
    unsigned long bpnum = strtoul(bpID, NULL, 10);
    if (bpnum >= breakpoints.size()) {
        fprintf(stderr, "** breakpoint %ld does not exist\n", bpnum);
        return;
    }
    auto it = breakpoints.begin();
    std::advance(it, bpnum);
    if (patch_clearBreakpoint(pid, it->address, it->oriByte)) {
        breakpoints.erase(it);
        fprintf(stderr, "** breakpoint %ld deleted\n", bpnum);
    }
}

void CMD_disAssembly(pid_t pid, State &state, char *address) {
    if (state != State::RUNNING) {
        fprintf(stderr, "** state must be RUNNING\n");
        return;
    }
    unsigned long addressVal = strtoul(address, NULL, 16);
    std::vector<Instruction> instrs;
    disAsmInstr(instrs, pid, addressVal, 10);
    printInstr(instrs);
}

char* getCmd(char *cmd, FILE *filein) {
    if (filein == stdin) {
        fprintf(stderr, "sdb> ");
    }
    return fgets(cmd, 512, filein);
}

void CMD_printHelpMsg() {
    fprintf(stderr, 
        "- break {instruction-address}: add a break point\n"
        "- cont: continue execution\n"
        "- delete {break-point-id}: remove a break point\n"
        "- disasm addr: disassemble instructions in a file or a memory region\n"
        "- dump addr: dump memory content\n"
        "- exit: terminate the debugger\n"
        "- get reg: get a single value from a register\n"
        "- getregs: show registers\n"
        "- help: show this message\n"
        "- list: list break points\n"
        "- load {path/to/a/program}: load a program\n"
        "- run: run the program\n"
        "- vmmap: show memory layout\n"
        "- set reg val: get a single value to a register\n"
        "- si: step into instruction\n"
        "- start: start the program and stop at the first instruction\n"
    );
}


int main(int argc, char *argv[]) {
    State state = State::NOT_LOADED;
    char cmd[512];
    char progName[256];
    char *scriptpath = NULL;
    char *progPath = NULL;
    pid_t tracee = -1;
    FILE *filein = stdin;

    int opt;
    opterr = 0;
    while ((opt = getopt(argc, argv, "s:")) != -1 ) {
        switch (opt) {
            case 's':
                scriptpath = optarg;
                break;
            default:
                exit(EXIT_FAILURE);
        }
    }

    if (argc > 1) {
        int progPos = 1;
        while (progPos < argc) {
            if (strcmp(argv[progPos], "-s") == 0) { progPos += 2; }
            else { break; }
        }
        progPath = argv[progPos];
    }

    if (progPath != NULL) {
        strncpy(progName, progPath, 256);
        CMD_loadProgram(state, progName);
    }

    if (scriptpath != NULL) {
        filein = fopen(scriptpath, "r");
    }
    
    while (getCmd(cmd, filein)!= NULL) {
        int nargs = 0;
        char *token, *saveptr, *args[3], *ptr = cmd;
        while (nargs < 3 && (token = strtok_r(ptr, " \t\n", &saveptr)) != NULL) {
            args[nargs++] = token;
            ptr = NULL;
        }
        if (nargs == 0) { continue; }

        if ((strcmp("exit", args[0]) == 0) || (strcmp("q", args[0]) == 0)) {
            exit(0);
        } else if (strcmp("start", args[0]) == 0) {
            tracee = CMD_startTracee(progName, state);
        } else if ((strcmp("cont", args[0]) == 0) || (strcmp("c", args[0]) == 0)) {
            CMD_contTracee(tracee, state);
        } else if ((strcmp("run", args[0]) == 0) || (strcmp("r", args[0]) == 0)) {
            CMD_runTracee(progName, tracee , state);
        } else if (strcmp("si", args[0]) == 0) {
            CMD_stepTracee(tracee, state);
        } else if (strcmp("getregs", args[0]) == 0) {
            CMD_getRegs(tracee, state);
        } else if ((strcmp("help", args[0]) == 0) || (strcmp("h", args[0]) == 0)) {
            CMD_printHelpMsg();
        } else if ((strcmp("vmmap", args[0]) == 0) || (strcmp("m", args[0]) == 0)) {
            CMD_vmmap(tracee, state);
        } else if ((strcmp("list", args[0]) == 0) || (strcmp("l", args[0]) == 0)) {
            CMD_listBreakPoints();
        } else if (strcmp("load", args[0]) == 0) {
            if (nargs < 2) {
                fprintf(stderr, "** no program path is given\n");
            } else {
                strncpy(progName, args[1], 256);
                CMD_loadProgram(state, progName);
            }
        } else if ((strcmp("get", args[0]) == 0) || (strcmp("g", args[0]) == 0)) {
            if (nargs < 2) {
                fprintf(stderr, "** no register is given\n");
            } else {
                CMD_get(tracee, state, args[1]);
            }
        } else if ((strcmp("dump", args[0]) == 0) || (strcmp("x", args[0]) == 0)) {
            if (nargs < 2) {
                fprintf(stderr, "** no addr is given\n");
            } else {
                CMD_dump(tracee, state, args[1]);
            }
        } else if ((strcmp("break", args[0]) == 0) || (strcmp("b", args[0]) == 0)) {
            if (nargs < 2) {
                fprintf(stderr, "** no addr is given\n");
            } else {
                CMD_createBreakPoint(tracee, state, args[1]);
            }
        } else if (strcmp("delete", args[0]) == 0) {
            if (nargs < 2) {
                fprintf(stderr, "** no addr is given\n");
            } else {
                CMD_deleteBreakPoint(tracee, state, args[1]);
            }
        } else if ((strcmp("disasm", args[0]) == 0) || (strcmp("d", args[0]) == 0)) {
            if (nargs < 2) {
                fprintf(stderr, "** no addr is given\n");
            } else {
                CMD_disAssembly(tracee, state, args[1]);
            }
        } else if ((strcmp("set", args[0]) == 0) || (strcmp("s", args[0]) == 0)) {
            if (nargs < 3) {
                fprintf(stderr, "** Not enough input arguments\n");
            } else {
                CMD_set(tracee, state, args[1], args[2]);
            }
        } else {
            fprintf(stderr, "** undefined command\n");
        }
    }
    if (scriptpath != NULL) {
        fclose(filein);
    }
    return 0;
}
