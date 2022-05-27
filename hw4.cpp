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

#include <map>
#include <string>

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

void exitProcess() {
    exit(0);
}

pid_t startTracee(char *progName, State &state) {
    if (state != State::LOADED) {
        printf("** state must be LOADED\n");
        return -1;
    }
    char *argv[] = {progName, NULL};
    pid_t child;
    int wait_State;
    if ((child = fork()) < 0) {
        perror("** fork");
        return -1;
    }
    if (child == 0) {
		if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
            perror("** ptrace@child");
            exit(1);
        }
		execv(argv[0], argv);
        perror("** execv");
		exit(1);
	} else {
        if(waitpid(child, &wait_State, 0) < 0) {
            perror("** waitpid");
            return -1;
        }
		ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
        printf("** pid %d\n", child);
        state = State::RUNNING;
    }
    return child;
}

bool contTracee(pid_t child, State &state) {
    if (state != State::RUNNING) {
        printf("** state must be RUNNING\n");
        return false;
    }
    int wait_status;
    if(ptrace(PTRACE_CONT, child, 0, 0) < 0) {
        perror("** cont");
        return false;
    }
    waitpid(child, &wait_status, 0);
    if (WIFEXITED(wait_status)) {
        printf("** child process %d terminiated normally (code %d)\n",
            child, WEXITSTATUS(wait_status));
        state = State::LOADED;
    } else if (WIFSTOPPED(wait_status)) {
        // do something
    }
    return true;
}

bool runTracee(char *progName, pid_t child, State &state) {
    if (state == State::NOT_LOADED) {
        printf("** state must be LOADED or RUNNING\n");
        return false;
    }
    if (state == State::LOADED) {
        child = startTracee(progName, state);
    }
    if (state == State::RUNNING) {
        contTracee(child, state);
    }
    return true;
}

bool stepTracee(pid_t child, State &state) {
    if (state != State::RUNNING) {
        printf("** state must be RUNNING\n");
        return false;
    }
    int wait_status;
    if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0) {
        perror("** singlestep");
        return false;
    }
    waitpid(child, &wait_status, 0);
    if (WIFEXITED(wait_status)) {
        printf("** child process %d terminiated normally (code %d)\n",
            child, WEXITSTATUS(wait_status));
        state = State::LOADED;
    } else if (WIFSTOPPED(wait_status)) {
        // do something
    }
    return true;
}

bool loadProgram(int nargs, char **args, State &state, char *progName) {
    if (nargs < 2) {
        printf("** no program path is given\n");
        return false;
    }
    if (state != State::NOT_LOADED) {
        printf("** state must be NOT LOADED\n");
        return false;
    }
    Elf64_Ehdr header;
    FILE *file = fopen(args[1], "rb");
    if (file == NULL) {
        printf("** '%s' no such file or directory\n", args[1]);
        return false;
    }
    fread(&header, sizeof(header), 1, file);
    if (memcmp(header.e_ident, ELFMAG, SELFMAG) != 0) {
        printf("** program '%s' is not ELF file\n", args[1]);
        fclose(file);
        return false;
    }
    printf("** program '%s' loaded. entry point 0x%lx\n", args[1], header.e_entry);
    strncpy(progName, args[1], 256);
    state = State::LOADED;
    fclose(file);
    return true;
}

bool getRegs(pid_t child, State &state) {
    if (state != State::RUNNING) {
        printf("** state must be RUNNING\n");
        return false;
    }
    struct user_regs_struct regs;
    if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) {
        return false;
    }
    printf("RAX %-16llx RBX %-16llx  RCX %-16llx RDX %-16llx\n"
           "R8  %-16llx R9  %-16llx  R10 %-16llx R11 %-16llx\n"
           "R12 %-16llx R13 %-16llx  R14 %-16llx R15 %-16llx\n"
           "RDI %-16llx RSI %-16llx  RBP %-16llx RSP %-16llx\n"
           "RIP %-16llx FLAGS %016llx\n",
            regs.rax, regs.rbx, regs.rcx, regs.rdx,
            regs.r8, regs.r9, regs.r10, regs.r11,
            regs.r12, regs.r13, regs.r14, regs.r15,
            regs.rdi, regs.rsi, regs.rbp, regs.rsp,
            regs.rip, regs.eflags);

    return true;
}

bool getSingleReg(int nargs, pid_t child, State &state, char *regName) {
    if (nargs < 2) {
        printf("** no register is given\n");
        return false;
    }
    if (state != State::RUNNING) {
        printf("** state must be RUNNING\n");
        return false;
    }
    std::string regkey(regName);
    auto iter = regoffsets.find(regkey);
    if (iter == regoffsets.end()) {
        printf("** undefined register\n");
        return false;
    }
    unsigned long long regVal;
    regVal = ptrace(PTRACE_PEEKUSER, child, iter->second, 0);
    printf("%s = %lld (0x%llx)\n", regName, regVal, regVal);
    return true;
}

bool setSingleTreg(int nargs, pid_t child, State &state, char *regName, char *regValptr) {
    if (nargs < 3) {
        printf("** Not enough input arguments\n");
        return false;
    }
    if (state != State::RUNNING) {
        printf("** state must be RUNNING\n");
        return false;
    }
    std::string regkey(regName);
    auto iter = regoffsets.find(regkey);
    if (iter == regoffsets.end()) {
        printf("** undefined register\n");
        return false;
    }
    unsigned long long regVal = strtoull(regValptr, NULL, 16);
    if (ptrace(PTRACE_POKEUSER, child, iter->second, regVal) < 0) {
        perror("** pokeuser");
        return false;
    }
    return true;
}

bool dumpMemory(int nargs, pid_t child, State &state, char *address) {
    if (nargs < 2) {
        printf("** no addr is given\n");
        return false;
    }
    if (state != State::RUNNING) {
        printf("** state must be RUNNING\n");
        return false;
    }
    unsigned long long addressVal = strtoull(address, NULL, 16);
    long ret;
    unsigned char *ptr = (unsigned char *) &ret;
    unsigned char strbuf[17];
    memset(strbuf, 0, 17);

    for (int i=0;i<10;i++) {
        if (i%2==0) { printf("      0x%llx:", addressVal + i*8); }
        ret = ptrace(PTRACE_PEEKTEXT, child, addressVal + i*8, 0);
        for (int j=0;j<8;j++) {
            printf(" %2.2x", ptr[j]);
            strbuf[j + i%2*8] = (isprint(ptr[j]) == 0) ? '.' : ptr[j];
        }
        if (i%2==1) {
            printf(" |%s|\n", strbuf);
        }
    }
    return true;
}

char* getCmd(char *cmd) {
    printf("sdb> ");
    return fgets(cmd, 512, stdin);
}

void printHelpMsg() {
    printf(
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


int main() {
    State state = State::NOT_LOADED;
    char cmd[512];
    char progName[256];
    pid_t tracee = -1;
    
    while (getCmd(cmd)!= NULL) {
        int nargs = 0;
        char *token, *saveptr, *args[3], *ptr = cmd;
        while (nargs < 3 && (token = strtok_r(ptr, " \t\n", &saveptr)) != NULL) {
            args[nargs++] = token;
            ptr = NULL;
        }
        if (nargs == 0) {
            // skip
        } else if (strcmp("load", args[0]) == 0) {
            loadProgram(nargs, args, state, progName);
        } else if ((strcmp("exit", args[0]) == 0) || (strcmp("q", args[0]) == 0)) {
            exitProcess();
        } else if (strcmp("start", args[0]) == 0) {
            tracee = startTracee(progName, state);
        } else if ((strcmp("cont", args[0]) == 0) || (strcmp("c", args[0]) == 0)) {
            contTracee(tracee, state);
        } else if ((strcmp("run", args[0]) == 0) || (strcmp("r", args[0]) == 0)) {
            runTracee(progName, tracee , state);
        } else if (strcmp("si", args[0]) == 0) {
            stepTracee(tracee, state);
        } else if (strcmp("getregs", args[0]) == 0) {
            getRegs(tracee, state);
        } else if ((strcmp("get", args[0]) == 0) || (strcmp("g", args[0]) == 0)) {
            getSingleReg(nargs, tracee, state, args[1]);
        } else if ((strcmp("set", args[0]) == 0) || (strcmp("s", args[0]) == 0)) {
            setSingleTreg(nargs, tracee, state, args[1], args[2]);
        } else if ((strcmp("help", args[0]) == 0) || (strcmp("h", args[0]) == 0)) {
            printHelpMsg();
        } else if ((strcmp("dump", args[0]) == 0) || (strcmp("x", args[0]) == 0)) {
            dumpMemory(nargs, tracee, state, args[1]);
        } else {
            printf("** undefined command\n");
        }
    }

    return 0;
}
