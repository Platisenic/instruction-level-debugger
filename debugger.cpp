#include "debugger.h"
#include <elf.h>

void Debugger::CMD_startTracee(char *progName) {
    if (m_state != State::LOADED) {
        fprintf(stderr, "** state must be LOADED\n");
        return;
    }
    char *argv[] = {progName, NULL};
    pid_t child;
    int wait_status;
    unsigned long code;
    if ((child = fork()) < 0) {
        perror("** fork");
        return;
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
        if (waitpid(child, &wait_status, 0) < 0) {
            perror("** waitpid");
            return;
        }
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
        for (auto it = m_breakpoints.begin(); it != m_breakpoints.end(); it++) {
            patch_setBreakpoint(child, it->address, NULL);
        }
        m_state = State::RUNNING;
        fprintf(stderr, "** pid %d\n", child);
    }
    m_tracee = child;
}

void Debugger::Handle_breakpoints() {
    unsigned long rip;
    int wait_status;
    getReg(m_tracee, "rip", rip);
    auto it = std::find_if(m_breakpoints.begin(), m_breakpoints.end(), [rip](const BPinfo &b) {
        return b.address == rip;
    });
    if (it == m_breakpoints.end()) { return; }

    patch_clearBreakpoint(m_tracee, it->address, it->oriByte);
    

    if(ptrace(PTRACE_SINGLESTEP, m_tracee, 0, 0) < 0) {
        perror("** singlestep");
        return;
    }
    waitpid(m_tracee, &wait_status, 0);
    if (WIFEXITED(wait_status)) {
        fprintf(stderr, "** child process %d terminiated normally (code %d)\n",
            m_tracee, WEXITSTATUS(wait_status));
        m_state = State::LOADED;
    } else if (WIFSTOPPED(wait_status)) {
        patch_setBreakpoint(m_tracee, it->address, NULL);
    }
}

void Debugger::CMD_stepTracee() {
    if (m_state != State::RUNNING) {
        fprintf(stderr, "** state must be RUNNING\n");
        return;
    }
    Handle_breakpoints();
    if(ptrace(PTRACE_SINGLESTEP, m_tracee, 0, 0) < 0) {
        perror("** singlestep");
        return;
    }
    int wait_status;
    waitpid(m_tracee, &wait_status, 0);
    if (WIFEXITED(wait_status)) {
        fprintf(stderr, "** child process %d terminiated normally (code %d)\n",
            m_tracee, WEXITSTATUS(wait_status));
        m_state = State::LOADED;
    } else if (WIFSTOPPED(wait_status)) {
        unsigned long rip;
        getReg(m_tracee, "rip", rip);
        if (check_cc(m_tracee, rip - 1)) {
            setReg(m_tracee, "rip", rip - 1);
            std::vector<Instruction> instrs;
            disAsmInstr(instrs, m_breakpoints, m_textsection, m_tracee, rip-1, 1);
            fprintf(stderr, "** breakpoint @");
            printInstr(instrs);   
        }
    }
}

void Debugger::CMD_contTracee() {
    if (m_state != State::RUNNING) {
        fprintf(stderr, "** state must be RUNNING\n");
        return;
    }
    Handle_breakpoints();
    if(ptrace(PTRACE_CONT, m_tracee, 0, 0) < 0) {
        perror("** cont");
        return;
    }
    int wait_status;
    waitpid(m_tracee, &wait_status, 0);
    if (WIFEXITED(wait_status)) {
        fprintf(stderr, "** child process %d terminiated normally (code %d)\n",
            m_tracee, WEXITSTATUS(wait_status));
        m_state = State::LOADED;
    } else if (WIFSTOPPED(wait_status)) {
        unsigned long rip;
        getReg(m_tracee, "rip", rip);
        if (check_cc(m_tracee, rip - 1)) {
            setReg(m_tracee, "rip", rip - 1);
            std::vector<Instruction> instrs;
            disAsmInstr(instrs, m_breakpoints, m_textsection, m_tracee, rip - 1, 1);
            fprintf(stderr, "** breakpoint @");
            printInstr(instrs);   
        }

        
    }
}

void Debugger::CMD_runTracee(char *progName) {
    if (m_state == State::NOT_LOADED) {
        fprintf(stderr, "** state must be LOADED or RUNNING\n");
    } else if (m_state == State::LOADED) {
        CMD_startTracee(progName);
        CMD_contTracee();
    } else if (m_state == State::RUNNING) {
        fprintf(stderr, "** program %s is already running\n", progName);
        CMD_contTracee();
    }
}

void Debugger::CMD_loadProgram(char *progName) {
    if (m_state != State::NOT_LOADED) {
        fprintf(stderr, "** state must be NOT LOADED\n");
        return;
    }
    Elf64_Ehdr header;
    FILE *file = fopen(progName, "rb");
    if (file == NULL) {
        fprintf(stderr, "** '%s' no such file or directory\n", progName);
        exit(1);
    }
    fread(&header, sizeof(header), 1, file);
    if (memcmp(header.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "** program '%s' is not ELF file\n", progName);
        exit(1);
    }
    Elf64_Shdr *sectionHeaders = (Elf64_Shdr *)calloc(header.e_shnum, header.e_shentsize);
    if (sectionHeaders == NULL) { exit(1);}
    fseek(file, header.e_shoff, SEEK_SET);
    fread(sectionHeaders, header.e_shentsize, header.e_shnum, file);
    char sectionName[256];
    char c;
    int k;
    for(int i=0;i<header.e_shnum;i++) {
        fseek(file, sectionHeaders[header.e_shstrndx].sh_offset+sectionHeaders[i].sh_name, SEEK_SET);
        k = 0;
        while((c = fgetc(file)) != '\0') {
            sectionName[k++] = c;
        }
        sectionName[k] = '\0';
        // fprintf(stderr, "** name: %s adderss: %lx size: %lx\n", sectionName, sectionHeaders[i].sh_addr, sectionHeaders[i].sh_size);
        if (strcmp(sectionName, ".text") == 0) {
            m_textsection.start = sectionHeaders[i].sh_addr;
            m_textsection.end = sectionHeaders[i].sh_addr + sectionHeaders[i].sh_size - 1;
            break;
        }
    }
    free(sectionHeaders);
    fclose(file);
    if ((m_textsection.start == 0) && (m_textsection.end) == 0) { exit(1); }
    fprintf(stderr, "** program '%s' loaded. entry point 0x%lx\n", progName, m_textsection.start);
    m_state = State::LOADED;
}

void Debugger::CMD_getRegs() {
    if (m_state != State::RUNNING) {
        fprintf(stderr, "** state must be RUNNING\n");
        return;
    }
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, m_tracee, 0, &regs) != 0) {
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

void Debugger::CMD_get(char *regName) {
    if (m_state != State::RUNNING) {
        fprintf(stderr, "** state must be RUNNING\n");
        return;
    }
    unsigned long regVal;
    std::string regNamestr(regName);
    if (getReg(m_tracee, regNamestr, regVal)) {
        fprintf(stderr, "%s = %ld (0x%lx)\n", regName, regVal, regVal);
    } else {
        fprintf(stderr, "** undefined register\n");
    }
}

void Debugger::CMD_set(char *regName, char *regValptr) {
    if (m_state != State::RUNNING) {
        fprintf(stderr, "** state must be RUNNING\n");
        return;
    }
    unsigned long regVal = strtoul(regValptr, NULL, 16);
    std::string regNamestr(regName);
    if (!setReg(m_tracee, regNamestr, regVal)) {
        fprintf(stderr, "** undefined register\n");
    }
}

void Debugger::CMD_dump(char *address) {
    if (m_state != State::RUNNING) {
        fprintf(stderr, "** state must be RUNNING\n");
        return;
    }
    unsigned long addressVal = strtoul(address, NULL, 16);
    long ret;
    unsigned char *ptr = (unsigned char *) &ret;
    unsigned char strbuf[17];
    memset(strbuf, 0, 17);

    for (int i=0;i<10;i++) {
        if (i%2==0) { fprintf(stderr, "%12lx:", addressVal + i*8); }
        ret = ptrace(PTRACE_PEEKTEXT, m_tracee, addressVal + i*8, 0);
        for (int j=0;j<8;j++) {
            fprintf(stderr, " %2.2x", ptr[j]);
            strbuf[j + i%2*8] = (isprint(ptr[j]) == 0) ? '.' : ptr[j];
        }
        if (i%2==1) {
            fprintf(stderr, " |%s|\n", strbuf);
        }
    }
}

void Debugger::CMD_vmmap() {
    if (m_state != State::RUNNING) {
        fprintf(stderr, "** state must be RUNNING\n");
        return;
    }
    char buf[512];
    char mmap_path[128];
    FILE *fp;
    long vm_begin, vm_end, offset;

    snprintf(mmap_path, sizeof(mmap_path), "/proc/%u/maps", m_tracee);
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

void Debugger::CMD_createBreakPoint(char *address) {
    if (m_state != State::RUNNING) {
        fprintf(stderr, "** state must be RUNNING\n");
        return;
    }
    unsigned long addressVal = strtoul(address, NULL, 16);
    if (!m_textsection.checkRange(addressVal)) {
        fprintf(stderr, "** the address is out of the range of the text segment\n");
        return;
    }
    auto it = std::find_if(m_breakpoints.begin(), m_breakpoints.end(), [addressVal](const BPinfo &b) {
        return b.address == addressVal;
    });
    if (it != m_breakpoints.end()) {
        fprintf(stderr, "** the breakpoint is already exists. (breakpoint %ld)\n", std::distance(m_breakpoints.begin(), it));
        return;
    }
    unsigned long oriByte;
    if (patch_setBreakpoint(m_tracee, addressVal, &oriByte)) {
        m_breakpoints.push_back(BPinfo(addressVal, oriByte));
    }
}

void Debugger::CMD_listBreakPoints() {
    for (auto it = m_breakpoints.begin(); it != m_breakpoints.end(); it++) {
        fprintf(stderr, "%3ld: %8lx\n", std::distance(m_breakpoints.begin(), it), it->address);
    }
}

void Debugger::CMD_deleteBreakPoint(char *bpID) {
    if (m_state != State::RUNNING) {
        fprintf(stderr, "** state must be RUNNING\n");
        return;
    }
    unsigned long bpnum = strtoul(bpID, NULL, 10);
    if (bpnum >= m_breakpoints.size()) {
        fprintf(stderr, "** breakpoint %ld does not exist\n", bpnum);
        return;
    }
    auto it = m_breakpoints.begin();
    std::advance(it, bpnum);
    if (patch_clearBreakpoint(m_tracee, it->address, it->oriByte)) {
        m_breakpoints.erase(it);
        fprintf(stderr, "** breakpoint %ld deleted\n", bpnum);
    }
}

void Debugger::CMD_disAssembly(char *address) {
    if (m_state != State::RUNNING) {
        fprintf(stderr, "** state must be RUNNING\n");
        return;
    }
    unsigned long addressVal = strtoul(address, NULL, 16);
    std::vector<Instruction> instrs;
    disAsmInstr(instrs, m_breakpoints, m_textsection, m_tracee, addressVal, 10);
    printInstr(instrs);
    if (instrs.size() < 10) {
        fprintf(stderr, "** the address is out of the range of the text segment\n");
    }
}

void Debugger::CMD_printHelpMsg() {
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
