#pragma once

#include <sys/types.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#include <string>
#include <map>
#include <vector>

enum class State {
    NOT_LOADED,
    LOADED,
    RUNNING
};

class AddressRange {
public:
    unsigned long start;
    unsigned long end;
    AddressRange():
        start(0), end(0) {
    }
    AddressRange(unsigned long start, unsigned long end):
        start(start), end(end) {
    }
    bool checkRange(unsigned long address) {
        return (start <= address && address <= end);
    }
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

bool getReg(pid_t pid, std::string regName, unsigned long &regVal);
bool setReg(pid_t pid, std::string regName, unsigned long regVal);
bool patch_setBreakpoint(pid_t pid, unsigned long addressVal, unsigned long *oriByte);
bool patch_clearBreakpoint(pid_t pid, unsigned long addressVal, unsigned long oriByte);
void printInstr(std::vector<Instruction> &instrs);
void disAsmInstr(
        std::vector<Instruction> &instrs,
        std::vector<BPinfo> &breakpoints,
        AddressRange &textsection,
        pid_t pid,
        unsigned long startAddr,
        int num);
