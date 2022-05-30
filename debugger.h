#pragma once

#include "putils.h"

#include <sys/wait.h>
#include <string.h>

#include <algorithm>

class Debugger {
public:
    Debugger():
        m_state(State::NOT_LOADED),
        m_lastBPAddress(0),
        m_tracee(-1) {
    }
    void CMD_startTracee(char *progName);
    void CMD_stepTracee();
    void CMD_contTracee();
    void CMD_runTracee(char *progName);
    void CMD_loadProgram(char *progName);
    void CMD_getRegs();
    void CMD_get(char *regName);
    void CMD_set(char *regName, char *regValptr);
    void CMD_dump(char *address);
    void CMD_vmmap();
    void CMD_createBreakPoint(char *address);
    void CMD_listBreakPoints();
    void CMD_deleteBreakPoint(char *bpID);
    void CMD_disAssembly(char *address);
    void CMD_printHelpMsg();

private:
    State m_state;
    AddressRange m_textsection;
    std::vector<BPinfo> m_breakpoints;
    unsigned long m_lastBPAddress;
    pid_t m_tracee;
};