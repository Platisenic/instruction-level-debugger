#pragma once

#include <sys/types.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#include <string>
#include <map>

bool getReg(pid_t pid, std::string regName, unsigned long &regVal);
bool setReg(pid_t pid, std::string regName, unsigned long regVal);
bool patch_setBreakpoint(pid_t pid, unsigned long addressVal, unsigned long *oriByte);
bool patch_clearBreakpoint(pid_t pid, unsigned long addressVal, unsigned long oriByte);
