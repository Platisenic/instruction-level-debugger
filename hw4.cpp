#include "putils.h"
#include "debugger.h"

int main(int argc, char *argv[]) {
    char cmd[512];
    char progName[256];
    char *progPath = NULL;
    FILE *filein = stdin;
    int opt;

    while ((opt = getopt(argc, argv, "s:")) != -1 ) {
        switch (opt) {
            case 's':
                filein = fopen(optarg, "r");
                break;
            default:
                fprintf(stderr, "usage: ./hw4 [-s script] [program]\n");
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

    Debugger dbg;

    if (progPath != NULL) {
        strncpy(progName, progPath, 256);
        dbg.CMD_loadProgram(progName);
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
            dbg.CMD_startTracee(progName);
        } else if ((strcmp("cont", args[0]) == 0) || (strcmp("c", args[0]) == 0)) {
            dbg.CMD_contTracee();
        } else if ((strcmp("run", args[0]) == 0) || (strcmp("r", args[0]) == 0)) {
            dbg.CMD_runTracee(progName);
        } else if (strcmp("si", args[0]) == 0) {
            dbg.CMD_stepTracee();
        } else if (strcmp("getregs", args[0]) == 0) {
            dbg.CMD_getRegs();
        } else if ((strcmp("help", args[0]) == 0) || (strcmp("h", args[0]) == 0)) {
            dbg.CMD_printHelpMsg();
        } else if ((strcmp("vmmap", args[0]) == 0) || (strcmp("m", args[0]) == 0)) {
            dbg.CMD_vmmap();
        } else if ((strcmp("list", args[0]) == 0) || (strcmp("l", args[0]) == 0)) {
            dbg.CMD_listBreakPoints();
        } else if (strcmp("load", args[0]) == 0) {
            if (nargs < 2) {
                fprintf(stderr, "** no program path is given\n");
            } else {
                strncpy(progName, args[1], 256);
                dbg.CMD_loadProgram(progName);
            }
        } else if ((strcmp("get", args[0]) == 0) || (strcmp("g", args[0]) == 0)) {
            if (nargs < 2) {
                fprintf(stderr, "** no register is given\n");
            } else {
                dbg.CMD_get(args[1]);
            }
        } else if ((strcmp("dump", args[0]) == 0) || (strcmp("x", args[0]) == 0)) {
            if (nargs < 2) {
                fprintf(stderr, "** no addr is given\n");
            } else {
                dbg.CMD_dump(args[1]);
            }
        } else if ((strcmp("break", args[0]) == 0) || (strcmp("b", args[0]) == 0)) {
            if (nargs < 2) {
                fprintf(stderr, "** no addr is given\n");
            } else {
                dbg.CMD_createBreakPoint(args[1]);
            }
        } else if (strcmp("delete", args[0]) == 0) {
            if (nargs < 2) {
                fprintf(stderr, "** no addr is given\n");
            } else {
                dbg.CMD_deleteBreakPoint(args[1]);
            }
        } else if ((strcmp("disasm", args[0]) == 0) || (strcmp("d", args[0]) == 0)) {
            if (nargs < 2) {
                fprintf(stderr, "** no addr is given\n");
            } else {
                dbg.CMD_disAssembly(args[1]);
            }
        } else if ((strcmp("set", args[0]) == 0) || (strcmp("s", args[0]) == 0)) {
            if (nargs < 3) {
                fprintf(stderr, "** Not enough input arguments\n");
            } else {
                dbg.CMD_set(args[1], args[2]);
            }
        } else {
            fprintf(stderr, "** undefined command\n");
        }
    }
    
    fclose(filein);
    return 0;
}
