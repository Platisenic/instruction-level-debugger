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

enum State {
    NOT_LOADED,
    LOADED,
    RUNNING
};

void errquit(const char *msg) {
	perror(msg);
	exit(-1);
}

pid_t startTracee(char *progName, State &state) {
    char *argv[] = {progName, NULL};
    pid_t child;
    int wait_State;
    if ((child = fork()) < 0) errquit("fork");
    if (child == 0) {
		if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("ptrace@child");
		execv(argv[0], argv);
		errquit("execv");
	} else {
        if(waitpid(child, &wait_State, 0) < 0) errquit("waitpid");
		ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
        printf("** pid %d\n", child);
        state = State::RUNNING;
    }
    return child;
}

bool loadProgram(int nargs, char **args, State &state, char *progName) {
    if (nargs < 2) {
        printf("** no program path is given\n");
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
    strncpy(progName, args[1], strlen(args[1]));
    state = State::LOADED;
    fclose(file);
    return true;
}

void exitProcess() {
    exit(0);
}


int main() {
    State state = State::NOT_LOADED;
    char cmd[512];
    char progName[256];
    pid_t tracee = -1;
    int wait_status;
    printf("sdb> ");
    while (fgets(cmd, sizeof(cmd), stdin) != NULL) {
        int nargs = 0;
        char *token, *saveptr, *args[3], *ptr = cmd;
        while (nargs < 3 && (token = strtok_r(ptr, " \t\n", &saveptr)) != NULL) {
            args[nargs++] = token;
            ptr = NULL;
        }

        if (nargs == 0) {
            // skip
        }else if (strcmp("load", args[0]) == 0) {
            loadProgram(nargs, args, state, progName);
        } else if (strcmp("exit", args[0]) == 0) {
            exitProcess();
        } else if (strcmp("start", args[0]) == 0) {
            tracee = startTracee(progName, state);
            printf("state: %d\n", state);
        } else if (strcmp("cont", args[0]) == 0) {
            ptrace(PTRACE_CONT, tracee, 0, 0);
            waitpid(tracee, &wait_status, 0);
        } else {
            printf("** Undefined command\n");
        }

        printf("sdb> ");
    }


    return 0;
}