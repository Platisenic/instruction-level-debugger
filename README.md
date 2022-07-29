# instruction-level-debugger
## Prerequisite
- Install [Capstone](https://www.capstone-engine.org/)
```bash
sudo apt-get install libcapstone-dev
```
## How to use
1. Build the source code
```bash
cd instruction-level-debugger
make
```
2. Start an interactive shell for debugging
```bash
./hw4
```
3. `h` for help
```
sdb> h
- break {instruction-address}: add a break point
- cont: continue execution
- delete {break-point-id}: remove a break point
- disasm addr: disassemble instructions in a file or a memory region
- dump addr: dump memory content
- exit: terminate the debugger
- get reg: get a single value from a register
- getregs: show registers
- help: show this message
- list: list break points
- load {path/to/a/program}: load a program
- run: run the program
- vmmap: show memory layout
- set reg val: get a single value to a register
- si: step into instruction
- start: start the program and stop at the first instruction
```
## Implementation detail
### A. Flow chart
In a debugging process, you have to load a program first, configure the debugger, and start debugging by running the program.  
- A debugger command may be only used in certain "states." 
  - any: a command can be used at any time.
  - not loaded: a command can only be used when a program is not loaded.
  - loaded: a command can only be used when a program is loaded.
  - running: a command can only be used when the program is running.
- The following is the state flow chart.  
![image](https://user-images.githubusercontent.com/69299037/181805844-3b222eb8-0393-4c04-8c31-549247916d18.png)
### B. Commands
The details of each command are explained below. We use brackets right after a command to enclose the list of the state(s) that the command should support.  
- break or b [running]: Setup a break point. If a program is loaded but is not running, you can simply display an error message. When a break point is hit, you have to output a message and indicate the corresponding address and instruction. The address of the break point should be within the range specified by the text segment in the ELF file and will not be the same as the entry point.
- cont or c [running]: continue the execution when a running program is stopped (suspended).
- delete [running]: remove a break point. Please remember to handle illegal situations, like deleting non-existing break points.
- disasm or d [running]: Disassemble instructions in a file or a memory region. The address of each instruction should be within the range specified by the text segment in the ELF file. You only have to dump 10 instructions for each command. If disasm command is executed without an address, you can simply output ** no addr is given. Please note that the output should not have the machine code cc. See the demonstration section for the sample output format.
- dump or x [running]: Dump memory content. You only have to dump 80 bytes from a given address. The output contains the addresses, the hex values, and printable ASCII characters. If dump command is executed without an address, you can simply output `** no addr is given.`Please note that the output should include the machine code `cc` if there is a break point.
- exit or q [any]: Quit from the debugger. The program being debugged should be killed as well.
- get or g [running]: Get the value of a register. Register names are all in lowercase.
- getregs [running]: Get the value of all registers.
- help or h [any]: Show the help message.
- list or l [any]: List break points, which contains index numbers (for deletion) and addresses.
- load [not loaded]: Load a program into the debugger. When a program is loaded, you have to print out the address of entry point.
- run or r [loaded and running]: Run the program. If the program is already running, show a warning message and continue the execution. If the program is loaded, start the program and continue the execution.
- vmmap or m [running]: Show memory layout for a running program. If a program is not running, you can simply display an error message.
- set or s [running]: Set the value of a register
- si [running]: Run a single instruction, and step into function calls.
- start [loaded]: Start the program and stop at the first instruction.
## Sample Usage
### 1. Load a program, show maps, and run the program (hello64)
```
$ ./hw4
sdb> load sample/hello64
** program 'sample/hello64' loaded. entry point 0x4000b0
sdb> start
** pid 121
sdb> vmmap
0000000000400000-0000000000401000 r-x 0        /home/docker/code/instruction-level-debugger/sample/hello64
0000000000600000-0000000000601000 rw- 0        /home/docker/code/instruction-level-debugger/sample/hello64
00007ffc27465000-00007ffc27486000 rw- 0        [stack]
00007ffc274eb000-00007ffc274ef000 r-- 0        [vvar]
00007ffc274ef000-00007ffc274f1000 r-x 0        [vdso]
ffffffffff600000-ffffffffff601000 --x 0        [vsyscall]
sdb> get rip
rip = 4194480 (0x4000b0)
sdb> run
** program sample/hello64 is already running
hello, world!
** child process 121 terminiated normally (code 0)
sdb>
```
### 2. Start a progrm, and show registers
```
$ ./hw4 sample/hello64
** program 'sample/hello64' loaded. entry point 0x4000b0
sdb> start
** pid 123
sdb> getregs
RAX 0                RBX 0                 RCX 0                RDX 0
R8  0                R9  0                 R10 0                R11 0
R12 0                R13 0                 R14 0                R15 0
RDI 0                RSI 0                 RBP 0                RSP 7ffc4e1686c0
RIP 4000b0           FLAGS 0000000000000200
sdb>
```
### 3. Start a program, set a break point, step into instruction, continue the execution, and run the program again without start (hello64)
```
$ ./hw4 sample/hello64
** program 'sample/hello64' loaded. entry point 0x4000b0
sdb> start
** pid 129
sdb> b 0x4000b5
sdb> b 0x4000ba
sdb> cont
** breakpoint @      4000b5: bb 01 00 00 00                     mov       ebx, 1
sdb> si
** breakpoint @      4000ba: b9 d4 00 60 00                     mov       ecx, 0x6000d4
sdb> cont
hello, world!
** child process 129 terminiated normally (code 0)
sdb> run
** pid 130
** breakpoint @      4000b5: bb 01 00 00 00                     mov       ebx, 1
sdb>
```
### 4. Start a program, set a break point, continue the execution, check assembly output, and dump memory (hello64)
```
$ ./hw4 sample/hello64
** program 'sample/hello64' loaded. entry point 0x4000b0
sdb> start
** pid 125
sdb> disasm
** no addr is given
sdb> disasm 0x4000b0
      4000b0: b8 04 00 00 00                    mov       eax, 4
      4000b5: bb 01 00 00 00                    mov       ebx, 1
      4000ba: b9 d4 00 60 00                    mov       ecx, 0x6000d4
      4000bf: ba 0e 00 00 00                    mov       edx, 0xe
      4000c4: cd 80                             int       0x80
      4000c6: b8 01 00 00 00                    mov       eax, 1
      4000cb: bb 00 00 00 00                    mov       ebx, 0
      4000d0: cd 80                             int       0x80
      4000d2: c3                                ret
** the address is out of the range of the text segment
sdb> b 0x4000c6
sdb> disasm 0x4000c6
      4000c6: b8 01 00 00 00                    mov       eax, 1
      4000cb: bb 00 00 00 00                    mov       ebx, 0
      4000d0: cd 80                             int       0x80
      4000d2: c3                                ret
** the address is out of the range of the text segment
sdb> cont
hello, world!
** breakpoint @      4000c6: b8 01 00 00 00                     mov       eax, 1
sdb> disasm 0x4000c6
      4000c6: b8 01 00 00 00                    mov       eax, 1
      4000cb: bb 00 00 00 00                    mov       ebx, 0
      4000d0: cd 80                             int       0x80
      4000d2: c3                                ret
** the address is out of the range of the text segment
sdb> dump 0x4000c6
      4000c6: cc 01 00 00 00 bb 00 00 00 00 cd 80 c3 00 68 65 |..............he|
      4000d6: 6c 6c 6f 2c 20 77 6f 72 6c 64 21 0a 00 00 00 00 |llo, world!.....|
      4000e6: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
      4000f6: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 03 00 |................|
      400106: 01 00 b0 00 40 00 00 00 00 00 00 00 00 00 00 00 |....@...........|
sdb>
```
### 5. Load a program, disassemble, set break points, run the program, and change the control flow (hello64)
```
$ ./hw4 sample/hello64
** program 'sample/hello64' loaded. entry point 0x4000b0
sdb> start
** pid 132
sdb> disasm 0x4000b0
      4000b0: b8 04 00 00 00                    mov       eax, 4
      4000b5: bb 01 00 00 00                    mov       ebx, 1
      4000ba: b9 d4 00 60 00                    mov       ecx, 0x6000d4
      4000bf: ba 0e 00 00 00                    mov       edx, 0xe
      4000c4: cd 80                             int       0x80
      4000c6: b8 01 00 00 00                    mov       eax, 1
      4000cb: bb 00 00 00 00                    mov       ebx, 0
      4000d0: cd 80                             int       0x80
      4000d2: c3                                ret
** the address is out of the range of the text segment
sdb> b 0x4000c6
sdb> l
  0:   4000c6
sdb> cont
hello, world!
** breakpoint @      4000c6: b8 01 00 00 00                     mov       eax, 1
sdb> set rip 0x4000b0
sdb> cont
hello, world!
** breakpoint @      4000c6: b8 01 00 00 00                     mov       eax, 1
sdb> delete 0
** breakpoint 0 deleted
sdb> set rip 0x4000b0
sdb> cont
hello, world!
** child process 132 terminiated normally (code 0)
sdb>
```
### 6. Load a program, set break points, run the program, and change the control flow (guess)
```
$ ./hw4 sample/guess.nopie
** program 'sample/guess.nopie' loaded. entry point 0x4006f0
sdb> start
** pid 134
sdb> b 0x400879
sdb> cont
Show me the key: get rax
** breakpoint @      400879: 48 39 d0                           cmp       rax, rdx
sdb> get rdx
rdx = 416178749 (0x18ce623d)
sdb> set rax 5678
sdb> set rdx 5678
sdb> cont
Bingo!
** child process 134 terminiated normally (code 0)
sdb>
```
