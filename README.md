# Bla-Rootkit
The Bla-rootkit is an a advance malware written in c that supposed to be installed on a server and hide himself via one of the 
normal protocol of the server.


![alt text](https://i.imgur.com/hhFu38m.jpg)

<br><br>

### Modules
Our malware have 3 parts.<br>

1. The launcher
The usermode elf that run the malware<br>

2. Kernel-mode client 
Hold the main functionality and recv the commands from the c&c by Man-in-the-middle technique between the main servcie of the server and the c&c.<br>

3. Command and Control Server (Python)
Send commands for the rootkit client.<br><br> 

### Marks
The rootkit tested only on **Ubuntu 18.04.1 LTS - amd64** for now.<br><br>

## Rootkit launcher
Hold the binary data of the lkm client as a buffer and use init_module syscall for loading the ko to the kernel.<br>
After the kernel module is got loaded is job is to delete himself.

## Rootkit client
LKM rootkit with high ability of network communication & host hidding.<br>
The rootkit tested only on **Ubuntu 18.04.1 LTS - amd64** for now.<br><br>

### Current Features
- Keylogger.<br>
- Run usermode command.<br>
- Self hide via DKOM (Break the lkm list).<br>
- Communcation back and forword on top a web http regular communcation.<br><br> 

### Evidence we left

**HD DATA**: In the normal mode (without persistence) <br>
**Files**: In the current version we left 2 files: output file (result of usermode command) and the keylogger file.<br>
**History**: hide the usermode command from history.<br>
**Logs**: 
- via the dmesg we can see that the sign verification leave a mark
- For sure there more logs but we need to check it yet.<br><br>

### Future Features
- Persistence mode (without deleting the runner for start).<br>
- Find another way to send a big reault (can be done by split the data to few parts and let the server know to expect more data).<br>
- Use vulnerabilities for getting from a simple user to the kernel or to a root Permissions.<br>
- Self kill.<br>
- Make the communaction module more flexable.<br><br>

## C&C 
The command and control server is written in python and can communicate with several victims simultaneously.
For now we only support http mode.

## Buildchain

### Future Features
- Auto stripper in the Makefile.<br><br>
