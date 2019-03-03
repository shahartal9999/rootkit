# Bla-Rootkit
The Bla-rootkit is an a advance malware wrotten in c that supposed to be installed on a server and hide himself via one of the 
normal protocol of the server.


![alt text](https://i.imgur.com/KOdSjwL.jpg)

<br><br><br><br><br>
<br><br><br><br><br>

## Modules
Our malware have 3 parts.

### 1. The launcher
The usermode elf that run the malware

### 2. Kernel-mode client 
Hold the main functionality and recv the commands from the c&c by Man-in-the-middle technique between the main servcie of the server and the c&c.

### 3. Command and Control Server (Python)
Send commands for the rootkit client 

## Version 0.1 Features
//with high ability of network communication & host hidding.
//The rootkit tested only on **Ubuntu 18.04.1 LTS - amd64** for now.

# Rootkit launcher
Hold the binary data of the lkm client as a buffer and use init_module syscall for loading the ko to the kernel. 
After the kernel module is got loaded is job is to delete himself.

# Rootkit client
LKM rootkit with high ability of network communication & host hidding.
The rootkit tested only on **Ubuntu 18.04.1 LTS - amd64** for now.

## Current Features
- Keylogger
- Run usermode command


## Evidence we left

**HD DATA**: In the normal mode (without persistence) <br>
**Logs**: 
1. via the dmesg we can see that the sign verification leave a mark
2. 4Shure their more logs, but we need to check if out
**Files**: In the current version we left 2 files: output file (result of usermode command) and the keylogger file.
**History**: hide the usermode command from history.

## Future Features
- Persistence mode (without deleting the runner for start)
- Find another way to send a big reault (can be done by split the data to few parts and let the server know to expect more data).
- Use vulnerabilities for getting from a simple user to the kernel or to a root Permissions.  
- Self kill
- Make the communaction module more flexable.

# Buildchain

## Future Features
- Auto stripper in the Makefile.


