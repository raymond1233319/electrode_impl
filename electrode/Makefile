CC = gcc
CLANG = clang
LLC = llc

LINUX_PATH = ./linux
LINUX_TOOLS_PATH = $(LINUX_PATH)/tools
LINUX_LIB_PATH = $(LINUX_TOOLS_PATH)/lib
LINUX_INCLUDE_PATH = $(LINUX_PATH)/include
LIBBPF_PATH = $(LINUX_LIB_PATH)/bpf
LIBBPF = $(LIBBPF_PATH)/libbpf.a
LINUX_INCLUDES := -I. -I$(LINUX_LIB_PATH) -I$(LINUX_TOOLS_PATH)/include/uapi

CFLAGS := -g -O3 -Wall -DKBUILD_MODNAME="\"electrode\"" $(LINUX_INCLUDES)
EXTRA_CFLAGS += -Werror
LDFLAGS := -L$(LIBBPF_PATH) -l:libbpf.a -lelf $(USER_LIBS) -lz
NOSTDINC_FLAGS := -nostdinc -isystem $(shell $(CC) -print-file-name=include)
ARCH := $(shell uname -m | sed -E 's/x86_64|i[3-6]86/x86/')

LINUX_INCLUDES := -I$(LINUX_PATH)/arch/$(ARCH)/include
LINUX_INCLUDES += -I$(LINUX_PATH)/arch/$(ARCH)/include/uapi
LINUX_INCLUDES += -I$(LINUX_PATH)/arch/$(ARCH)/include/generated
LINUX_INCLUDES += -I$(LINUX_PATH)/arch/$(ARCH)/include/generated/uapi
LINUX_INCLUDES += -I$(LINUX_INCLUDE_PATH)
LINUX_INCLUDES += -I$(LINUX_INCLUDE_PATH)/uapi
LINUX_INCLUDES += -include $(LINUX_INCLUDE_PATH)/linux/kconfig.h

TARGETS += electrode
KERN_OBJECTS = ${TARGETS}.bpf.o
USER_OBJECTS = ${TARGETS}.o

.PHONY: all clean

all: $(TARGETS) $(KERN_OBJECTS)

clean:
	@find . -type f \
	    \( -name '*~' -o -name '*.ll' -o -name '*.bc' -o -name 'core' \) \
	    -exec rm -vf '{}' \;
	rm -f $(TARGETS) $(KERN_OBJECTS)

$(KERN_OBJECTS): %.o: %.c
	$(CLANG) -S $(NOSTDINC_FLAGS) $(LINUX_INCLUDES) $(EXTRA_CFLAGS) \
	    -D__KERNEL__ -D__ASM_SYSREG_H -D__BPF_TRACING__ -DKBUILD_MODNAME="\"electrode\"" \
	    -D__TARGET_ARCH_$(ARCH) \
	    -O3 -g -emit-llvm -c $< -o ${@:.o=.ll}
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

$(TARGETS): %: %.c $(OBJECTS) $(LIBBPF)
	$(CC) $(CFLAGS) $(OBJECTS) -o $@ $< $(LIBBPF) $(LDFLAGS)
