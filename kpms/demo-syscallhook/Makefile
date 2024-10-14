TARGET_COMPILE = $(shell uname -m)-$(shell uname -r)

KP_DIR = ../..

CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

# Add the KPM module source file
KPM_MODULE = kpm-hide-lineage.c

objs := $(KPM_MODULE:.c=.o)

all: $(KPM_MODULE).kpm

$(KPM_MODULE).kpm: ${objs}
	${CC} -r -o $@ $^

%.o: %.c
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -c -O2 -o $@ $<

.PHONY: clean
clean:
	rm -rf *.kpm
	find . -name "*.o" | xargs rm -f
