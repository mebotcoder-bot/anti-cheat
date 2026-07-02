# Build the acheat kernel module against the running kernel's headers.
#   make          - build acheat.ko
#   sudo insmod acheat.ko   /  sudo rmmod acheat
#   cat /proc/acheat/status
# Requires: linux-headers-$(uname -r) and build-essential.
obj-m += acheat.o

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
