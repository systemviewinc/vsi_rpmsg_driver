obj-m += vsi_rpmsg_proxy.o
vsi_rpmsg_proxy-y += rpmsg_user_dev_driver.o
#KDIR := ../../linux-xlnx/
#KDIR := ~/Desktop/repos/linux-xlnx-debug/
#KDIR := ~/Desktop/repos/linux-xlnx/
#KDIR := ~/DF_vivado/zynq_linux/linux-xlnx
KDIR := ~/petalinux/MPSoc_Boot/build/linux/kernel/xlnx-4.0
PWD := $(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean

