obj-m += vsi_rpmsg_driver.o
#vsi_rpmsg_driver-y += vsi_rpmsg_driver.o

all:
	make -C $(KERNEL_SRC) M=$(CURDIR)
modules_install:
	make -C $(KERNEL_SRC) M=$(CURDIR) modules_install
clean:
	make -C $(KERNEL_SRC) M=$(CURDIR) clean
