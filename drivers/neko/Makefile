# Dual-mode kbuild file:
#  - in-tree  (Neko-Kernel/drivers/neko): obj-$(CONFIG_NEKO_DRV)
#  - out-of-tree (make -C <KDIR> M=$PWD modules): obj-m
ifdef KBUILD_EXTMOD
obj-m := neko_drv.o
else
obj-$(CONFIG_NEKO_DRV) += neko_drv.o
endif
