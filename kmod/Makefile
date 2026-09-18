# Out-of-tree GKI-line module. Built against kernel/common for one Android
# GKI generation (android13-5.15, android14-6.1, ...), not an OEM tree.
# Same matching rule as clone/Re-Kernel/template/customize.sh: uname -r
# maps to androidN-X.Y, then finit_module of fluxrs-androidN-X.Y.ko.
#
# DDK sets KDIR inside the image:
#   ddk build --target android13-5.15
# Host (clang must match the kdir, android13-5.15: r450784e / 14.0.7):
#   PATH=/path/to/clang-r450784e/bin:$PATH make KDIR=/path/to/gki-kdir
#
# KDIR / KERNEL_SRC must be that generation's unpacked GKI common tree with
# Module.symvers from a GKI build. Do not point it at a vendor kernel.

ifneq ($(KERNELRELEASE),)
obj-m := fluxrs.o
fluxrs-y := fluxrs_main.o fluxrs_hook.o fluxrs_ctl.o fluxrs_sym.o
# 0=classify only. 2=STOLEN+kfree. 3=tproxy lookup+put.
# 4=scrub+assign+kfree. 5=deliver without dst (panicked, do not insmod).
# 6=attach loopback local dst, then deliver (product default).
# FLUXRS_NOCFI=1: __nocfi on __symbol_get nf_tproxy paths (required on CFI GKI).
FLUXRS_STAGE ?= 6
FLUXRS_NOCFI ?= 1
ccflags-y += -DFLUXRS_STAGE=$(FLUXRS_STAGE) -DFLUXRS_NOCFI=$(FLUXRS_NOCFI)
else
KERNEL_SRC ?= $(KDIR)
ifeq ($(KERNEL_SRC),)
$(warning KDIR/KERNEL_SRC is empty; set it to kernel/common or a DDK kdir for the GKI line)
endif

# GKI common is arm64 + LLVM. Forward so `make KDIR=...` does not pick
# the host gcc and the kdir's native (x86) compiler.
ARCH ?= arm64
LLVM ?= 1
LLVM_IAS ?= 1
CROSS_COMPILE ?= aarch64-linux-gnu-
FLUXRS_STAGE ?= 6
FLUXRS_NOCFI ?= 1

all:
	$(MAKE) -C $(KERNEL_SRC) M=$(CURDIR) ARCH=$(ARCH) LLVM=$(LLVM) LLVM_IAS=$(LLVM_IAS) CROSS_COMPILE=$(CROSS_COMPILE) FLUXRS_STAGE=$(FLUXRS_STAGE) FLUXRS_NOCFI=$(FLUXRS_NOCFI) modules

clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(CURDIR) ARCH=$(ARCH) LLVM=$(LLVM) LLVM_IAS=$(LLVM_IAS) CROSS_COMPILE=$(CROSS_COMPILE) FLUXRS_STAGE=$(FLUXRS_STAGE) FLUXRS_NOCFI=$(FLUXRS_NOCFI) clean
endif

.PHONY: all clean
