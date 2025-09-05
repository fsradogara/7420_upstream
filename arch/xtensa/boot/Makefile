#
# arch/xtensa/boot/Makefile
#
# This file is subject to the terms and conditions of the GNU General Public
# License.  See the file "COPYING" in the main directory of this archive
# for more details.
#
#


# KBUILD_CFLAGS used when building rest of boot (takes effect recursively)
KBUILD_CFLAGS	+= -fno-builtin -Iarch/$(ARCH)/boot/include
HOSTFLAGS	+= -Iarch/$(ARCH)/boot/include

BIG_ENDIAN	:= $(shell echo -e __XTENSA_EB__ | $(CC) -E - | grep -v "\#")

export EXTRA_CFLAGS
BIG_ENDIAN	:= $(shell echo __XTENSA_EB__ | $(CC) -E - | grep -v "\#")

export ccflags-y
export BIG_ENDIAN

subdir-y	:= lib

# Subdirs for the boot loader(s)

bootdir-$(CONFIG_XTENSA_PLATFORM_ISS)	 += boot-elf
bootdir-$(CONFIG_XTENSA_PLATFORM_XT2000) += boot-redboot boot-elf


zImage zImage.initrd Image Image.initrd: $(bootdir-y)
bootdir-$(CONFIG_XTENSA_PLATFORM_XT2000) += boot-redboot boot-elf boot-uboot
bootdir-$(CONFIG_XTENSA_PLATFORM_XTFPGA) += boot-redboot boot-elf boot-uboot
boot-$(CONFIG_XTENSA_PLATFORM_ISS)    += Image
boot-$(CONFIG_XTENSA_PLATFORM_XT2000) += Image zImage uImage
boot-$(CONFIG_XTENSA_PLATFORM_XTFPGA) += Image zImage uImage

all: $(boot-y)
Image: boot-elf
zImage: boot-redboot
uImage: $(obj)/uImage

boot-elf boot-redboot: $(addprefix $(obj)/,$(subdir-y))
	$(Q)$(MAKE) $(build)=$(obj)/$@ $(MAKECMDGOALS)

OBJCOPYFLAGS = --strip-all -R .comment -R .notes -O binary

vmlinux.bin: vmlinux FORCE
	$(call if_changed,objcopy)

vmlinux.bin.gz: vmlinux.bin FORCE
	$(call if_changed,gzip)

boot-elf: vmlinux.bin
boot-redboot: vmlinux.bin.gz

UIMAGE_LOADADDR = $(CONFIG_KERNEL_LOAD_ADDRESS)
UIMAGE_COMPRESSION = gzip

$(obj)/uImage: vmlinux.bin.gz FORCE
	$(call if_changed,uimage)
	$(Q)$(kecho) '  Kernel: $@ is ready'
