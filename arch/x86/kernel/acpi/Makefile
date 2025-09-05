subdir-				:= realmode

obj-$(CONFIG_ACPI)		+= boot.o
obj-$(CONFIG_ACPI_SLEEP)	+= sleep.o wakeup_rm.o wakeup_$(BITS).o

ifneq ($(CONFIG_ACPI_PROCESSOR),)
obj-y				+= cstate.o processor.o
endif

$(obj)/wakeup_rm.o:    $(obj)/realmode/wakeup.bin

$(obj)/realmode/wakeup.bin: FORCE
	$(Q)$(MAKE) $(build)=$(obj)/realmode
# SPDX-License-Identifier: GPL-2.0
OBJECT_FILES_NON_STANDARD_wakeup_$(BITS).o := y

obj-$(CONFIG_ACPI)		+= boot.o
obj-$(CONFIG_ACPI_SLEEP)	+= sleep.o wakeup_$(BITS).o
obj-$(CONFIG_ACPI_APEI)		+= apei.o
obj-$(CONFIG_ACPI_CPPC_LIB)	+= cppc_msr.o

ifneq ($(CONFIG_ACPI_PROCESSOR),)
obj-y				+= cstate.o
endif

