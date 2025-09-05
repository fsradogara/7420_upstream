# SPDX-License-Identifier: GPL-2.0
#
# S/390 crypto devices
#

ifdef CONFIG_ZCRYPT_MONOLITHIC

z90crypt-objs := zcrypt_mono.o ap_bus.o zcrypt_api.o \
		zcrypt_pcica.o zcrypt_pcicc.o zcrypt_pcixcc.o zcrypt_cex2a.o
obj-$(CONFIG_ZCRYPT) += z90crypt.o

else

ap-objs := ap_bus.o
obj-$(CONFIG_ZCRYPT) += ap.o zcrypt_api.o zcrypt_pcicc.o zcrypt_pcixcc.o
obj-$(CONFIG_ZCRYPT) += zcrypt_pcica.o zcrypt_cex2a.o

endif
ap-objs := ap_bus.o
# zcrypt_api depends on ap
obj-$(CONFIG_ZCRYPT) += ap.o zcrypt_api.o
# msgtype* depend on zcrypt_api
obj-$(CONFIG_ZCRYPT) += zcrypt_msgtype6.o zcrypt_msgtype50.o
# adapter drivers depend on ap, zcrypt_api and msgtype*
ap-objs := ap_bus.o ap_card.o ap_queue.o
obj-$(subst m,y,$(CONFIG_ZCRYPT)) += ap.o
# zcrypt_api.o and zcrypt_msgtype*.o depend on ap.o
zcrypt-objs := zcrypt_api.o zcrypt_card.o zcrypt_queue.o
zcrypt-objs += zcrypt_msgtype6.o zcrypt_msgtype50.o
obj-$(CONFIG_ZCRYPT) += zcrypt.o
# adapter drivers depend on ap.o and zcrypt.o
obj-$(CONFIG_ZCRYPT) += zcrypt_pcixcc.o zcrypt_cex2a.o zcrypt_cex4.o

# pkey kernel module
pkey-objs := pkey_api.o
obj-$(CONFIG_PKEY) += pkey.o
