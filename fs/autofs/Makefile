#
# Makefile for the linux autofs-filesystem routines.
#

obj-$(CONFIG_AUTOFS_FS) += autofs.o

autofs-objs := dirhash.o init.o inode.o root.o symlink.o waitq.o
obj-$(CONFIG_AUTOFS_FS) += autofs4.o

autofs4-objs := init.o inode.o root.o symlink.o waitq.o expire.o
autofs4-objs := init.o inode.o root.o symlink.o waitq.o expire.o dev-ioctl.o
