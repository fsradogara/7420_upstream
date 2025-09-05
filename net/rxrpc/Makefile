# SPDX-License-Identifier: GPL-2.0
#
# Makefile for Linux kernel RxRPC
#

af-rxrpc-objs := \
af-rxrpc-y := \
obj-$(CONFIG_AF_RXRPC) += rxrpc.o

rxrpc-y := \
	af_rxrpc.o \
	call_accept.o \
	call_event.o \
	call_object.o \
	conn_client.o \
	conn_event.o \
	conn_object.o \
	conn_service.o \
	input.o \
	insecure.o \
	key.o \
	local_event.o \
	local_object.o \
	misc.o \
	net_ns.o \
	output.o \
	peer_event.o \
	peer_object.o \
	recvmsg.o \
	security.o \
	sendmsg.o \
	skbuff.o \
	utils.o

ifeq ($(CONFIG_PROC_FS),y)
af-rxrpc-objs += ar-proc.o
endif
af-rxrpc-$(CONFIG_PROC_FS) += ar-proc.o
af-rxrpc-$(CONFIG_SYSCTL) += sysctl.o

obj-$(CONFIG_AF_RXRPC) += af-rxrpc.o

obj-$(CONFIG_RXKAD) += rxkad.o
rxrpc-$(CONFIG_PROC_FS) += proc.o
rxrpc-$(CONFIG_RXKAD) += rxkad.o
rxrpc-$(CONFIG_SYSCTL) += sysctl.o
