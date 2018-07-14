SGFS_VERSION="0.1"

EXTRA_CFLAGS += -DSGFS_VERSION=\"$(SGFS_VERSION)\"

obj-$(CONFIG_SG_FS) += sgfs.o

sgfs-y := dentry.o file.o inode.o main.o super.o lookup.o mmap.o
