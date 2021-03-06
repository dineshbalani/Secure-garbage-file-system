# Secure-garbage-file-system
Developed a stackable file system to asynchronously delete and move the files to a trash bin. Files in trash bin folder are secured, compressed, encrypted and can be restored by user.

* PURPOSE:

To become familiar with the VFS layer of Linux, and especially with
extensible file systems APIs.  To build a useful file system using stacking
technologies.

* INTRODUCTION:

In a stackable file system, each VFS-based object at the stackable file
system (e.g., in Wrapfs) has a link to one other object on the lower file
system (sometimes called the "hidden" object).  We identify this
symbolically as X->X' where "X" is an object at the upper layer, and X' is
an object on the lower layer.  This form of stacking is a single-layer
linear stacking.

*IMPORTANT COMMANDS/THINGS TO NOTE:

-Please give permission to create .sg folder accessible to all other users this can be done by
-umask 0011 or 0000

-Run the Makefile in hw2 folder to create object file for sgctl.c

-Run the following command to make the fs/sgfs modules.
	make modules SUBDIRS=fs/sgfs/
	make modules_install SUBDIRS=fs/sgfs/

-Unmount anyother file system
	umount /mnt/sgfs

-Remove anyother sgfs mounted
	rmmod sgfs

-Install the new make of sgfs
	insmod ./fs/sgfs/sgfs.ko

-Mounting sgfs can be done as follows:

# mount -t sgfs /some/lower/path /mnt/sgfs

or

# mount -t sgfs -o key=MySecretPa55 /some/lower/path /mnt/sgfs

-To undelete a file give the following command
$ PATH_TOSGCTL/sgctl -u FILE

FILE: the file's name to undelete
-u: option to "undelete"

*LIST OF FILES ADDED:

/usr/src/hw2-user/fs/sgfs
	-dentry.c
	-file.c(modified)
	-inode.c(modified)
	-lookup.c
	-main.c(modified)
	-sgfs.h(modified)
	-mmap.c
	-sgfs.mod.c
	-super.c

/usr/src/hw2-user/hw2
	-README(modified)
	-sgctl.c
	-Makefile
	-kernel.config

/usr/src/hw2-user/
	-compile.sh

Other files modified

magic.h(modified)
fs/Kconfig(modified)
fs/Makefile(modfied)



* DETAILS(Algorithm)

I. During mount two functions were modified :-
sgfs_mount():-
- void *raw_data was parsed to get the key, and check if it is passed or not
sgfs_read_super():-
- To create .sg folder at mount path (obtained from variable dev_name)
- using SGFS_SB(sb) struct sgfs_sb_info was obtained.
- Information of key and mount path is stored in this struct sgfs_sb_info, 

II. To delete a file :- SGFS_UNLIK
-Get user id of current user
-Check if the file is .sg folder(using complete paths, mount path(obtained from Superblock private_info) and file path from d_path)
	- from the file name check if the file owner(first 4 bytes) is same as current user.
	- If it is same delete the file
	- Else return -EPERM error
-Check if the key was supplied during mount option(this information is stored in Superblock of fs)
-If No key was supplied 
	-Then rename the file to .sg folder
-Else
	- Encrypt the content of file and write to a new file in .sg folder
	- If the encryption of writing fails in between
		- Unlink the new file created and restore the dentry of the file which was supposed to be deleted using d_drop
	- Else
		-Unlink the old file
		-Sync the upper level obejcts with lower level objects.
-Free all the buffers

III. To undelete a file :-
- A user program  .sgctl was created that will call sgfs_unlock_ioctl() function
- User program passed a file descriptor to kernel
- Get the lower file descriptor using funcion sgfs_get_lower()
- Check if the file is .sg folder(using complete paths, mount path(obtained from Superblock private_info) and file path from d_path)
- If it is .sg folder
- from the file name check if the file owner(first 4 bytes) is same as current user.
- If it is same 
	- Extract the original name of the file
	- Check the extension of the file
	- If extension is .enc
		- Rename it to CWD
	- Else 
		- Encrypt the content of file and write to a new file in .sg folder
	- If the encryption of writing fails in between
		- Unlink the new file created and restore the dentry of the file which was supposed to be deleted using d_drop
	- Else
		-Unlink the old file
		-Sync the upper level obejcts with lower level objects.
-Free all the buffers

IV. To List the files in .sg folder
- sgfs_readdir function was modified. and a new my_filldir() function is created
- Create a global struct dir_context and store the context received in this global variable.
- Create another new struct dir_context with actor function pointing to my_filldir()
	my_filldir()
	- from the file name check if the file owner(first 4 bytes) is same as current user.
	- If it is same 
	- call and the actor of the original context using global dir_context 
	- Else return 0
- If ls is issued in .sg folder
	- the call iterdir with new dir_context
- Else call iterdir with the old dir_context




REFERENCES:-

https://elixir.bootlin.com/linux/v3.2.29/source/fs/char_dev.c
http://lxr.fsl.cs.sunysb.edu/linux/source/kernel/audit.c#L1658
https://github.com/richygerard/file-encryption-decryption/



