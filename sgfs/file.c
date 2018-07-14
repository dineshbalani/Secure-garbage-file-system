/*
 * Copyright (c) 1998-2015 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2015 Stony Brook University
 * Copyright (c) 2003-2015 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "sgfs.h"

# include <linux/module.h>
# include <linux/kernel.h>
# include <linux/slab.h>
# include <linux/fs.h>
# include <linux/uaccess.h>
# include <generated/autoconf.h>
# include <asm/unistd.h>
# include <linux/err.h>
# include <linux/scatterlist.h>
# include <linux/stat.h>
# include <linux/namei.h>
# include <linux/hash.h>
# include <linux/slab.h>
# include <linux/mm.h>
# include <linux/key-type.h>
# include <linux/ceph/decode.h>
# include <crypto/md5.h>
# include <crypto/aes.h>
# include <linux/scatterlist.h>
# include <keys/ceph-type.h>

static const u8 *aes_iv = (u8 *)CEPH_AES_IV;

static ssize_t sgfs_read(struct file *file, char __user *buf,
			   size_t count, loff_t *ppos)
{
	int err;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = sgfs_lower_file(file);
	err = vfs_read(lower_file, buf, count, ppos);
	/* update our inode atime upon a successful lower read */
	if (err >= 0)
		fsstack_copy_attr_atime(d_inode(dentry),
					file_inode(lower_file));

	return err;
}

static ssize_t sgfs_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	int err;

	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = sgfs_lower_file(file);
	err = vfs_write(lower_file, buf, count, ppos);
	/* update our inode times+sizes upon a successful lower write */
	if (err >= 0) {
		fsstack_copy_inode_size(d_inode(dentry),
					file_inode(lower_file));
		fsstack_copy_attr_times(d_inode(dentry),
					file_inode(lower_file));
	}

	return err;
}

static struct crypto_blkcipher *ceph_crypto_alloc_cipher(void)
{
	return crypto_alloc_blkcipher("cbc(aes)", 0, CRYPTO_ALG_ASYNC);
}

static int m_decrypt(const void *key, int key_len,
                    void *dst, size_t *dst_len,
                    const void *src, size_t src_len,
                    int page, struct file *file_in)
{
    int ivsize;
    int ret;
    int last_byte;
    char pad[48];
    struct scatterlist sg_in[1], sg_out[2];
    struct crypto_blkcipher *tfm = ceph_crypto_alloc_cipher();
    struct blkcipher_desc desc = { .tfm = tfm };
    void *iv;

    if (IS_ERR(tfm))
        return PTR_ERR(tfm);

    /* Setting the key for Block cipher */
    crypto_blkcipher_setkey((void *)tfm, key, key_len);
    sg_init_table(sg_in, 1);
    sg_init_table(sg_out, 2);
    sg_set_buf(sg_in, src, src_len);
    sg_set_buf(&sg_out[0], dst, *dst_len);
    sg_set_buf(&sg_out[1], pad, sizeof(pad));

    iv = crypto_blkcipher_crt(tfm)->iv;
    ivsize = crypto_blkcipher_ivsize(tfm);
    memcpy(iv, aes_iv, ivsize);

    /* Crypto Block Cipher Decryption */
    ret = crypto_blkcipher_decrypt(&desc, sg_out, sg_in, src_len);
    crypto_free_blkcipher(tfm);

    if (ret < 0) {
        pr_err("AES DECRYPTION FAILED : %d\n", ret);
        return ret;
    }

    if (src_len <= *dst_len)
        last_byte = ((char *)dst)[src_len - 1];
    else
        last_byte = pad[src_len - *dst_len - 1];

    if (last_byte <= 16 && src_len >= last_byte) {

        *dst_len = src_len - last_byte;
    }
    else {
        pr_err("INVALID KEY!!\n");
        return -EPERM;
    }

    return 0;
}
struct dir_context *old_ctx;
static int my_filldir(struct dir_context *ctx, const char *name, int namlen,loff_t offset, u64 ino, unsigned int d_type){
	uid_t current_uid;
	uid_t file_uid;
	char *numbuf = NULL;
	int err =0;
	struct user_struct *u = current_user();
	current_uid = get_uid(u)->uid.val;

	if(!strcmp(name,".")||!strcmp(name,"..")){
		return old_ctx->actor(old_ctx, name, namlen, offset, ino, d_type);
	}
	numbuf = kmalloc(20,GFP_KERNEL);
	printk("INFO: Current user is: %d\n",(int)current_uid);
	strncpy(numbuf, name, 4);
	err = kstrtoint(numbuf,10,&file_uid);
	printk("INFO: File uid is %d\n",file_uid);
	if(current_uid!=file_uid&&current_uid!=0){
		printk("INFO: Current user is not the owner of the file\n");
		kfree(numbuf);
		return 0;
	}
	else{
		kfree(numbuf);
		return old_ctx->actor(old_ctx, name, namlen, offset, ino, d_type);
	}
}

static int sgfs_readdir(struct file *file, struct dir_context *ctx)
{
	int err;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;
	struct dir_context new_ctx  = { .actor = &my_filldir, .pos = ctx->pos};
	old_ctx = ctx;
	lower_file = sgfs_lower_file(file);
	if(!strcmp(file->f_path.dentry->d_iname,".sg")){
		err = iterate_dir(lower_file,&new_ctx);
	}
	else{
		err = iterate_dir(lower_file, ctx);
	}
	file->f_pos = lower_file->f_pos;
	if (err >= 0)		/* copy the atime */
		fsstack_copy_attr_atime(d_inode(dentry),
					file_inode(lower_file));
		return err;
}

static long sgfs_unlocked_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	long err = -ENOTTY;
	struct inode *dir;
	struct dentry *dentry;
	struct file *lower_file;
	struct dentry *lower_dentry=NULL;
	struct inode *lower_dir_inode = NULL;
	struct dentry *lower_dir_dentry=NULL;
	struct path lower_path;
	char *new_name = NULL;
	char *old_name=NULL, *pathname=NULL;
	char *key_buffer = NULL;
	mm_segment_t  in_oldfs;
	struct dentry *new_lower_dentry=NULL;
	struct inode *new_lower_dir_inode = NULL;
	struct path new_lower_path;
	struct file *new_filp=NULL,*old_filp=NULL;
	ssize_t *dstlen=NULL;
	int chunk_no = 0,old_bytes,new_bytes;
	int chunks=0;
	loff_t pos = 0;
	char *old_buf=NULL;
	char *new_buf=NULL;
	char *mount_path = NULL;
	uid_t current_uid;
	uid_t file_uid;
	char *numbuf = NULL;
	struct user_struct *u = current_user();


	if(!file){
		printk("ERROR: file is null\n");
	}



	printk("INFO: Path of Upper file: %s\n",file->f_path.dentry->d_name.name);
	lower_file = sgfs_lower_file(file);
	printk("INFO: Path of lower file: %s\n",lower_file->f_path.dentry->d_name.name);

	numbuf = kmalloc(20,GFP_KERNEL);
	current_uid = get_uid(u)->uid.val;
	printk("INFO: Current user is: %d\n",(int)current_uid);
	strncpy(numbuf, lower_file->f_path.dentry->d_name.name, 4);
	err = kstrtoint(numbuf,10,&file_uid);
	printk("INFO: File uid is: %d\n",file_uid);

	if(current_uid!=file_uid){
		err = -EACCES;
		printk("ERROR: Current user is not the owner of the file. Cannot undelete\n");
		goto free_numbuf;
	}

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;

	if (lower_file->f_op->unlocked_ioctl)
		err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);

	/* some ioctls can change inode attributes (EXT2_IOC_SETFLAGS) */
	if (!err)
		fsstack_copy_attr_all(file_inode(file),
							  file_inode(lower_file));

	dir = file->f_path.dentry->d_inode;
	dentry = file->f_path.dentry;
	lower_dir_inode = lower_file->f_path.dentry->d_parent->d_inode;
	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	dget(lower_dentry);


	pathname = kmalloc(PATH_MAX+11, GFP_KERNEL);
	if (!pathname)
	{
		printk("Error\n");
		goto out;
	}
	old_name = d_path(&lower_file->f_path, pathname, PATH_MAX+11);
	if (IS_ERR(old_name))
	{ /* Should never happen since we send PATH_MAX */
		goto free_pathName;
	}
	printk("INFO: Lower Absolute of file%s\n",old_name);

	mount_path = kmalloc(PATH_MAX, GFP_KERNEL);
	if(!mount_path){
		goto free_new_name;
	}
	strcpy(mount_path,SGFS_SB(dentry->d_sb)->root_path);
	strcat(mount_path,"/.sg/");
	strcat(mount_path,lower_file->f_path.dentry->d_name.name);

	printk("INFO: Mount Path Original.sg location%s\n",mount_path);

	/*Check if file is .sg folder */
	if(strcmp(old_name,mount_path)){
		err=-EINVAL;
		goto free_mount_path;
	}

	/*Extract original name of file*/
	printk("INFO: File is in .sg folder\n");
	new_name=kmalloc(20,GFP_KERNEL);
	if(!new_name){
		goto free_mount_path;
	}
	strcpy(new_name,lower_file->f_path.dentry->d_name.name+25);
	printk("INFO: Original name of file is %s\n",new_name);
	printk("INFO: Extension is %s\n",old_name+(strlen(old_name)-4));

	/*If extension is not enc then we have to just rename the file*/
	if(strcmp(old_name+(strlen(old_name)-4),".enc")){
		printk("Renaming the file \n");
		printk("INFO: Absolute Path of New file is %s \n",new_name);
		in_oldfs = get_fs();
		set_fs(KERNEL_DS);
		new_lower_dentry = user_path_create(AT_FDCWD, new_name, &new_lower_path, 0);
		set_fs(in_oldfs);
		if (IS_ERR(new_lower_dentry)){
			printk("ERROR: No Lower Dentry %d\n", (int) PTR_ERR(new_lower_dentry));
			err = PTR_ERR(new_lower_dentry);
			goto free_new_name;
		}
		done_path_create(&new_lower_path, new_lower_dentry);
		lock_rename(lower_file->f_path.dentry->d_parent,new_lower_dentry->d_parent);
		err = vfs_rename(lower_file->f_path.dentry->d_parent->d_inode, lower_file->f_path.dentry, new_lower_dentry->d_parent->d_inode,new_lower_dentry, NULL, 0);
		unlock_rename(lower_file->f_path.dentry->d_parent,new_lower_dentry->d_parent);
		if(err!=0){
			goto free_new_name;
		}
		goto free_new_name;
	}


	/*Get key from super block*/
	key_buffer = kmalloc(16,GFP_KERNEL);
	if(!key_buffer){
		goto free_new_name;
	}
	strcpy(key_buffer,SGFS_SB(file->f_path.dentry->d_sb)->key_t);

	if(!strcmp(key_buffer,"NO")){
		printk("ERROR: Key is not provided during mount option\n");
		err = -EINVAL;
		goto free_key_buf;
	}
	/*Else remove the .enc extension from the name*/
	snprintf(new_name,strlen(new_name)-3,"%s",new_name);
	printk("INFO: Original name of file %s \n",new_name);

	/*Open the original file in read mode*/
	old_filp = filp_open(old_name, O_RDONLY, 0);
	if (!old_filp || IS_ERR(old_filp)) {
		err = (int) PTR_ERR(old_filp); // return appropriate error
		goto free_key_buf;
	}
	old_filp->f_pos = 0;

	/*Open the new file with new name in write mode*/
	new_filp = filp_open(new_name, O_WRONLY | O_CREAT, old_filp->f_path.dentry->d_inode->i_mode);
	if (!new_filp || IS_ERR(new_filp)) {
		printk("sgfs_read_file err %d\n", (int) PTR_ERR(new_filp));
		err = (int) PTR_ERR(new_filp); // return appropriate error
		goto close_old_filp;
	}

	dstlen = kmalloc(sizeof(ssize_t), GFP_KERNEL);
	if(!dstlen){
		goto close_new_filp;
	}

	/*Write data to new file chunk by chunk*/
	chunks = (int)((i_size_read(old_filp->f_path.dentry->d_inode))/(PAGE_SIZE-16));
	printk("INFO: Write data to new file chunk by chunk %d\n",chunks);
	in_oldfs = get_fs();
	set_fs(KERNEL_DS);
	for(chunk_no=0;chunk_no<=chunks;chunk_no=chunk_no+1)
	{
		old_buf=kmalloc(PAGE_SIZE,GFP_KERNEL);
		if (old_buf == NULL) {
			err = -ENOMEM;
			goto free_dstlen;
		}
		new_buf=kmalloc(PAGE_SIZE,GFP_KERNEL);
		if (new_buf == NULL) {
			err = -ENOMEM;
			goto kfree_old_buf;
		}
		/*Read the data*/
		old_bytes = vfs_read(old_filp, old_buf, PAGE_SIZE, &old_filp->f_pos);
		if(old_bytes<=0){
			break;
		}
		old_filp->f_pos = old_filp->f_pos +old_bytes;
//		old_filp->f_pos =old_bytes;
		printk("INFO: Bytes Read: %d\n",old_bytes);
		/*Decrypt the data*/
		err = m_decrypt(key_buffer, strlen(key_buffer), new_buf, dstlen, old_buf, old_bytes, 1, old_filp);
		/*Decryption fails in between*/
		if (err < 0) {
			printk("Decryption Failed.\n");
			goto unlink_new_file;
		}
		printk("INFO: Decrypted bytes: %d\n",(int)*dstlen);
		/*Write to the new file*/
		new_bytes = vfs_write(new_filp, new_buf, *dstlen, &pos);
		printk("INFO: Written bytes: %d\n",new_bytes);
		pos = pos+new_bytes;
		/*Writing fails in between*/
		if(new_bytes<*dstlen){
			err = -EIO;
			goto unlink_new_file;
		}
		/*No more data to read*/
		if(old_bytes<PAGE_SIZE){
			break;
		}
		/*Free buffer for next chunk*/
		kfree(old_buf);
		kfree(new_buf);
	}
	set_fs(in_oldfs);

	/*Unlink the original file*/
	printk("INFO: Deleteing the original file\n");
	lower_dir_dentry = lock_parent(lower_dentry);
	err = vfs_unlink(lower_dir_inode, lower_dentry, NULL);
	/*
     * Note: unlinking on top of NFS can cause silly-renamed files.
     * Trying to delete such files results in EBUSY from NFS
     * below.  Silly-renamed files will get deleted by NFS later on, so
     * we just need to detect them here and treat such EBUSY errors as
     * if the upper file was successfully deleted.
     */
	if (err == -EBUSY && lower_dentry->d_flags & DCACHE_NFSFS_RENAMED)
		err = 0;
	if (err)
		goto out3;
	fsstack_copy_attr_times(dir, lower_dir_inode);
	fsstack_copy_inode_size(dir, lower_dir_inode);
	set_nlink(d_inode(dentry),
			  sgfs_lower_inode(d_inode(dentry))->i_nlink);
	d_inode(dentry)->i_ctime = dir->i_ctime;
	d_drop(dentry); /* this is needed, else LTP fails (VFS won't do it) */
	out3:
		unlock_dir(lower_dir_dentry);

	printk("INFO: Freeing the buffers\n");
	/*Free buffers*/
	kfree_new_buf:
		if(new_buf)
			kfree(new_buf);
	kfree_old_buf:
		if(old_buf)
			kfree(old_buf);
	free_dstlen:
		if(dstlen)
			kfree(dstlen);
	printk("INFO: Closing files\n");
	close_new_filp:
		filp_close(new_filp,NULL);
	close_old_filp:
		filp_close(old_filp,NULL);
	printk("INFO: Freeing the buffers\n");
	free_key_buf:
		if(key_buffer)
			kfree(key_buffer);
	free_new_name:
		if(new_name)
			kfree(new_name);
	free_mount_path:
		if(mount_path)
			kfree(mount_path);
	free_pathName:
		if(pathname)
			kfree(pathname);
	free_numbuf:
		if(numbuf)
			kfree(numbuf);
	printk("INFO: Freeing path and dentry\n");
		dput(lower_dentry);
		sgfs_put_lower_path(dentry, &lower_path);
	out:
	printk("INFO: Returning \n");
		/*Exit the Program */
		return err;

	/*If Encryption or writing fails partially then delete/unlink the new file*/
	unlink_new_file:
		printk("INFO: Unlink the new file\n");
		new_lower_dir_inode = new_filp->f_path.dentry->d_parent->d_inode;
		err = vfs_unlink(new_lower_dir_inode, new_filp->f_path.dentry, NULL);
		d_drop(dentry); /* this is needed, else LTP fails (VFS won't do it) */
		printk("INFO: Done Unlinking the file\n");
		/*Goto free buffers and then it will exit the program*/
		goto kfree_new_buf;

}

#ifdef CONFIG_COMPAT
static long sgfs_compat_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = sgfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
	return err;
}
#endif

static int sgfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;
	bool willwrite;
	struct file *lower_file;
	const struct vm_operations_struct *saved_vm_ops = NULL;

	/* this might be deferred to mmap's writepage */
	willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

	/*
	 * File systems which do not implement ->writepage may use
	 * generic_file_readonly_mmap as their ->mmap op.  If you call
	 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
	 * But we cannot call the lower ->mmap op, so we can't tell that
	 * writeable mappings won't work.  Therefore, our only choice is to
	 * check if the lower file system supports the ->writepage, and if
	 * not, return EINVAL (the same error that
	 * generic_file_readonly_mmap returns in that case).
	 */
	lower_file = sgfs_lower_file(file);
	if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
		err = -EINVAL;
		printk(KERN_ERR "sgfs: lower file system does not "
		       "support writeable mmap\n");
		goto out;
	}

	/*
	 * find and save lower vm_ops.
	 *
	 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
	 */
	if (!SGFS_F(file)->lower_vm_ops) {
		err = lower_file->f_op->mmap(lower_file, vma);
		if (err) {
			printk(KERN_ERR "sgfs: lower mmap failed %d\n", err);
			goto out;
		}
		saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
	}

	/*
	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
	 * don't want its test for ->readpage which returns -ENOEXEC.
	 */
	file_accessed(file);
	vma->vm_ops = &sgfs_vm_ops;

	file->f_mapping->a_ops = &sgfs_aops; /* set our aops */
	if (!SGFS_F(file)->lower_vm_ops) /* save for our ->fault */
		SGFS_F(file)->lower_vm_ops = saved_vm_ops;

out:
	return err;
}

static int sgfs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct path lower_path;

	/* don't open unhashed/deleted files */
	if (d_unhashed(file->f_path.dentry)) {
		err = -ENOENT;
		goto out_err;
	}

	file->private_data =
		kzalloc(sizeof(struct sgfs_file_info), GFP_KERNEL);
	if (!SGFS_F(file)) {
		err = -ENOMEM;
		goto out_err;
	}

	/* open lower object and link sgfs's file struct to lower's */
	sgfs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_file = dentry_open(&lower_path, file->f_flags, current_cred());
	path_put(&lower_path);
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		lower_file = sgfs_lower_file(file);
		if (lower_file) {
			sgfs_set_lower_file(file, NULL);
			fput(lower_file); /* fput calls dput for lower_dentry */
		}
	} else {
		sgfs_set_lower_file(file, lower_file);
	}

	if (err)
		kfree(SGFS_F(file));
	else
		fsstack_copy_attr_all(inode, sgfs_lower_inode(inode));
out_err:
	return err;
}

static int sgfs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = sgfs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush) {
		filemap_write_and_wait(file->f_mapping);
		err = lower_file->f_op->flush(lower_file, id);
	}

	return err;
}

/* release all lower object references & free the file info structure */
static int sgfs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;

	lower_file = sgfs_lower_file(file);
	if (lower_file) {
		sgfs_set_lower_file(file, NULL);
		fput(lower_file);
	}

	kfree(SGFS_F(file));
	return 0;
}

static int sgfs_fsync(struct file *file, loff_t start, loff_t end,
			int datasync)
{
	int err;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;

	err = __generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	lower_file = sgfs_lower_file(file);
	sgfs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	sgfs_put_lower_path(dentry, &lower_path);
out:
	return err;
}

static int sgfs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = sgfs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

	return err;
}

/*
 * Sgfs cannot use generic_file_llseek as ->llseek, because it would
 * only set the offset of the upper file.  So we have to implement our
 * own method to set both the upper and lower file offsets
 * consistently.
 */
static loff_t sgfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	int err;
	struct file *lower_file;

	err = generic_file_llseek(file, offset, whence);
	if (err < 0)
		goto out;

	lower_file = sgfs_lower_file(file);
	err = generic_file_llseek(lower_file, offset, whence);

out:
	return err;
}

/*
 * Sgfs read_iter, redirect modified iocb to lower read_iter
 */
ssize_t
sgfs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = sgfs_lower_file(file);
	if (!lower_file->f_op->read_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->read_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode atime as needed */
	if (err >= 0 || err == -EIOCBQUEUED)
		fsstack_copy_attr_atime(d_inode(file->f_path.dentry),
					file_inode(lower_file));
out:
	return err;
}

/*
 * Sgfs write_iter, redirect modified iocb to lower write_iter
 */
ssize_t
sgfs_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = sgfs_lower_file(file);
	if (!lower_file->f_op->write_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->write_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode times/sizes as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
		fsstack_copy_inode_size(d_inode(file->f_path.dentry),
					file_inode(lower_file));
		fsstack_copy_attr_times(d_inode(file->f_path.dentry),
					file_inode(lower_file));
	}
out:
	return err;
}

const struct file_operations sgfs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= sgfs_read,
	.write		= sgfs_write,
	.unlocked_ioctl	= sgfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= sgfs_compat_ioctl,
#endif
	.mmap		= sgfs_mmap,
	.open		= sgfs_open,
	.flush		= sgfs_flush,
	.release	= sgfs_file_release,
	.fsync		= sgfs_fsync,
	.fasync		= sgfs_fasync,
	.read_iter	= sgfs_read_iter,
	.write_iter	= sgfs_write_iter,
};

/* trimmed directory options */
const struct file_operations sgfs_dir_fops = {
	.llseek		= sgfs_file_llseek,
	.read		= generic_read_dir,
	.iterate	= sgfs_readdir,
	.unlocked_ioctl	= sgfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= sgfs_compat_ioctl,
#endif
	.open		= sgfs_open,
	.release	= sgfs_file_release,
	.flush		= sgfs_flush,
	.fsync		= sgfs_fsync,
	.fasync		= sgfs_fasync,
};
