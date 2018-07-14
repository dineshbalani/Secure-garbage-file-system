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
//#include "sys_xcrypt.h"
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
# include <linux/rtc.h>
# include <linux/cred.h>

static const u8 *aes_iv = (u8 *)CEPH_AES_IV;

static int sgfs_create(struct inode *dir, struct dentry *dentry,
			 umode_t mode, bool want_excl)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_create(d_inode(lower_parent_dentry), lower_dentry, mode,
			 want_excl);
	if (err)
		goto out;
	err = sgfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, sgfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int sgfs_link(struct dentry *old_dentry, struct inode *dir,
		       struct dentry *new_dentry)
{
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_dir_dentry;
	u64 file_size_save;
	int err;
	struct path lower_old_path, lower_new_path;

	file_size_save = i_size_read(d_inode(old_dentry));
	sgfs_get_lower_path(old_dentry, &lower_old_path);
	sgfs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_dir_dentry = lock_parent(lower_new_dentry);

	err = vfs_link(lower_old_dentry, d_inode(lower_dir_dentry),
		       lower_new_dentry, NULL);
	if (err || !d_inode(lower_new_dentry))
		goto out;

	err = sgfs_interpose(new_dentry, dir->i_sb, &lower_new_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, d_inode(lower_new_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_new_dentry));
	set_nlink(d_inode(old_dentry),
		  sgfs_lower_inode(d_inode(old_dentry))->i_nlink);
	i_size_write(d_inode(new_dentry), file_size_save);
out:
	unlock_dir(lower_dir_dentry);
	sgfs_put_lower_path(old_dentry, &lower_old_path);
	sgfs_put_lower_path(new_dentry, &lower_new_path);
	return err;
}

static struct crypto_blkcipher *ceph_crypto_alloc_cipher(void)
{
	return crypto_alloc_blkcipher("cbc(aes)", 0, CRYPTO_ALG_ASYNC);
}

static int sgfs_rename(struct inode *old_dir, struct dentry *old_dentry,
					   struct inode *new_dir, struct dentry *new_dentry)
{
	int err = 0;
	struct dentry *lower_old_dentry = NULL;
	struct dentry *lower_new_dentry = NULL;
	struct dentry *lower_old_dir_dentry = NULL;
	struct dentry *lower_new_dir_dentry = NULL;
	struct dentry *trap = NULL;
	struct path lower_old_path, lower_new_path;

	sgfs_get_lower_path(old_dentry, &lower_old_path);
	sgfs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_old_dir_dentry = dget_parent(lower_old_dentry);
	lower_new_dir_dentry = dget_parent(lower_new_dentry);

	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	/* source should not be ancestor of target */
	if (trap == lower_old_dentry) {
		err = -EINVAL;
		goto out;
	}
	/* target should not be ancestor of source */
	if (trap == lower_new_dentry) {
		err = -ENOTEMPTY;
		goto out;
	}

	err = vfs_rename(d_inode(lower_old_dir_dentry), lower_old_dentry,
					 d_inode(lower_new_dir_dentry), lower_new_dentry,
					 NULL, 0);
	if (err)
		goto out;

	fsstack_copy_attr_all(new_dir, d_inode(lower_new_dir_dentry));
	fsstack_copy_inode_size(new_dir, d_inode(lower_new_dir_dentry));
	if (new_dir != old_dir) {
		fsstack_copy_attr_all(old_dir,
							  d_inode(lower_old_dir_dentry));
		fsstack_copy_inode_size(old_dir,
								d_inode(lower_old_dir_dentry));
	}

	out:
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	dput(lower_old_dir_dentry);
	dput(lower_new_dir_dentry);
	sgfs_put_lower_path(old_dentry, &lower_old_path);
	sgfs_put_lower_path(new_dentry, &lower_new_path);
	return err;
}



static int m_encrypt(const void *key, int key_len, void *dst, size_t *dst_len,const void *src, size_t src_len,int page,struct file *file_out)
{
	int ret;
	int ivsize;
	char pad[48];
	size_t zero_padding = (0x10 - (src_len & 0x0f));
	struct scatterlist sg_in[2], sg_out[1];
	struct crypto_blkcipher *tfm = ceph_crypto_alloc_cipher();
	struct blkcipher_desc desc = { .tfm = tfm, .flags = 0 };
	void *iv;

	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	memset(pad, zero_padding, zero_padding);
	*dst_len = src_len + zero_padding;

	/* Setting the Key for Block cipher */
	crypto_blkcipher_setkey((void *)tfm, key, key_len);
	sg_init_table(sg_in, 2);
	sg_set_buf(&sg_in[0], src, src_len);
	sg_set_buf(&sg_in[1], pad, zero_padding);
	sg_init_table(sg_out, 1);
	sg_set_buf(sg_out, dst,*dst_len);

	/* Customizing Initialization Vector for Extra Credit A */
	iv = crypto_blkcipher_crt(tfm)->iv;
	ivsize = crypto_blkcipher_ivsize(tfm);
	memcpy(iv, aes_iv, ivsize);
	ret = crypto_blkcipher_encrypt(&desc, sg_out, sg_in,
								   src_len + zero_padding);
	crypto_free_blkcipher(tfm);

	if (ret < 0)
		pr_err("AES ENCRYPTION FAILED : %d\n", ret);
	return 0;;
}

static int sgfs_unlink(struct inode *dir, struct dentry *dentry)
{
	int err=0;
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry=NULL;
	struct inode *lower_dir_inode = sgfs_lower_inode(dir);
	struct path lower_path;

	mm_segment_t  in_oldfs;
	struct file *old_filp, *new_filp;
	char *old_buf=NULL;
	char *new_buf=NULL;
	char *old_name=NULL, *pathname=NULL, *new_name=NULL, *user_id=NULL;
	int chunk_no = 0,old_bytes,new_bytes;
	loff_t pos = 0;

	ssize_t dstlen;
	struct rtc_time tm;
	struct timeval time;
	unsigned long local_time;
	char *datetime = NULL;
	char *key_buffer = NULL;

	struct dentry *new_lower_dentry=NULL;
	struct path new_lower_path;
	char *numbuf = NULL;
	char *mount_path = NULL;
	uid_t current_uid;
	int chunks =0;
	uid_t file_uid;
	struct user_struct *u = current_user();
	current_uid = get_uid(u)->uid.val;
	printk("INFO: Current user is: %d\n",(int)current_uid);
	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	dget(lower_dentry);


	/* Check if dentny passed is direcrotry*/
	if(d_is_dir(dentry)){
		return -EINVAL;
	}

	user_id = kmalloc(40,GFP_KERNEL);
	if(!user_id){
		return -ENOMEM ;
	}
	/* Getting owner of file*/
	snprintf(user_id, 5, "%04d",dentry->d_inode->i_uid.val);
	printk("INFO: Owner of file is: %s\n",user_id);

	mount_path = kmalloc(PATH_MAX, GFP_KERNEL);
	if(!mount_path){
		err = -ENOMEM;
		goto free_user_id;
	}
	new_name = kmalloc(PATH_MAX+11, GFP_KERNEL);
	if(!new_name){
		err = -ENOMEM;
		goto free_mount_path;
	}

	/* Getting mount path and appending with .sg to get the original location of .sg folder*/
	strcpy(new_name,SGFS_SB(dentry->d_sb)->root_path);
	strcat(new_name,"/.sg/");
	strcpy(mount_path,new_name);
	strcat(mount_path,dentry->d_name.name);
	printk("INFO: Mount Path with .sg(Location of .sg): %s\n",mount_path);

	/* Getting absolute path of lower file name*/
	pathname = kmalloc(PATH_MAX+11, GFP_KERNEL);
	if (!pathname)
	{
		err = -ENOMEM;
		goto free_new_name;
	}
	old_name = d_path(&lower_path, pathname, PATH_MAX+11);
	if (IS_ERR(old_name))
	{ /* Should never happen since we send PATH_MAX */
		err = -ENOMEM;
		printk("ERROR: %d\n",err);
		goto free_pathName;
	}
	printk("INFO: Lower absolute path of file is: %s\n",old_name);

	/* Check of lower file path is equal to mount path(original location of .sg folder)*/
	if(!strcmp(old_name,mount_path)){
		printk("INFO: File is in .sg folder\n");
		/*Get the owner of file from the name of the file*/
		numbuf = kmalloc(20,GFP_KERNEL);
		if (!numbuf)
		{
			err = -ENOMEM;
			printk("ERROR: %d\n",err);
			goto free_pathName;
		}
		strncpy(numbuf, dentry->d_name.name, 4);
		err = kstrtoint(numbuf,10,&file_uid);
		printk("INFO: File uid is: %d\n",file_uid);
		/* Check if owner of file(from file name and current user are same*/
		if(file_uid==current_uid||current_uid==0){
			/* Delete the file */
			printk("INFO: Owner of file is same as current user or current user is root\n");
			printk("INFO: Delete the file\n");
			kfree(numbuf);
			goto directly_delete;
		}
		kfree(numbuf);
		/* User is not allowed to delete the file*/
		err = -EACCES;
		printk("ERROR: User is Not allowed to delete file: %d\n",err);
		d_drop(dentry);
		goto out2;
	}
	printk("INFO: File is not in .sg folder\n");

	/*Get the key from Super block private info structure*/
	key_buffer = kmalloc(16,GFP_KERNEL);
	if(!key_buffer){
		err = -ENOMEM;
		goto free_pathName;
	}
	strcpy(key_buffer,SGFS_SB(dentry->d_sb)->key_t);

	/*Get date and time of day*/
	datetime = kmalloc(22,GFP_KERNEL);
	if(!datetime){
		err = -ENOMEM;
		printk("ERROR: %d\n",err);
		goto free_key_buf;
	}
	do_gettimeofday(&time);
	local_time = (u32)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
	rtc_time_to_tm(local_time, &tm);
	/*Generate new name of file to be moved to .sg folder in format USERID-DATETIME-FILENAME-EXTENSTION*/
	snprintf(datetime, 22, ":%04d-%02d-%02d-%02d:%02d:%02d-", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
	strcat(user_id,datetime);
	strcat(new_name,user_id);
	strcat(new_name,dentry->d_iname);

	printk("Key : %s \n",key_buffer);

	/*If No key is given , Rename the file to the new name and location i.e. .sg folder*/

	if(!strcmp(key_buffer,"NO")){
			printk("INFO: No key is given. Rename to another folder\n");
			printk("INFO: Absolute Path of New file is %s \n",new_name);
			in_oldfs = get_fs();
			set_fs(KERNEL_DS);
			new_lower_dentry = user_path_create(AT_FDCWD, new_name, &new_lower_path, 0);
			set_fs(in_oldfs);
			if (IS_ERR(new_lower_dentry)){
				err = (int)PTR_ERR(new_lower_dentry);
				printk("ERROR: %d\n",err);
				goto free_datetime;
			}
			done_path_create(&new_lower_path, new_lower_dentry);
			lock_rename(lower_dentry->d_parent,new_lower_dentry->d_parent);
			err = vfs_rename(lower_dentry->d_parent->d_inode, lower_dentry, new_lower_dentry->d_parent->d_inode,new_lower_dentry, NULL, 0);
			unlock_rename(lower_dentry->d_parent,new_lower_dentry->d_parent);
			if(err!=0){
				printk("ERROR: %d\n",err);
				goto free_datetime;
			}
			goto free_datetime;
	}

	/*Else If key is given , append .enc in the name of the file to be created */
	strcat(new_name,".enc");
	/*Open the original file in read mode*/
	old_filp = filp_open(old_name, O_RDONLY, 0);
	if (!old_filp || IS_ERR(old_filp)) {
		err = (int) PTR_ERR(old_filp); // return appropriate error
		printk("ERROR: %d\n",err);
		goto free_datetime;
	}
	old_filp->f_pos = 0;  /* start offset */

	/*Open the new file with new name in write mode*/
	printk("INFO: Absolute Path of New file is %s \n",new_name);
	new_filp = filp_open(new_name, O_WRONLY | O_CREAT, dir->i_mode);
	if (!new_filp || IS_ERR(new_filp)) {
		printk("sgfs_read_file err %d\n", (int) PTR_ERR(new_filp));
		err = (int) PTR_ERR(new_filp); // return appropriate error
		printk("ERROR: %d\n",err);
		goto close_old_filp;
	}

	/*Write data to new file chunk by chunk*/
	chunks = (int)((i_size_read(old_filp->f_path.dentry->d_inode))/(PAGE_SIZE-16));
	printk("INFO: Write data to new file chunk by chunk Number of chunks: %d\n",chunks);
	in_oldfs = get_fs();
	set_fs(KERNEL_DS);
	for(chunk_no=0;chunk_no<=chunks;chunk_no=chunk_no+1)
	{
		old_buf=kmalloc(PAGE_SIZE,GFP_KERNEL);
		if (old_buf == NULL) {
			err = -ENOMEM;
			goto close_new_filp;
		}
		new_buf=kmalloc(PAGE_SIZE,GFP_KERNEL);
		if (old_buf == NULL) {
			err = -ENOMEM;
			goto kfree_old_buf;
		}

		/*Read the data*/
		old_bytes = vfs_read(old_filp, old_buf, PAGE_SIZE-16, &old_filp->f_pos);
		if(old_bytes<=0){
			break;
		}
		old_filp->f_pos = old_filp->f_pos +old_bytes;
		printk("INFO: Bytes Read %d\n", old_bytes);
		/*Encrypt the data*/
		err = m_encrypt(key_buffer, (int)strlen(key_buffer), new_buf, &dstlen, old_buf, old_bytes, 1, old_filp);
		/*Encryption fails in between*/
		if (err < 0) {
			printk("ERROR: Encryption Failed.\n");
			goto unlink_new_file;
		}
		printk("INFO: Encrypted bytes %d\n",(int)dstlen);
//		goto unlink_new_file;
		/*Write to the new file*/
		new_bytes = vfs_write(new_filp, new_buf, (int)dstlen, &pos);
		pos = pos+new_bytes;
		printk("INFO: Bytes Written %d\n", new_bytes);
		/*Writing fails in between*/
		if(new_bytes<(int)dstlen){
			err = -EIO;
			goto unlink_new_file;
		}
		/*No more data to read*/
		if(old_bytes<PAGE_SIZE-16){
//			goto unlink_new_file;
			break;
		}
		/*Free buffer for next chunk*/
		kfree(old_buf);
		kfree(new_buf);
	}
	set_fs(in_oldfs);

	if(new_buf)
		kfree(new_buf);
	kfree_old_buf:
		if(old_buf)
		kfree(old_buf);
	close_new_filp:
		filp_close(new_filp,NULL);
	close_old_filp:
		filp_close(old_filp,NULL);


	printk("INFO: Deleteing the original file\n");
	/*Unlink the original file*/
	directly_delete:
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
			goto out;
		fsstack_copy_attr_times(dir, lower_dir_inode);
		fsstack_copy_inode_size(dir, lower_dir_inode);
		set_nlink(d_inode(dentry),
				  sgfs_lower_inode(d_inode(dentry))->i_nlink);
		d_inode(dentry)->i_ctime = dir->i_ctime;
		d_drop(dentry); /* this is needed, else LTP fails (VFS won't do it) */
	out:
		unlock_dir(lower_dir_dentry);

	printk("INFO: Freeing the buffers\n");
	/*Free buffers*/
	free_datetime:
		if(datetime)
			kfree(datetime);
	free_pathName:
		if(pathname)
			kfree(pathname);
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
	free_user_id:
		if(user_id)
			kfree(user_id);
	printk("INFO: Freeing dentry and sgfs_path\n");
	out2:
		dput(lower_dentry);
		sgfs_put_lower_path(dentry, &lower_path);

	/*Exit the Program */
	return err;

	/*If Encryption or writing fails partially then delete/unlink the new file*/
	unlink_new_file:
		printk("INFO: Unlink the new file\n");
		err = vfs_unlink(new_filp->f_path.dentry->d_parent->d_inode, new_filp->f_path.dentry, NULL);
		d_drop(dentry);
		if(new_buf)
			kfree(new_buf);
		if(old_buf)
			kfree(old_buf);
		filp_close(new_filp,NULL);
		filp_close(old_filp,NULL);
		printk("INFO: Done Unlinking the file\n");
		/*Goto free buffers and then it will exit the program*/
		goto free_datetime;

}

static int sgfs_symlink(struct inode *dir, struct dentry *dentry,
			  const char *symname)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_symlink(d_inode(lower_parent_dentry), lower_dentry, symname);
	if (err)
		goto out;
	err = sgfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, sgfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int sgfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);
	printk("Dinesh\n");
	err = vfs_mkdir(d_inode(lower_parent_dentry), lower_dentry, mode);
	if (err)
		goto out;

	err = sgfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;

	fsstack_copy_attr_times(dir, sgfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));
	/* update number of links on parent directory */
	set_nlink(dir, sgfs_lower_inode(dir)->i_nlink);

out:
	unlock_dir(lower_parent_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int sgfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	int err;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_dir_dentry = lock_parent(lower_dentry);

	err = vfs_rmdir(d_inode(lower_dir_dentry), lower_dentry);
	if (err)
		goto out;

	d_drop(dentry);	/* drop our dentry on success (why not VFS's job?) */
	if (d_inode(dentry))
		clear_nlink(d_inode(dentry));
	fsstack_copy_attr_times(dir, d_inode(lower_dir_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_dir_dentry));
	set_nlink(dir, d_inode(lower_dir_dentry)->i_nlink);

out:
	unlock_dir(lower_dir_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int sgfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
			dev_t dev)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_mknod(d_inode(lower_parent_dentry), lower_dentry, mode, dev);
	if (err)
		goto out;

	err = sgfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, sgfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

/*
 * The locking rules in sgfs_rename are complex.  We could use a simpler
 * superblock-level name-space lock for renames and copy-ups.
 */

static int sgfs_readlink(struct dentry *dentry, char __user *buf, int bufsiz)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op ||
	    !d_inode(lower_dentry)->i_op->readlink) {
		err = -EINVAL;
		goto out;
	}

	err = d_inode(lower_dentry)->i_op->readlink(lower_dentry,
						    buf, bufsiz);
	if (err < 0)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry), d_inode(lower_dentry));

out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static const char *sgfs_get_link(struct dentry *dentry, struct inode *inode,
				   struct delayed_call *done)
{
	char *buf;
	int len = PAGE_SIZE, err;
	mm_segment_t old_fs;

	if (!dentry)
		return ERR_PTR(-ECHILD);

	/* This is freed by the put_link method assuming a successful call. */
	buf = kmalloc(len, GFP_KERNEL);
	if (!buf) {
		buf = ERR_PTR(-ENOMEM);
		return buf;
	}

	/* read the symlink, and then we will follow it */
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = sgfs_readlink(dentry, buf, len);
	set_fs(old_fs);
	if (err < 0) {
		kfree(buf);
		buf = ERR_PTR(err);
	} else {
		buf[err] = '\0';
	}
	set_delayed_call(done, kfree_link, buf);
	return buf;
}

static int sgfs_permission(struct inode *inode, int mask)
{
	struct inode *lower_inode;
	int err;

	lower_inode = sgfs_lower_inode(inode);
	err = inode_permission(lower_inode, mask);
	return err;
}

static int sgfs_setattr(struct dentry *dentry, struct iattr *ia)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *inode;
	struct inode *lower_inode;
	struct path lower_path;
	struct iattr lower_ia;

	inode = d_inode(dentry);

	/*
	 * Check if user has permission to change inode.  We don't check if
	 * this user can change the lower inode: that should happen when
	 * calling notify_change on the lower inode.
	 */
	err = inode_change_ok(inode, ia);
	if (err)
		goto out_err;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_inode = sgfs_lower_inode(inode);

	/* prepare our own lower struct iattr (with the lower file) */
	memcpy(&lower_ia, ia, sizeof(lower_ia));
	if (ia->ia_valid & ATTR_FILE)
		lower_ia.ia_file = sgfs_lower_file(ia->ia_file);

	/*
	 * If shrinking, first truncate upper level to cancel writing dirty
	 * pages beyond the new eof; and also if its' maxbytes is more
	 * limiting (fail with -EFBIG before making any change to the lower
	 * level).  There is no need to vmtruncate the upper level
	 * afterwards in the other cases: we fsstack_copy_inode_size from
	 * the lower level.
	 */
	if (ia->ia_valid & ATTR_SIZE) {
		err = inode_newsize_ok(inode, ia->ia_size);
		if (err)
			goto out;
		truncate_setsize(inode, ia->ia_size);
	}

	/*
	 * mode change is for clearing setuid/setgid bits. Allow lower fs
	 * to interpret this in its own way.
	 */
	if (lower_ia.ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID))
		lower_ia.ia_valid &= ~ATTR_MODE;

	/* notify the (possibly copied-up) lower inode */
	/*
	 * Note: we use d_inode(lower_dentry), because lower_inode may be
	 * unlinked (no inode->i_sb and i_ino==0.  This happens if someone
	 * tries to open(), unlink(), then ftruncate() a file.
	 */
	inode_lock(d_inode(lower_dentry));
	err = notify_change(lower_dentry, &lower_ia, /* note: lower_ia */
			    NULL);
	inode_unlock(d_inode(lower_dentry));
	if (err)
		goto out;

	/* get attributes from the lower inode */
	fsstack_copy_attr_all(inode, lower_inode);
	/*
	 * Not running fsstack_copy_inode_size(inode, lower_inode), because
	 * VFS should update our inode size, and notify_change on
	 * lower_inode should update its size.
	 */

out:
	sgfs_put_lower_path(dentry, &lower_path);
out_err:
	return err;
}

static int sgfs_getattr(struct vfsmount *mnt, struct dentry *dentry,
			  struct kstat *stat)
{
	int err;
	struct kstat lower_stat;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	err = vfs_getattr(&lower_path, &lower_stat);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry),
			      d_inode(lower_path.dentry));
	generic_fillattr(d_inode(dentry), stat);
	stat->blocks = lower_stat.blocks;
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int
sgfs_setxattr(struct dentry *dentry, const char *name, const void *value,
		size_t size, int flags)
{
	int err; struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op->setxattr) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_setxattr(lower_dentry, name, value, size, flags);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry),
			      d_inode(lower_path.dentry));
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static ssize_t
sgfs_getxattr(struct dentry *dentry, const char *name, void *buffer,
		size_t size)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op->getxattr) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_getxattr(lower_dentry, name, buffer, size);
	if (err)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry),
				d_inode(lower_path.dentry));
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static ssize_t
sgfs_listxattr(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op->listxattr) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_listxattr(lower_dentry, buffer, buffer_size);
	if (err)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry),
				d_inode(lower_path.dentry));
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int
sgfs_removexattr(struct dentry *dentry, const char *name)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op ||
	    !d_inode(lower_dentry)->i_op->removexattr) {
		err = -EINVAL;
		goto out;
	}
	err = vfs_removexattr(lower_dentry, name);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry),
			      d_inode(lower_path.dentry));
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}
const struct inode_operations sgfs_symlink_iops = {
	.readlink	= sgfs_readlink,
	.permission	= sgfs_permission,
	.setattr	= sgfs_setattr,
	.getattr	= sgfs_getattr,
	.get_link	= sgfs_get_link,
	.setxattr	= sgfs_setxattr,
	.getxattr	= sgfs_getxattr,
	.listxattr	= sgfs_listxattr,
	.removexattr	= sgfs_removexattr,
};

const struct inode_operations sgfs_dir_iops = {
	.create		= sgfs_create,
	.lookup		= sgfs_lookup,
	.link		= sgfs_link,
	.unlink		= sgfs_unlink,
	.symlink	= sgfs_symlink,
	.mkdir		= sgfs_mkdir,
	.rmdir		= sgfs_rmdir,
	.mknod		= sgfs_mknod,
	.rename		= sgfs_rename,
	.permission	= sgfs_permission,
	.setattr	= sgfs_setattr,
	.getattr	= sgfs_getattr,
	.setxattr	= sgfs_setxattr,
	.getxattr	= sgfs_getxattr,
	.listxattr	= sgfs_listxattr,
	.removexattr	= sgfs_removexattr,
};

const struct inode_operations sgfs_main_iops = {
	.permission	= sgfs_permission,
	.setattr	= sgfs_setattr,
	.getattr	= sgfs_getattr,
	.setxattr	= sgfs_setxattr,
	.getxattr	= sgfs_getxattr,
	.listxattr	= sgfs_listxattr,
	.removexattr	= sgfs_removexattr,
};
