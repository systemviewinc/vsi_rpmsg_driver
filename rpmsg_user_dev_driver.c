/*
 * RPMSG User Device Kernel Driver
 *
 * Copyright (C) 2014 Mentor Graphics Corporation
 * Copyright (C) 2015 Xilinx, Inc.
 * Copyright (C) 2016 Systemview Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/rpmsg.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/kfifo.h>
#include <linux/uaccess.h>
#include <linux/kthread.h>
#include <linux/ioctl.h>
#include <linux/errno.h>
#include <linux/rpmsg.h>
#include <linux/spinlock.h>

#include "vsi_rpmsg_header.h"


/* Shutdown message ID */
#define SHUTDOWN_MSG			0xEF56A55A

#define RPMSG_USER_DEV_MAX_MINORS 10

#define RPMSG_INIT_MSG "init_msg"

#define USEABLE_BUFF_SIZE		(MAX_RPMSG_BUFF_SIZE-sizeof(struct _rpmsg_proxy_header))
/**
 * rpmsg per file data structure initialized when opened
 * 
 */
struct _rpmsg_file_params {
	int 	 	minor_num;
	int		established;
	spinlock_t 	sync_lock;
	struct kfifo    rx_kfifo;
	int 		block_flag;	
	char 		tx_buff[MAX_RPMSG_BUFF_SIZE]; /* buffer to keep the message to send */
};

/**
 * rpmsg device parameters
 * 
 */
struct _rpmsg_dev_params {
	int 			rpmsg_major;
	struct device 		*rpmsg_dev;
	wait_queue_head_t 	usr_wait_q;
	struct rpmsg_channel 	*rpmsg_chnl;
	u32 			rpmsg_dst;
	int			n_files;
	struct _rpmsg_file_params **_file_parms;
	char 			g_tx_buff[MAX_RPMSG_BUFF_SIZE]; /* buffer to keep the message to send */
};

/* module parameters */
static int major = 242; // nothing special just more than vsi_driver
module_param(major, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);/**< Insmod Parameter */
MODULE_PARM_DESC(major, "MajorNumber");/**< Insmod Parameter */

static int rpmsg_max_files = 32; // maximum number of files allowed
module_param(rpmsg_max_files, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);/**< Insmod Parameter */
MODULE_PARM_DESC(rpmsg_max_files, "MaximumNumberOfFiles");/**< Insmod Parameter */

/* global variables */
spinlock_t 		_cb_lock  ;
int			wt_block;
wait_queue_head_t 	write_thread_b;
wait_queue_head_t 	write_thread_e;
spinlock_t 		wt_fifo_lock;
struct kfifo		write_thread_fifo;

struct mutex _g_access; // protect access to global variables
struct mutex _g_write;  // only one thread can write at a time
static struct _rpmsg_dev_params *_g_rdp;
static int *_rpmsg_tgt_file_opened;

static const char *const shutdown_argv[]
		= { "/sbin/shutdown", "-h", "-P", "now", NULL };
static struct class *rpmsg_class;


/** 
 * @brief called when a remote proc file is opened
 * 
 * @param inode 
 * @param p_file 
 * 
 * @return 
 */
static int rpmsg_dev_open(struct inode *inode, struct file *p_file)
{
	struct _rpmsg_file_params *rfp;
	struct _rpmsg_proxy_header rph;
	int status;
	if (MINOR(inode->i_rdev) >= rpmsg_max_files) {
		pr_err("vsi_rpmsg_driver: minor number (%d) exceeds max (%d)\n",rpmsg_max_files,MINOR(inode->i_rdev));
		return -ENFILE;
	}
	if (_rpmsg_tgt_file_opened[ MINOR(inode->i_rdev)] > 1) {
		pr_err("vsi_rpmsg_driver: minor already open %d\n", MINOR(inode->i_rdev));
		return -EACCES;
	}
	while(mutex_lock_interruptible(&_g_access));

	/* Initialize rpmsg instance with device params from inode */
	rfp = (struct _rpmsg_file_params *)kmalloc(sizeof(struct _rpmsg_file_params), GFP_KERNEL);
	memset(rfp,0,sizeof(struct _rpmsg_file_params));
	
	/* save the minor */
	rfp->minor_num = MINOR(inode->i_rdev);

	/* Initialize mutex */
	spin_lock_init(&rfp->sync_lock);

	/* Allocate kfifo for rpmsg */
	status = kfifo_alloc(&rfp->rx_kfifo, RPMSG_KFIFO_SIZE, GFP_KERNEL);
	if (status) {
		pr_err("Failed to run kfifo_alloc.");
		mutex_unlock(&_g_access);
		return -1;
	}
	kfifo_reset(&rfp->rx_kfifo);

	p_file->private_data = rfp;

	// update globals
	_g_rdp->_file_parms[rfp->minor_num] = rfp;
	mutex_unlock(&_g_access);

	// wait till remote opens the file as well
	if (!_rpmsg_tgt_file_opened[rfp->minor_num]) {
		wait_event_interruptible(_g_rdp->usr_wait_q, 
					 _rpmsg_tgt_file_opened[rfp->minor_num] != 0);
	} 

	while(mutex_lock_interruptible(&_g_access));

	// tell remote both sides are open
	rph.operation = RPROC_FOPEN;
	rph.minor_num = rfp->minor_num;
	rph.xfer_len  = sizeof(rph);
	memcpy(rfp->tx_buff, &rph,sizeof(rph));
	if (rpmsg_sendto(_g_rdp->rpmsg_chnl, rfp->tx_buff, sizeof(rph), _g_rdp->rpmsg_chnl->dst))
		pr_err("cannot send open message to remote\n");
	_rpmsg_tgt_file_opened[rfp->minor_num]++;
	rfp->established = 1;
	mutex_unlock(&_g_access);
	pr_info("opened file %d rx kfifo size = %d  element size %d\n", 
		rfp->minor_num, kfifo_size(&rfp->rx_kfifo), kfifo_esize(&rfp->rx_kfifo));

	return 0;
}

/** 
 * @brief rease or close the file
 * 
 * @param inode 
 * @param p_file 
 * 
 * @return 
 */
static int rpmsg_dev_release(struct inode *inode, struct file *p_file)
{
	struct _rpmsg_file_params *rfp = p_file->private_data;
	int err, minor;

	minor = rfp->minor_num;
	pr_info("%s minor (%d)", __func__, minor);

	/* if remote still has it open */
	while(mutex_lock_interruptible(&_g_access));

	if (rfp->established) {
		/* send close to remote */		
		struct _rpmsg_proxy_header rph;
		rph.operation = RPROC_FCLOSE;
		rph.minor_num = minor;
		rph.xfer_len  = sizeof(rph);
		memcpy(rfp->tx_buff, &rph,sizeof(rph));
		err = rpmsg_sendto(_g_rdp->rpmsg_chnl, rfp->tx_buff, sizeof(rph), _g_rdp->rpmsg_chnl->dst);
		if (err) {
			pr_err("cannot send close message to remote (%d)\n",err);
		}
	}
	kfifo_free(&rfp->rx_kfifo);

	_g_rdp->_file_parms[minor]    = 0;
	_rpmsg_tgt_file_opened[minor]--;
	mutex_unlock(&_g_access);
	kfree(rfp);
	return 0;
}

static void write_thread (struct rpmsg_channel 	*rpmsg_chnl)
{	
	char xbuffer [MAX_RPMSG_BUFF_SIZE*2];
	int len;
	printk(KERN_INFO"write_thread started %p\n", rpmsg_chnl);
	while(!kthread_should_stop()){
		wait_event_interruptible(write_thread_b,wt_block != 0);
		// some one put something in
		spin_lock(&wt_fifo_lock);
		while ((len = kfifo_len(&write_thread_fifo)) != 0) {
			if (len > MAX_RPMSG_BUFF_SIZE) len = MAX_RPMSG_BUFF_SIZE;
			kfifo_out(&write_thread_fifo,xbuffer,len);
			rpmsg_sendto(rpmsg_chnl,xbuffer,len,rpmsg_chnl->dst);
			printk(KERN_INFO,"%s sent %d bytes\n",__func__,len);
		} 
		wt_block = 0;
		spin_unlock(&wt_fifo_lock);
		wake_up_interruptible(&write_thread_e);
	}

	printk(KERN_INFO"Leaving write_thread\n");
}

/** 
 * @brief called for a device write
 * 
 * @param p_file 
 * @param ubuff 
 * @param len 
 * @param p_off 
 * 
 * @return 
 */
static ssize_t rpmsg_dev_write(struct file *p_file,
				const char __user *ubuff, size_t len,
				loff_t *p_off)
{
	struct _rpmsg_file_params *local = p_file->private_data;
	struct _rpmsg_proxy_header rph;
	int err, wlen = len;
	unsigned int size, bytes;

	while(mutex_lock_interruptible(&_g_write)); // only one thread can enter write
	//pr_info("write( %d, %p , %d)\n",local->minor_num, ubuff, len);
	while (wlen > 0) {
		if (wlen < USEABLE_BUFF_SIZE) size = wlen;
		else size = USEABLE_BUFF_SIZE;

		//prepend operation 
		rph.operation = RPROC_FWRITE;
		rph.minor_num = local->minor_num;
		rph.xfer_len  = size ;


		if (wt_block != 0) wait_event_interruptible(write_thread_e,wt_block == 0);

		spin_lock(&wt_fifo_lock);
		kfifo_in(&write_thread_fifo,&rph,sizeof(rph));
		kfifo_from_user(&write_thread_fifo,ubuff,size,&bytes);
		if (bytes != size) printk(KERN_INFO"%s copy from user problem %d %d\n",__func__,bytes,size);
		wt_block = 1;
		spin_unlock(&wt_fifo_lock);
		wake_up_interruptible(&write_thread_b);
		/* // ensures that the write goes as one packet  */
		/* memcpy(local->tx_buff,&rph,sizeof(rph)); */
		/* // copy into kernel space  */
		/* if (copy_from_user(local->tx_buff+sizeof(rph), ubuff, size)) { */
		/* 	pr_err("%s: user to kernel buff copy error.\n", __func__); */
		/* 	len = -1; */
		/* 	break; */
		/* } */
		/* err = rpmsg_sendto(_g_rdp->rpmsg_chnl, local->tx_buff, size + sizeof(rph), _g_rdp->rpmsg_chnl->dst); */
		/* if (err) { */
		/* 	pr_err("rpmsg_sendto (size = %d) error: %d\n", size, err); */
		/* 	len = -1; */
		/* 	size = 0; */
		/* 	break; */
		/* }  */
		ubuff += size;
		wlen  -= size;
	} 

	mutex_unlock(&_g_write);
	return len;
}

/** 
 * @brief called for a device read
 * 
 * @param p_file 
 * @param ubuff 
 * @param len 
 * @param p_off 
 * 
 * @return 
 */
static ssize_t rpmsg_dev_read(struct file *p_file, char __user *ubuff,
				size_t len, loff_t *p_off)
{
	struct _rpmsg_file_params *local = p_file->private_data;
	int retval;
	unsigned int data_available, data_used, bytes_copied;
	
	if (!local->established) {
		pr_err("open not completed no reads allowed minor(%d)\n",local->minor_num);
		return -EAGAIN;
	}

	spin_lock(&local->sync_lock);
	if (local->block_flag ==  0) {
		spin_unlock(&local->sync_lock);

		/* if non-blocking read is requested return error */
		if (p_file->f_flags & O_NONBLOCK)
			return -EAGAIN;

		/* Block the calling context till data becomes available */
		wait_event_interruptible(_g_rdp->usr_wait_q,
					local->block_flag != 0);
		spin_lock(&local->sync_lock);
	}

	/* Provide requested data size to user space */
	data_available = kfifo_len(&local->rx_kfifo);
	data_used = (data_available > len) ? len : data_available;
	retval = kfifo_to_user(&local->rx_kfifo, ubuff, data_used, &bytes_copied);
	if (data_used != bytes_copied) {
		pr_err("copied less to user space %d %d\n",data_used, bytes_copied);
	}
	/* reset block flag : if all data is read */
	local->block_flag = (bytes_copied < data_available) ? 1 : 0;

	/* Release lock on rpmsg kfifo */
	spin_unlock(&local->sync_lock);

	return retval ? retval : bytes_copied;
}

/** 
 * @brief ioctl call
 * 
 * @param p_file 
 * @param cmd 
 * @param arg 
 * 
 * @return 
 */
static long rpmsg_dev_ioctl(struct file *p_file, unsigned int cmd,
				unsigned long arg)
{
	unsigned int tmp;
	struct _rpmsg_file_params *local = p_file->private_data;

	switch (cmd) {
	case IOCTL_CMD_GET_KFIFO_SIZE:
		tmp = kfifo_size(&local->rx_kfifo);
		if (copy_to_user((unsigned int *)arg, &tmp, sizeof(int)))
			return -EACCES;
		break;

	case IOCTL_CMD_GET_AVAIL_DATA_SIZE:
		tmp = kfifo_len(&local->rx_kfifo);
		pr_info("kfifo len ioctl = %d  element size %d", 
			kfifo_len(&local->rx_kfifo), kfifo_esize(&local->rx_kfifo));
		if (copy_to_user((unsigned int *)arg, &tmp, sizeof(int)))
			return -EACCES;
		break;
	case IOCTL_CMD_GET_FREE_BUFF_SIZE:
		tmp = kfifo_avail(&local->rx_kfifo);
		if (copy_to_user((unsigned int *)arg, &tmp, sizeof(int)))
			return -EACCES;
		break;

	default:
		return -EINVAL;
	}

	return 0;
}


/** 
 * @brief will wait till data arrives on the 
 * 
 * @param filep 
 * @param pwait 
 * 
 * @return 
 */
static unsigned int rpmsg_dev_poll(struct file *p_file, poll_table * pwait)
{
	struct _rpmsg_file_params *rfp = p_file->private_data;
	unsigned long lock_flags;
	unsigned int mask = 0;

	poll_wait(p_file,&_g_rdp->usr_wait_q,pwait);
	spin_lock_irqsave(&rfp->sync_lock,lock_flags);
	if (rfp->block_flag != 0) {
		spin_unlock_irqrestore(&rfp->sync_lock,lock_flags);
		printk(KERN_INFO"got data data %p\n",&rfp->block_flag);
		mask |= POLLIN;
	} else 	spin_unlock_irqrestore(&rfp->sync_lock,lock_flags);

	return mask;
}


static void rpmsg_user_dev_rpmsg_drv_cb(struct rpmsg_channel *rpdev, void *data,
					int len, void *priv, u32 src)
{
	struct _rpmsg_proxy_header rph = {0,0,0};
	struct _rpmsg_file_params *local;
	unsigned long  _lock_flags;

	/* Shutdow Linux if such a message is received. Only applicable
	when Linux is a remoteproc remote. */
	if ((*(int *) data) == SHUTDOWN_MSG) {
		dev_info(&rpdev->dev,"shutdown message is received. Shutting down...\n");
		call_usermodehelper((char*)shutdown_argv[0], (char**)shutdown_argv,
					NULL, UMH_NO_WAIT);
	} else {
		if (len < sizeof(rph)) {
			pr_err("message len to short ignored %d\n",len);
			return ;
		}
		spin_lock_irqsave(&_cb_lock,_lock_flags);
		memcpy(&rph,data,sizeof(rph));
		len  -= sizeof(rph);
		data  = ((char *)data) + sizeof(rph);
		if (rph.minor_num != 0 && rph.minor_num != 1) {
			pr_err("Invalid header %d, %d, %d\n",rph.operation, rph.minor_num, rph.xfer_len);
			spin_unlock_irqrestore(&_cb_lock, _lock_flags);
			return;
		}
		local = _g_rdp->_file_parms[rph.minor_num];
		//pr_info("local %d, %d, %d\n",rph.operation, rph.minor_num, rph.xfer_len);

		/* depending on the action coming in : can be open, write, close*/
		switch (rph.operation) {
		case RPROC_FOPEN:
			pr_info("Remote open file %d\n",rph.minor_num);
			_rpmsg_tgt_file_opened[rph.minor_num] ++;
			spin_unlock_irqrestore(&_cb_lock, _lock_flags);
			wake_up_interruptible(&_g_rdp->usr_wait_q);
			return;
			
		case RPROC_FWRITE:
			if (len != rph.xfer_len) {
				pr_err("Wierd length %d %d\n",len, rph.xfer_len);
			}
			if (!local) {
				pr_err("write operation from remote on unopend file %d\n",rph.minor_num);
				break;
			}
			if (!local->established) {
				pr_err("write operation from remote on unestablished channel %d\n",rph.minor_num);
				break;
			}
			spin_lock(&local->sync_lock);
			// not enough space
			if (kfifo_avail(&local->rx_kfifo) < len) {
				pr_err("not enough data on receive fifo dropped packet %d\n",rph.minor_num);
				local->block_flag = 1;
				spin_unlock(&local->sync_lock);
				spin_unlock_irqrestore(&_cb_lock,_lock_flags);
				wake_up_interruptible(&_g_rdp->usr_wait_q);
				return;
			}
			if (kfifo_in(&local->rx_kfifo, data, (unsigned int)len) != len) {
				pr_err("fifo put error %d\n",len);
			}
			
			/* Wake up any blocking contexts waiting for data */
			pr_info("got data waking up waiting processes %d %d %p\n",
				rph.minor_num,len,&local->block_flag);
			local->block_flag = 1;
			spin_unlock(&local->sync_lock);
			spin_unlock_irqrestore(&_cb_lock,_lock_flags);
			wake_up_interruptible(&_g_rdp->usr_wait_q);
			return;
			
		case RPROC_FCLOSE:

			if (!local) {
				pr_err("close operation from remote on unopend file %d\n",rph.minor_num);
				break;
			}
			if (!local->established) {
				pr_err("close operation from remote on unestablished channel %d\n",rph.minor_num);
			} 
			spin_lock(&local->sync_lock);
			_rpmsg_tgt_file_opened[rph.minor_num] --;
			local->established = 0;
			spin_unlock(&local->sync_lock);
			break;
			
		default:
			pr_err("Unexpected Header operation code received (%d) minor (%d)\n",
			       rph.operation, rph.minor_num); 
			break; // drop the rest of the packet
		}
		spin_unlock_irqrestore(&_cb_lock,_lock_flags);
	}
}

static const struct file_operations rpmsg_dev_fops = {
	.owner = THIS_MODULE,
	.read = rpmsg_dev_read,
	.write = rpmsg_dev_write,
	.open = rpmsg_dev_open,
	.unlocked_ioctl = rpmsg_dev_ioctl,
	.release = rpmsg_dev_release,
	.poll = rpmsg_dev_poll,
};

static int rpmsg_user_dev_rpmsg_drv_probe(struct rpmsg_channel *rpdev);

static void rpmsg_user_dev_rpmsg_drv_remove(struct rpmsg_channel *rpdev);

static struct rpmsg_device_id rpmsg_user_dev_drv_id_table[] = {
	{ .name = "rpmsg-openamp-demo-channel" },
	{},
};

static struct rpmsg_driver rpmsg_user_dev_drv = {
	.drv.name = "vsi_rpmsg_driver",
	.drv.owner = THIS_MODULE,
	.id_table = rpmsg_user_dev_drv_id_table,
	.probe = rpmsg_user_dev_rpmsg_drv_probe,
	.remove = rpmsg_user_dev_rpmsg_drv_remove,
	.callback = rpmsg_user_dev_rpmsg_drv_cb,
};
struct task_struct * kthread_heap;

static int rpmsg_user_dev_rpmsg_drv_probe(struct rpmsg_channel *rpdev)
{
	struct _rpmsg_dev_params *local;
	struct _rpmsg_proxy_header rph;
	int status;
	dev_info(&rpdev->dev, "%s", __func__);

	local = devm_kzalloc(&rpdev->dev, sizeof(struct _rpmsg_dev_params), GFP_KERNEL);
	if (!local) {
		pr_err("Failed to allocate memory for rpmsg user dev.\n");
		return -ENOMEM;
	}
	memset(local, 0x0, sizeof(struct _rpmsg_dev_params));

	local->_file_parms = (struct _rpmsg_file_params **)kmalloc(sizeof(struct _rpmsg_file_params *)*(rpmsg_max_files), GFP_KERNEL);
	memset(local->_file_parms,0,sizeof(struct _rpmsg_file_params *)*(rpmsg_max_files));

	_rpmsg_tgt_file_opened = (int *)kmalloc(sizeof(int)*(rpmsg_max_files),GFP_KERNEL);
	memset(_rpmsg_tgt_file_opened,0,sizeof(int)*(rpmsg_max_files));

	/* Initialize wait queue head that provides blocking rx for userspace */
	init_waitqueue_head(&local->usr_wait_q);

	mutex_init(&_g_access);
	mutex_init(&_g_write);
	spin_lock_init(&_cb_lock);

	local->rpmsg_chnl = rpdev;

	wt_block = 0;
	init_waitqueue_head(&write_thread_b);
	init_waitqueue_head(&write_thread_e);
	spin_lock_init(&wt_fifo_lock);
	status = kfifo_alloc(&write_thread_fifo, RPMSG_KFIFO_SIZE, GFP_KERNEL);
	if (status) {
		pr_err("Failed to run kfifo_alloc .");
		goto error1;
	} else {
		kfifo_reset(&write_thread_fifo);
	}
	if (kthread_heap = kthread_create(write_thread,(void*)rpdev,"vsi_write_thread")) {
		wake_up_process(kthread_heap);
	}
	
	dev_set_drvdata(&rpdev->dev, local);

	// register the drver to the kernel
	if ((status = register_chrdev(major, "vsi_rpmsg_driver", &rpmsg_dev_fops)) != 0) {
		pr_err("vsi_rpmsg_driver Cannot register driver %d",status);
		goto error1;
	}
	
	// initialize remote
	memcpy(local->g_tx_buff,RPMSG_INIT_MSG,strlen(RPMSG_INIT_MSG));
	while(mutex_lock_interruptible(&_g_access));
	if (rpmsg_sendto(local->rpmsg_chnl, local->g_tx_buff, strlen(RPMSG_INIT_MSG), rpdev->dst)) {
		pr_err("Failed to send init_msg to target 0x%x.", local->rpmsg_dst);
		goto error1;
	}
	dev_info(&rpdev->dev, "Sent init_msg of size to target 0x%x.", local->rpmsg_dst);
	dev_info(&rpdev->dev, "new channel: 0x%x -> 0x%x!\n", rpdev->src, rpdev->dst);

	/* the protocol message */
	rph.operation = RPROC_INIT;
	rph.minor_num = -1;
	rph.xfer_len = sizeof(rph);
	memcpy(local->g_tx_buff, &rph, sizeof(rph));
	if (rpmsg_sendto(local->rpmsg_chnl, local->g_tx_buff, sizeof(rph), rpdev->dst)) {
		pr_err("Failed to send init protocol to target 0x%x.", local->rpmsg_dst);
		goto error1;
	}
	goto out;
error1:
	mutex_unlock(&_g_access);
	kfree(local->_file_parms);
	kfree(_rpmsg_tgt_file_opened);
	return -ENODEV;
out:
	mutex_unlock(&_g_access);
	_g_rdp = local;
	return 0;
}

static void rpmsg_user_dev_rpmsg_drv_remove(struct rpmsg_channel *rpdev)
{
	struct _rpmsg_dev_params *local = dev_get_drvdata(&rpdev->dev);
	int i;

	dev_info(&rpdev->dev, "%s", __func__);
	
	/* free all the memoty for the files that are not closed */
	for (i =0 ; i < rpmsg_max_files; i++) {		
		if (local->_file_parms[i] == 0) continue; // closed
		kfifo_free(&local->_file_parms[i]->rx_kfifo);
		local->_file_parms[i] = 0;		
	}

	kfree(local->_file_parms);
	kfree(_rpmsg_tgt_file_opened);
	unregister_chrdev(major, "vsi_rpmsg_driver");
}

static int __init init(void)
{
	/* Create device class for this device */
	rpmsg_class = class_create(THIS_MODULE, "vsi_rpmsg_driver");

	if (rpmsg_class == NULL) {
		printk(KERN_ERR "Failed to register vsi_rpmsg_driver class");
		return -1;
	}
	pr_info("vsi_rpmsg_driver : initializing max message size %ld usable %ld\n",MAX_RPMSG_BUFF_SIZE,USEABLE_BUFF_SIZE);
	return register_rpmsg_driver(&rpmsg_user_dev_drv);
}

static void __exit fini(void)
{
	unregister_rpmsg_driver(&rpmsg_user_dev_drv);
	class_destroy(rpmsg_class);
}

module_init(init);
module_exit(fini);

MODULE_DESCRIPTION("SVI Driver to expose rpmsg to user space");
MODULE_LICENSE("GPL v2");
