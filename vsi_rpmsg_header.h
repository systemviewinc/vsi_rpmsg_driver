#ifndef _VSI_RPMSG_HEADER
#define _VSI_RPMSG_HEADER

/* Data structures */
typedef enum {
	RPROC_INIT  = 1,
	RPROC_FOPEN ,
	RPROC_FREAD ,
	RPROC_FWRITE,
	RPROC_FCLOSE
} rproc_ops;

struct _rpmsg_proxy_header {
	int 	operation;
	int	minor_num;
	int	xfer_len;
	int	reserved;
};

// note this is defined in the virtio kernel 
// DO NOT CHANGE TO LARGER VALUE
//#define MAX_RPMSG_BUFF_SIZE		(512-sizeof(struct rpmsg_hdr))
#define MAX_RPMSG_BUFF_SIZE		(512-20)

#define IOCTL_CMD_GET_KFIFO_SIZE	1
#define IOCTL_CMD_GET_AVAIL_DATA_SIZE	2
#define IOCTL_CMD_GET_FREE_BUFF_SIZE	3

#define RPMSG_KFIFO_SIZE		(2048)

#endif
