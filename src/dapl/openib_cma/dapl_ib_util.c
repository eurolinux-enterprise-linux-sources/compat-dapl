/*
 * This Software is licensed under one of the following licenses:
 *
 * 1) under the terms of the "Common Public License 1.0" a copy of which is
 *    available from the Open Source Initiative, see
 *    http://www.opensource.org/licenses/cpl.php.
 *
 * 2) under the terms of the "The BSD License" a copy of which is
 *    available from the Open Source Initiative, see
 *    http://www.opensource.org/licenses/bsd-license.php.
 *
 * 3) under the terms of the "GNU General Public License (GPL) Version 2" a
 *    copy of which is available from the Open Source Initiative, see
 *    http://www.opensource.org/licenses/gpl-license.php.
 *
 * Licensee has the right to choose one of the above licenses.
 *
 * Redistributions of source code must retain the above copyright
 * notice and one of the license notices.
 *
 * Redistributions in binary form must reproduce both the above copyright
 * notice, one of the license notices in the documentation
 * and/or other materials provided with the distribution.
 */

/***************************************************************************
 *
 *   Module:		 uDAPL
 *
 *   Filename:		 dapl_ib_util.c
 *
 *   Author:		 Arlin Davis
 *
 *   Created:		 3/10/2005
 *
 *   Description: 
 *
 *   The uDAPL openib provider - init, open, close, utilities, work thread
 *
 ****************************************************************************
 *		   Source Control System Information
 *
 *    $Id: $
 *
 *	Copyright (c) 2005 Intel Corporation.  All rights reserved.
 *
 **************************************************************************/
#ifdef RCSID
static const char rcsid[] = "$Id:  $";
#endif

#include "dapl.h"
#include "dapl_adapter_util.h"
#include "dapl_ib_util.h"

#include <stdlib.h>
#include <netinet/tcp.h>
#include <sys/poll.h>
#include <fcntl.h>

#include <sys/ioctl.h>  /* for IOCTL's */
#include <sys/types.h>  /* for socket(2) and related bits and pieces */
#include <sys/socket.h> /* for socket(2) */
#include <net/if.h>     /* for struct ifreq */
#include <net/if_arp.h> /* for ARPHRD_INFINIBAND */
#include <arpa/inet.h>	/* for inet_ntoa */


int g_dapl_loopback_connection = 0;
int g_ib_pipe[2];
struct rdma_event_channel *g_cm_events = NULL;
ib_thread_state_t g_ib_thread_state = 0;
DAPL_OS_THREAD g_ib_thread;
DAPL_OS_LOCK g_hca_lock;
struct dapl_llist_entry	*g_hca_list;	

/* Get IP address using network device name */
static int getipaddr_netdev(char *name, char *addr, int addr_len)
{
    struct ifreq ifr;
    int skfd, ret, len;

    /* Fill in the structure */
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);
    ifr.ifr_hwaddr.sa_family = ARPHRD_INFINIBAND;

    /* Create a socket fd */
    skfd = socket(PF_INET, SOCK_STREAM, 0);
    ret = ioctl(skfd, SIOCGIFADDR, &ifr);
    if (ret)
	goto bail;

    switch (ifr.ifr_addr.sa_family) 
    {
#ifdef	AF_INET6
	case AF_INET6:
	    len = sizeof(struct sockaddr_in6);
	    break;
#endif
	case AF_INET:	
	default:	
	    len = sizeof(struct sockaddr);
	    break;
    }
      
    if (len <= addr_len)
	memcpy(addr, &ifr.ifr_addr, len);
    else
	ret = EINVAL;

bail:
    close(skfd);
    return ret;
}

/* Get IP address using network name, address, or device name */
static int getipaddr(char *name, char *addr, int len)
{
	struct addrinfo *res;
	
	/* assume netdev for first attempt, then network and address type */
	if (getipaddr_netdev(name,addr,len)) {
		if (getaddrinfo(name, NULL, NULL, &res)) {
			dapl_log(DAPL_DBG_TYPE_ERR,
		 		" open_hca: getaddr_netdev ERROR:"
		 		" %s. Is %s configured?\n",
		 		strerror(errno), name);
			return 1;
		} else {
			if (len >= res->ai_addrlen) 
				memcpy(addr, res->ai_addr, res->ai_addrlen);
			else {
				freeaddrinfo(res);
				return 1;
			}
			freeaddrinfo(res);
		}
	}

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL, 
		" getipaddr: family %d port %d addr %d.%d.%d.%d\n", 
		((struct sockaddr_in *)addr)->sin_family,
		((struct sockaddr_in *)addr)->sin_port,
		((struct sockaddr_in *)addr)->sin_addr.s_addr >> 0 & 0xff,
		((struct sockaddr_in *)addr)->sin_addr.s_addr >> 8 & 0xff,
		((struct sockaddr_in *)addr)->sin_addr.s_addr >> 16 & 0xff,
		((struct sockaddr_in *)addr)->sin_addr.s_addr >> 24 & 0xff);
	
	return 0;
}

/*
 * dapls_ib_init, dapls_ib_release
 *
 * Initialize Verb related items for device open
 *
 * Input:
 * 	none
 *
 * Output:
 *	none
 *
 * Returns:
 * 	0 success, -1 error
 *
 */
int32_t dapls_ib_init(void)
{	
	dapl_dbg_log(DAPL_DBG_TYPE_UTIL, " dapl_ib_init: \n" );

	/* initialize hca_list lock */
	dapl_os_lock_init(&g_hca_lock);
	
	/* initialize hca list for CQ events */
	dapl_llist_init_head(&g_hca_list);

	/* create pipe for waking up work thread */
	if (pipe(g_ib_pipe))
		return 1;

	return 0;
}

int32_t dapls_ib_release(void)
{
	dapl_dbg_log(DAPL_DBG_TYPE_UTIL, " dapl_ib_release: \n");
	dapli_ib_thread_destroy();
	if (g_cm_events != NULL)
		rdma_destroy_event_channel(g_cm_events);
	return 0;
}

/*
 * dapls_ib_open_hca
 *
 * Open HCA
 *
 * Input:
 *      *hca_name         pointer to provider device name
 *      *ib_hca_handle_p  pointer to provide HCA handle
 *
 * Output:
 *      none
 *
 * Return:
 *      DAT_SUCCESS
 *      dapl_convert_errno
 *
 */
DAT_RETURN dapls_ib_open_hca(IN IB_HCA_NAME hca_name, IN DAPL_HCA *hca_ptr)
{
	long opts;
	struct rdma_cm_id *cm_id;
	union ibv_gid *gid;
	int ret;
	DAT_RETURN dat_status;

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL, 
		     " open_hca: %s - %p\n", hca_name, hca_ptr);

	/* Setup the global cm event channel */
	dapl_os_lock(&g_hca_lock);
	if (g_cm_events == NULL) {
		g_cm_events = rdma_create_event_channel();
		if (g_cm_events == NULL)
			return DAT_INTERNAL_ERROR;
	}
	dapl_os_unlock(&g_hca_lock);

	dat_status = dapli_ib_thread_init();
	if (dat_status != DAT_SUCCESS)
		return dat_status;

	/* HCA name will be hostname or IP address */
	if (getipaddr((char*)hca_name,
		      (char*)&hca_ptr->hca_address, 
		      sizeof(DAT_SOCK_ADDR6)))
		return DAT_INVALID_ADDRESS;

	/* cm_id will bind local device/GID based on IP address */
	if (rdma_create_id(g_cm_events, &cm_id, (void*)hca_ptr, RDMA_PS_TCP)) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			 " open_hca: rdma_create_id ERR %s\n",
			 strerror(errno));
		return DAT_INTERNAL_ERROR;
	}

	ret = rdma_bind_addr(cm_id,
			     (struct sockaddr *)&hca_ptr->hca_address);
	if ((ret) || (cm_id->verbs == NULL)) {
                rdma_destroy_id(cm_id); 
		dapl_log(DAPL_DBG_TYPE_ERR,
			 " open_hca: rdma_bind ERR %s."
			 " Is %s configured?\n",
			 strerror(errno),hca_name);
		return DAT_INVALID_ADDRESS;
	}

	/* keep reference to IB device and cm_id */
	hca_ptr->ib_trans.cm_id = cm_id;
	hca_ptr->ib_hca_handle = cm_id->verbs;
	hca_ptr->port_num = cm_id->port_num;
	gid = &cm_id->route.addr.addr.ibaddr.sgid;

	dapl_dbg_log(
		DAPL_DBG_TYPE_UTIL,
		" open_hca: ctx=%p port=%d GID subnet %016llx id %016llx\n",
		cm_id->verbs,cm_id->port_num,
		(unsigned long long)bswap_64(gid->global.subnet_prefix),
		(unsigned long long)bswap_64(gid->global.interface_id));

	/* set inline max with env or default, get local lid and gid 0 */
	if (hca_ptr->ib_hca_handle->device->transport_type
					== IBV_TRANSPORT_IWARP)
		hca_ptr->ib_trans.max_inline_send =
			dapl_os_get_env_val("DAPL_MAX_INLINE",
					    INLINE_SEND_IWARP_DEFAULT);
	else
		hca_ptr->ib_trans.max_inline_send =
			dapl_os_get_env_val("DAPL_MAX_INLINE",
					    INLINE_SEND_IB_DEFAULT);

	/* set CM timer defaults */	
	hca_ptr->ib_trans.max_cm_timeout =
		dapl_os_get_env_val("DAPL_MAX_CM_RESPONSE_TIME", 
				    IB_CM_RESPONSE_TIMEOUT);
	hca_ptr->ib_trans.max_cm_retries = 
		dapl_os_get_env_val("DAPL_MAX_CM_RETRIES", 
				    IB_CM_RETRIES);

	/* EVD events without direct CQ channels, non-blocking */
	hca_ptr->ib_trans.ib_cq = 
		ibv_create_comp_channel(hca_ptr->ib_hca_handle);
	if (hca_ptr->ib_trans.ib_cq == NULL) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			 " open_hca: ibv_create_comp_channel ERR %s\n",
			 strerror(errno));
		goto bail;
	}

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
		     " open_hca: CQ channel created(fd=%d)\n",
		     hca_ptr->ib_trans.ib_cq->fd);

	opts = fcntl(hca_ptr->ib_trans.ib_cq->fd, F_GETFL); /* uCQ */
	if (opts < 0 || fcntl(hca_ptr->ib_trans.ib_cq->fd, 
			      F_SETFL, opts | O_NONBLOCK) < 0) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			 " open_hca: fcntl on ib_cq->fd %d ERR %d %s\n",
			 hca_ptr->ib_trans.ib_cq->fd, opts,
			strerror(errno));
		goto bail;
	}
	
	/* 
	 * Put new hca_transport on list for async and CQ event processing 
	 * Wakeup work thread to add to polling list
	 */
	dapl_llist_init_entry((DAPL_LLIST_ENTRY*)&hca_ptr->ib_trans.entry);
	dapl_os_lock( &g_hca_lock );
	dapl_llist_add_tail(&g_hca_list, 
			    (DAPL_LLIST_ENTRY*)&hca_ptr->ib_trans.entry, 
			    &hca_ptr->ib_trans.entry);
	if (write(g_ib_pipe[1], "w", sizeof "w") == -1)
		dapl_log(DAPL_DBG_TYPE_UTIL,
			 " open_hca: thread wakeup error = %s\n",
			 strerror(errno));
	dapl_os_unlock(&g_hca_lock);
	
  	dapl_dbg_log(
		DAPL_DBG_TYPE_UTIL, 
		" open_hca: %s, %s %d.%d.%d.%d INLINE_MAX=%d\n", hca_name, 
		((struct sockaddr_in *)
			&hca_ptr->hca_address)->sin_family == AF_INET ?  
			"AF_INET":"AF_INET6",
		((struct sockaddr_in *)
			&hca_ptr->hca_address)->sin_addr.s_addr >> 0 & 0xff,
		((struct sockaddr_in *)
			&hca_ptr->hca_address)->sin_addr.s_addr >> 8 & 0xff,
		((struct sockaddr_in *)
			&hca_ptr->hca_address)->sin_addr.s_addr >> 16 & 0xff,
		((struct sockaddr_in *)
			&hca_ptr->hca_address)->sin_addr.s_addr >> 24 & 0xff,
		hca_ptr->ib_trans.max_inline_send );

	hca_ptr->ib_trans.d_hca = hca_ptr;
	return DAT_SUCCESS;
bail:
	rdma_destroy_id(hca_ptr->ib_trans.cm_id); 
	hca_ptr->ib_hca_handle = IB_INVALID_HANDLE;
	return DAT_INTERNAL_ERROR;
}


/*
 * dapls_ib_close_hca
 *
 * Open HCA
 *
 * Input:
 *      DAPL_HCA   provide CA handle
 *
 * Output:
 *      none
 *
 * Return:
 *      DAT_SUCCESS
 *	dapl_convert_errno 
 *
 */
DAT_RETURN dapls_ib_close_hca(IN DAPL_HCA *hca_ptr)
{
	dapl_dbg_log(DAPL_DBG_TYPE_UTIL," close_hca: %p->%p\n",
		     hca_ptr,hca_ptr->ib_hca_handle);

	dapl_os_lock(&g_hca_lock);
	if (g_ib_thread_state != IB_THREAD_RUN) {
		dapl_os_unlock(&g_hca_lock);
		goto bail;
	}
	dapl_os_unlock(&g_hca_lock);

	/* 
	 * Remove hca from async and CQ event processing list
	 * Wakeup work thread to remove from polling list
	 */
	hca_ptr->ib_trans.destroy = 1;
	if (write(g_ib_pipe[1], "w", sizeof "w") == -1)
		dapl_log(DAPL_DBG_TYPE_UTIL,
			 " close_hca: thread wakeup error = %s\n",
			 strerror(errno));

	/* wait for thread to remove HCA references */
	while (hca_ptr->ib_trans.destroy != 2) {
		struct timespec	sleep, remain;
		sleep.tv_sec = 0;
		sleep.tv_nsec = 10000000; /* 10 ms */
		if (write(g_ib_pipe[1], "w", sizeof "w") == -1)
			dapl_log(DAPL_DBG_TYPE_UTIL,
				 " close_hca: thread wakeup error = %s\n",
				 strerror(errno));		
		dapl_dbg_log(DAPL_DBG_TYPE_UTIL, 
			     " ib_thread_destroy: wait on hca %p destroy\n");
		nanosleep (&sleep, &remain);
	}
bail:
	if (hca_ptr->ib_trans.ib_cq)
		ibv_destroy_comp_channel(hca_ptr->ib_trans.ib_cq);

	if (hca_ptr->ib_trans.ib_cq_empty) {
		struct ibv_comp_channel *channel;
		channel = hca_ptr->ib_trans.ib_cq_empty->channel;
		ibv_destroy_cq(hca_ptr->ib_trans.ib_cq_empty);
		ibv_destroy_comp_channel(channel);
	}

	if (hca_ptr->ib_hca_handle != IB_INVALID_HANDLE) {
		if (rdma_destroy_id(hca_ptr->ib_trans.cm_id))
			return (dapl_convert_errno(errno, "ib_close_device"));
		hca_ptr->ib_hca_handle = IB_INVALID_HANDLE;
	}

	return (DAT_SUCCESS);
}
  
/*
 * dapls_ib_query_hca
 *
 * Query the hca attribute
 *
 * Input:
 *	hca_handl		hca handle	
 *	ia_attr			attribute of the ia
 *	ep_attr			attribute of the ep
 *	ip_addr			ip address of DET NIC
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INVALID_HANDLE
 */

DAT_RETURN dapls_ib_query_hca(IN DAPL_HCA *hca_ptr,
			      OUT DAT_IA_ATTR *ia_attr,
			      OUT DAT_EP_ATTR *ep_attr,
			      OUT DAT_SOCK_ADDR6 *ip_addr)
{
	struct ibv_device_attr dev_attr;
	struct ibv_port_attr port_attr;

	if (hca_ptr->ib_hca_handle == NULL) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR," query_hca: BAD handle\n");
		return (DAT_INVALID_HANDLE);
	}

	/* local IP address of device, set during ia_open */
	if (ip_addr != NULL)
		memcpy(ip_addr, &hca_ptr->hca_address, sizeof(DAT_SOCK_ADDR6));
	
	if (ia_attr == NULL && ep_attr == NULL) 
		return DAT_SUCCESS;

	/* query verbs for this device and port attributes */	
	if (ibv_query_device(hca_ptr->ib_hca_handle, &dev_attr) ||
			     ibv_query_port(hca_ptr->ib_hca_handle, 
					    hca_ptr->port_num, &port_attr))
		return(dapl_convert_errno(errno,"ib_query_hca"));

	if (ia_attr != NULL) {
		(void) dapl_os_memzero(ia_attr, sizeof(*ia_attr));
		ia_attr->adapter_name[DAT_NAME_MAX_LENGTH - 1] = '\0';
		ia_attr->vendor_name[DAT_NAME_MAX_LENGTH - 1] = '\0';
		ia_attr->ia_address_ptr = 
			(DAT_IA_ADDRESS_PTR)&hca_ptr->hca_address;

		dapl_log(DAPL_DBG_TYPE_UTIL,
			 "dapl_query_hca: %s %s %s\n", hca_ptr->name,
			 ((struct sockaddr_in *)
			 ia_attr->ia_address_ptr)->sin_family == AF_INET ?
			 "AF_INET":"AF_INET6",
			 inet_ntoa(((struct sockaddr_in *)
				ia_attr->ia_address_ptr)->sin_addr));

		ia_attr->hardware_version_major = dev_attr.hw_ver;
		ia_attr->max_eps                  = dev_attr.max_qp;
		ia_attr->max_dto_per_ep           = dev_attr.max_qp_wr;
		ia_attr->max_rdma_read_in         = dev_attr.max_res_rd_atom;
		ia_attr->max_rdma_read_out        = dev_attr.max_qp_init_rd_atom;
		ia_attr->max_rdma_read_per_ep_in  = dev_attr.max_qp_rd_atom;
		ia_attr->max_rdma_read_per_ep_out = dev_attr.max_qp_init_rd_atom;
		ia_attr->max_rdma_read_per_ep_in_guaranteed  = DAT_TRUE;
		ia_attr->max_rdma_read_per_ep_out_guaranteed = DAT_TRUE;
		ia_attr->max_evds                 = dev_attr.max_cq;
		ia_attr->max_evd_qlen             = dev_attr.max_cqe;
		ia_attr->max_iov_segments_per_dto = dev_attr.max_sge;
		ia_attr->max_lmrs                 = dev_attr.max_mr;
		ia_attr->max_lmr_block_size       = dev_attr.max_mr_size;
		ia_attr->max_rmrs                 = dev_attr.max_mw;
		ia_attr->max_lmr_virtual_address  = dev_attr.max_mr_size;
		ia_attr->max_rmr_target_address   = dev_attr.max_mr_size;
		ia_attr->max_pzs                  = dev_attr.max_pd;
		ia_attr->max_mtu_size             = port_attr.max_msg_sz;
		ia_attr->max_rdma_size            = port_attr.max_msg_sz;
		ia_attr->num_transport_attr       = 0;
		ia_attr->transport_attr           = NULL;
		ia_attr->num_vendor_attr          = 0;
		ia_attr->vendor_attr              = NULL;
		/* iWARP spec. - 1 sge for RDMA reads */
		if (hca_ptr->ib_hca_handle->device->transport_type
							== IBV_TRANSPORT_IWARP)
			ia_attr->max_iov_segments_per_rdma_read = 1;
		else
			ia_attr->max_iov_segments_per_rdma_read = 
							dev_attr.max_sge;

		ia_attr->max_iov_segments_per_rdma_write = dev_attr.max_sge;
		/* save rd_atom for peer validation during connect requests */
		hca_ptr->ib_trans.max_rdma_rd_in  = dev_attr.max_qp_rd_atom;
		hca_ptr->ib_trans.max_rdma_rd_out = dev_attr.max_qp_init_rd_atom;

		dapl_log(DAPL_DBG_TYPE_UTIL,
			 "dapl_query_hca: (ver=%x) ep's %d ep_q %d"
			 " evd's %d evd_q %d\n",
			 ia_attr->hardware_version_major,
			 ia_attr->max_eps, ia_attr->max_dto_per_ep,
			 ia_attr->max_evds, ia_attr->max_evd_qlen );
		dapl_log(DAPL_DBG_TYPE_UTIL,
			 "dapl_query_hca: msg %llu rdma %llu iov's %d"
			 " lmr %d rmr %d rd_in,out %d,%d inline=%d\n",
			 ia_attr->max_mtu_size, ia_attr->max_rdma_size,
			 ia_attr->max_iov_segments_per_dto, ia_attr->max_lmrs,
			 ia_attr->max_rmrs, ia_attr->max_rdma_read_per_ep_in,
			 ia_attr->max_rdma_read_per_ep_out,
			 hca_ptr->ib_trans.max_inline_send);
	}
	
	if (ep_attr != NULL) {
		(void) dapl_os_memzero(ep_attr, sizeof(*ep_attr));
		ep_attr->max_mtu_size     = port_attr.max_msg_sz;
		ep_attr->max_rdma_size    = port_attr.max_msg_sz;
		ep_attr->max_recv_dtos    = dev_attr.max_qp_wr;
		ep_attr->max_request_dtos = dev_attr.max_qp_wr;
		ep_attr->max_recv_iov     = dev_attr.max_sge;
		ep_attr->max_request_iov  = dev_attr.max_sge;
		ep_attr->max_rdma_read_in = dev_attr.max_qp_rd_atom;
		ep_attr->max_rdma_read_out= dev_attr.max_qp_init_rd_atom;
		/* iWARP spec. - 1 sge for RDMA reads */
		if (hca_ptr->ib_hca_handle->device->transport_type
							== IBV_TRANSPORT_IWARP)
			ep_attr->max_rdma_read_iov = 1;
		else
			ep_attr->max_rdma_read_iov = dev_attr.max_sge;

		ep_attr->max_rdma_write_iov= dev_attr.max_sge;
		dapl_log(DAPL_DBG_TYPE_UTIL,
			 "dapl_query_hca: MAX msg %llu dto %d iov %d"
			 " rdma i%d,o%d\n",
			 ep_attr->max_mtu_size,
			 ep_attr->max_recv_dtos, ep_attr->max_recv_iov,
			 ep_attr->max_rdma_read_in, ep_attr->max_rdma_read_out);
	}
	return DAT_SUCCESS;
}

/*
 * dapls_ib_setup_async_callback
 *
 * Set up an asynchronous callbacks of various kinds
 *
 * Input:
 *	ia_handle		IA handle
 *	handler_type		type of handler to set up
 *	callback_handle 	handle param for completion callbacks
 *	callback		callback routine pointer
 *	context 		argument for callback routine
 *
 * Output:
 *	none
 *
 * Returns:
 *	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *	DAT_INVALID_PARAMETER
 *
 */
DAT_RETURN dapls_ib_setup_async_callback(IN  DAPL_IA *ia_ptr,
					 IN  DAPL_ASYNC_HANDLER_TYPE type,
					 IN  DAPL_EVD *evd_ptr,
					 IN  ib_async_handler_t callback,
					 IN  void *context)

{
	ib_hca_transport_t *hca_ptr;

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
		     " setup_async_cb: ia %p type %d hdl %p cb %p ctx %p\n",
		     ia_ptr, type, evd_ptr, callback, context);

	hca_ptr = &ia_ptr->hca_ptr->ib_trans;
	switch(type)
	{
	case DAPL_ASYNC_UNAFILIATED:
		hca_ptr->async_unafiliated = 
			(ib_async_handler_t)callback;
		hca_ptr->async_un_ctx = context;
		break;
	case DAPL_ASYNC_CQ_ERROR:
		hca_ptr->async_cq_error = 
			(ib_async_cq_handler_t)callback;
		break;
	case DAPL_ASYNC_CQ_COMPLETION:
		hca_ptr->async_cq = 
			(ib_async_dto_handler_t)callback;
		break;
	case DAPL_ASYNC_QP_ERROR:
		hca_ptr->async_qp_error = 
			(ib_async_qp_handler_t)callback;
		break;
	default:
		break;
	}
	return DAT_SUCCESS;
}

DAT_RETURN dapli_ib_thread_init(void)
{
	long opts;
	DAT_RETURN dat_status;

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
		     " ib_thread_init(%d)\n", getpid());

	dapl_os_lock(&g_hca_lock);
	if (g_ib_thread_state != IB_THREAD_INIT) {
		dapl_os_unlock(&g_hca_lock);
		return DAT_SUCCESS;
	}
		
	/* uCMA events non-blocking */
	opts = fcntl(g_cm_events->fd, F_GETFL); /* uCMA */
	if (opts < 0 || fcntl(g_cm_events->fd, 
			      F_SETFL, opts | O_NONBLOCK) < 0) {
		dapl_os_unlock(&g_hca_lock);
		return(dapl_convert_errno(errno, "create_thread ERR: cm_fd"));
	}

	g_ib_thread_state = IB_THREAD_CREATE;
	dapl_os_unlock(&g_hca_lock);

	/* create thread to process inbound connect request */
	dat_status = dapl_os_thread_create(dapli_thread, NULL, &g_ib_thread);
	if (dat_status != DAT_SUCCESS)
		return(dapl_convert_errno(errno,
					  "create_thread ERR:"
					  " check resource limits"));
	
	/* wait for thread to start */
	dapl_os_lock(&g_hca_lock);
	while (g_ib_thread_state != IB_THREAD_RUN) {
                struct timespec sleep, remain;
                sleep.tv_sec = 0;
                sleep.tv_nsec = 2000000; /* 2 ms */
                dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
                             " ib_thread_init: waiting for ib_thread\n");
		dapl_os_unlock(&g_hca_lock);
                nanosleep (&sleep, &remain);
		dapl_os_lock(&g_hca_lock);
        }
	dapl_os_unlock(&g_hca_lock);
	
	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
		     " ib_thread_init(%d) exit\n",getpid());

 	return DAT_SUCCESS;
}

void dapli_ib_thread_destroy(void)
{
	int retries = 10;

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
		     " ib_thread_destroy(%d)\n", getpid());
	/* 
	 * wait for async thread to terminate. 
	 * pthread_join would be the correct method
	 * but some applications have some issues
	 */
	 
	/* destroy ib_thread, wait for termination, if not already */
	dapl_os_lock(&g_hca_lock);
	if (g_ib_thread_state != IB_THREAD_RUN) 
		goto bail;
			
	g_ib_thread_state = IB_THREAD_CANCEL;
	if (write(g_ib_pipe[1], "w", sizeof "w") == -1)
		dapl_log(DAPL_DBG_TYPE_UTIL,
			 " destroy: thread wakeup error = %s\n",
			 strerror(errno));	
	while ((g_ib_thread_state != IB_THREAD_EXIT) && (retries--)) {
		struct timespec	sleep, remain;
		sleep.tv_sec = 0;
		sleep.tv_nsec = 2000000; /* 2 ms */
		dapl_dbg_log(DAPL_DBG_TYPE_UTIL, 
			" ib_thread_destroy: waiting for ib_thread\n");
		if (write(g_ib_pipe[1], "w", sizeof "w") == -1)
			dapl_log(DAPL_DBG_TYPE_UTIL,
				 " destroy: thread wakeup error = %s\n",
				 strerror(errno));	
		dapl_os_unlock( &g_hca_lock );
		nanosleep(&sleep, &remain);
		dapl_os_lock( &g_hca_lock );
	}

bail:
	dapl_os_unlock( &g_hca_lock );
	
	dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
		     " ib_thread_destroy(%d) exit\n",getpid());
}

void dapli_async_event_cb(struct _ib_hca_transport *hca)
{
	struct ibv_async_event	event;
	struct pollfd	async_fd = {
		.fd      = hca->cm_id->verbs->async_fd,
		.events  = POLLIN,
		.revents = 0
	};
	
	dapl_dbg_log(DAPL_DBG_TYPE_UTIL, " async_event(%p)\n",hca);

	if (hca->destroy)
		return;

	if ((poll(&async_fd, 1, 0)==1) &&
		(!ibv_get_async_event(hca->cm_id->verbs, &event))) {

		switch (event.event_type) {
		case	IBV_EVENT_CQ_ERR:
		{
			struct dapl_ep *evd_ptr = 
				event.element.cq->cq_context;

			dapl_log(
				DAPL_DBG_TYPE_ERR,
				"dapl async_event CQ (%p) ERR %d\n",
				evd_ptr, event.event_type);				
			
			/* report up if async callback still setup */
			if (hca->async_cq_error)
				hca->async_cq_error(hca->cm_id->verbs,
						    event.element.cq,	
						    &event,
						    (void*)evd_ptr);
			break;
		}
		case	IBV_EVENT_COMM_EST:
		{
			/* Received msgs on connected QP before RTU */
			dapl_log(
				DAPL_DBG_TYPE_UTIL,
				"dapl async_event COMM_EST(%p) "
				"rdata beat RTU\n",
				event.element.qp);	

			break;
		}
		case	IBV_EVENT_QP_FATAL:
		case	IBV_EVENT_QP_REQ_ERR:
		case	IBV_EVENT_QP_ACCESS_ERR:
		case	IBV_EVENT_QP_LAST_WQE_REACHED:
		case	IBV_EVENT_SRQ_ERR:
		case	IBV_EVENT_SRQ_LIMIT_REACHED:
		case	IBV_EVENT_SQ_DRAINED:
		{
			struct dapl_ep *ep_ptr = 
				event.element.qp->qp_context;

			dapl_log(
				DAPL_DBG_TYPE_ERR,
				"dapl async_event QP (%p) ERR %d\n",
				ep_ptr, event.event_type);	
			
			/* report up if async callback still setup */
			if (hca->async_qp_error)
				hca->async_qp_error(hca->cm_id->verbs,
						    ep_ptr->qp_handle,
						    &event,
						    (void*)ep_ptr);
			break;
		}
		case	IBV_EVENT_PATH_MIG:
		case	IBV_EVENT_PATH_MIG_ERR:
		case	IBV_EVENT_DEVICE_FATAL:
		case	IBV_EVENT_PORT_ACTIVE:
		case	IBV_EVENT_PORT_ERR:
		case	IBV_EVENT_LID_CHANGE:
		case	IBV_EVENT_PKEY_CHANGE:
		case	IBV_EVENT_SM_CHANGE:
		{
			dapl_log(DAPL_DBG_TYPE_WARN,
				     "dapl async_event: DEV ERR %d\n",
				     event.event_type);	

			/* report up if async callback still setup */
			if (hca->async_unafiliated)
				hca->async_unafiliated( 
						hca->cm_id->verbs,
						&event,
						hca->async_un_ctx);
			break;
		}
		case	IBV_EVENT_CLIENT_REREGISTER:
			/* no need to report this event this time */
			dapl_log (DAPL_DBG_TYPE_UTIL,
			          "dapl async_event: "
				  "IBV_EVENT_CLIENT_REREGISTER\n");
			break;

		default:
			dapl_log (DAPL_DBG_TYPE_WARN,
				     "dapl async_event: %d UNKNOWN\n", 
				     event.event_type);
			break;
		
		}
		ibv_ack_async_event(&event);
	}
}

/* work thread for uAT, uCM, CQ, and async events */
void dapli_thread(void *arg) 
{
	struct pollfd		 ufds[__FD_SETSIZE];
	struct _ib_hca_transport *uhca[__FD_SETSIZE]={NULL};
	struct _ib_hca_transport *hca;
	int			 ret,idx,fds;
	char			 rbuf[2];
	
	dapl_dbg_log (DAPL_DBG_TYPE_UTIL,
		      " ib_thread(%d,0x%x): ENTER: pipe %d ucma %d\n",
		      getpid(), g_ib_thread, g_ib_pipe[0], g_cm_events->fd);

 	/* Poll across pipe, CM, AT never changes */
	dapl_os_lock( &g_hca_lock );
	g_ib_thread_state = IB_THREAD_RUN;
		
	ufds[0].fd = g_ib_pipe[0];	/* pipe */
	ufds[0].events = POLLIN;
	ufds[1].fd = g_cm_events->fd;	/* uCMA */
	ufds[1].events = POLLIN;
	
	while (g_ib_thread_state == IB_THREAD_RUN) {
		
		/* build ufds after pipe and uCMA events */
		ufds[0].revents = 0;
		ufds[1].revents = 0;
		idx=1;

		/*  Walk HCA list and setup async and CQ events */
		if (!dapl_llist_is_empty(&g_hca_list))
			hca = dapl_llist_peek_head(&g_hca_list);
		else
			hca = NULL;

		while(hca) {
		
			/* uASYNC events */
			ufds[++idx].fd = hca->cm_id->verbs->async_fd;	
			ufds[idx].events = POLLIN;
			ufds[idx].revents = 0;
			uhca[idx] = hca;

			/* uCQ, non-direct events */
			ufds[++idx].fd = hca->ib_cq->fd; 
			ufds[idx].events = POLLIN;
			ufds[idx].revents = 0;
			uhca[idx] = hca;

			dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
				" ib_thread(%d) poll_fd: hca[%d]=%p, async=%d"
				" pipe=%d cm=%d cq=d\n",
				getpid(), hca, ufds[idx-1].fd, 
				ufds[0].fd, ufds[1].fd, ufds[idx].fd);

			hca = dapl_llist_next_entry(
				&g_hca_list,
				(DAPL_LLIST_ENTRY*)&hca->entry);
		}
		
		/* unlock, and setup poll */
		fds = idx+1;
		dapl_os_unlock(&g_hca_lock);
                ret = poll(ufds, fds, -1); 
		if (ret <= 0) {
			dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
				     " ib_thread(%d): ERR %s poll\n",
				     getpid(),strerror(errno));
                	dapl_os_lock(&g_hca_lock);
			continue;
		}

		dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
			" ib_thread(%d) poll_event: "
			" async=0x%x pipe=0x%x cm=0x%x cq=0x%x\n",
			getpid(), ufds[idx-1].revents, ufds[0].revents, 
			ufds[1].revents, ufds[idx].revents);

		/* uCMA events */
		if (ufds[1].revents == POLLIN)
			dapli_cma_event_cb();

		/* check and process CQ and ASYNC events, per device */
		for(idx=2;idx<fds;idx++) {
			if (ufds[idx].revents == POLLIN) {
				dapli_cq_event_cb(uhca[idx]);
				dapli_async_event_cb(uhca[idx]);
			}
		}

		/* check and process user events, PIPE */
		if (ufds[0].revents == POLLIN) {

                       if (read(g_ib_pipe[0], rbuf, 2) == -1)
				dapl_log(DAPL_DBG_TYPE_UTIL,
					 " ib_thread: pipe rd err= %s\n",
					 strerror(errno));
	
			/* cleanup any device on list marked for destroy */
			for(idx=3;idx<fds;idx++) {
				if(uhca[idx] && uhca[idx]->destroy == 1) {
					dapl_os_lock(&g_hca_lock);
					dapl_llist_remove_entry(
						&g_hca_list, 
						(DAPL_LLIST_ENTRY*)
							&uhca[idx]->entry);
					dapl_os_unlock(&g_hca_lock);
					uhca[idx]->destroy = 2;
				}
			}
		}
		dapl_os_lock(&g_hca_lock);
	}

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL," ib_thread(%d) EXIT\n",getpid());
	g_ib_thread_state = IB_THREAD_EXIT;
	dapl_os_unlock(&g_hca_lock);	
}

