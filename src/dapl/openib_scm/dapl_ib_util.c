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
 *   The uDAPL openib provider - init, open, close, utilities
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
#include <sys/utsname.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>	
#include <fcntl.h>

int g_dapl_loopback_connection = 0;
int g_scm_pipe[2];

enum ibv_mtu dapl_ib_mtu(int mtu)
{
	switch (mtu) {
	case 256:  return IBV_MTU_256;
	case 512:  return IBV_MTU_512;
	case 1024: return IBV_MTU_1024;
	case 2048: return IBV_MTU_2048;
	case 4096: return IBV_MTU_4096;
	default:   return IBV_MTU_1024;
	}
}

/* just get IP address for hostname */
DAT_RETURN getipaddr( char *addr, int addr_len)
{
	struct sockaddr_in	*ipv4_addr = (struct sockaddr_in*)addr;
	struct hostent		*h_ptr;
	struct utsname		ourname;

	if (uname(&ourname) < 0)  {
		 dapl_log(DAPL_DBG_TYPE_ERR, 
			  " open_hca: uname err=%s\n", strerror(errno));
		return DAT_INTERNAL_ERROR;
	}

	h_ptr = gethostbyname(ourname.nodename);
	if (h_ptr == NULL) {
		 dapl_log(DAPL_DBG_TYPE_ERR, 
			  " open_hca: gethostbyname err=%s\n", 
			  strerror(errno));
		return DAT_INTERNAL_ERROR;
	}

	if (h_ptr->h_addrtype == AF_INET) {
		int i;
		struct in_addr  **alist =
			(struct in_addr **)h_ptr->h_addr_list;

		*(uint32_t*)&ipv4_addr->sin_addr = 0;
		ipv4_addr->sin_family = AF_INET;
		
		/* Walk the list of addresses for host */
		for (i=0; alist[i] != NULL; i++) {
		       /* first non-loopback address */			
		       if (*(uint32_t*)alist[i] != htonl(0x7f000001)) {
                               dapl_os_memcpy(&ipv4_addr->sin_addr,
                                              h_ptr->h_addr_list[i],
                                              4);
                               break;
                       }
               }
               /* if no acceptable address found */
               if (*(uint32_t*)&ipv4_addr->sin_addr == 0)
			return DAT_INVALID_ADDRESS;
	} else 
		return DAT_INVALID_ADDRESS;

	return DAT_SUCCESS;
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
int32_t dapls_ib_init (void)
{	
	/* create pipe for waking up thread */
	if (pipe(g_scm_pipe))
		return 1;

	return 0;
}

int32_t dapls_ib_release (void)
{
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
DAT_RETURN dapls_ib_open_hca (
        IN   IB_HCA_NAME	hca_name,
        IN   DAPL_HCA		*hca_ptr)
{
	struct ibv_device **dev_list;
	int		i;
	DAT_RETURN	dat_status = DAT_SUCCESS;

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL, 
		      " open_hca: %s - %p\n", hca_name, hca_ptr );

	/* Get list of all IB devices, find match, open */
	dev_list = ibv_get_device_list(NULL);
	if (!dev_list) {
		dapl_dbg_log (DAPL_DBG_TYPE_ERR,
			      " open_hca: ibv_get_device_list() failed\n",
			      hca_name);
		return DAT_INTERNAL_ERROR;
	}

	for (i = 0; dev_list[i]; ++i) {
		hca_ptr->ib_trans.ib_dev = dev_list[i];
		if (!strcmp(ibv_get_device_name(hca_ptr->ib_trans.ib_dev),
			    hca_name))
			goto found;
	}

	dapl_log(DAPL_DBG_TYPE_ERR,
		 " open_hca: device %s not found\n",
		 hca_name);
	goto err;

found:
	dapl_dbg_log(DAPL_DBG_TYPE_UTIL," open_hca: Found dev %s %016llx\n", 
		     ibv_get_device_name(hca_ptr->ib_trans.ib_dev),
		     (unsigned long long)
		     bswap_64(ibv_get_device_guid(hca_ptr->ib_trans.ib_dev)));

	hca_ptr->ib_hca_handle = ibv_open_device(hca_ptr->ib_trans.ib_dev);
	if (!hca_ptr->ib_hca_handle) {
		 dapl_log(DAPL_DBG_TYPE_ERR, 
			  " open_hca: dev open failed for %s, err=%s\n", 
			  ibv_get_device_name(hca_ptr->ib_trans.ib_dev),
			  strerror(errno));
		 goto err;
	}

	/* set RC tunables via enviroment or default */
	hca_ptr->ib_trans.max_inline_send = 
		dapl_os_get_env_val("DAPL_MAX_INLINE", INLINE_SEND_DEFAULT);
	hca_ptr->ib_trans.ack_retry = 
		dapl_os_get_env_val("DAPL_ACK_RETRY", SCM_ACK_RETRY);
	hca_ptr->ib_trans.ack_timer =
		dapl_os_get_env_val("DAPL_ACK_TIMER", SCM_ACK_TIMER);
	hca_ptr->ib_trans.rnr_retry = 
		dapl_os_get_env_val("DAPL_RNR_RETRY", SCM_RNR_RETRY);
	hca_ptr->ib_trans.rnr_timer = 
		dapl_os_get_env_val("DAPL_RNR_TIMER", SCM_RNR_TIMER);
	hca_ptr->ib_trans.global = 
		dapl_os_get_env_val("DAPL_GLOBAL_ROUTING", SCM_GLOBAL);
	hca_ptr->ib_trans.hop_limit = 
		dapl_os_get_env_val("DAPL_HOP_LIMIT", SCM_HOP_LIMIT);
	hca_ptr->ib_trans.tclass = 
		dapl_os_get_env_val("DAPL_TCLASS", SCM_TCLASS);
	hca_ptr->ib_trans.mtu = 
		dapl_ib_mtu(dapl_os_get_env_val("DAPL_IB_MTU", SCM_IB_MTU));

#ifndef CQ_WAIT_OBJECT
	/* initialize cq_lock */
	dat_status = dapl_os_lock_init(&hca_ptr->ib_trans.cq_lock);
	if (dat_status != DAT_SUCCESS) {
		dapl_log(DAPL_DBG_TYPE_ERR, 
			 " open_hca: failed to init cq_lock\n");
		goto bail;
	}

	/* EVD events without direct CQ channels, non-blocking */
	hca_ptr->ib_trans.ib_cq = 
		ibv_create_comp_channel(hca_ptr->ib_hca_handle);
	if (hca_ptr->ib_trans.ib_cq == NULL) {
		dapl_log(DAPL_DBG_TYPE_ERR, 
			 " open_hca: ibv_create_comp_channel ERR %s\n",
			 strerror(errno));
		goto bail;
	}

	opts = fcntl(hca_ptr->ib_trans.ib_cq->fd, F_GETFL); /* uCQ */
	if (opts < 0 || fcntl(hca_ptr->ib_trans.ib_cq->fd, 
			      F_SETFL, opts | O_NONBLOCK) < 0) {
		dapl_log(DAPL_DBG_TYPE_ERR, 
			 " open_hca: fcntl on ib_cq->fd %d ERR %d %s\n", 
			 hca_ptr->ib_trans.ib_cq->fd, opts,
			 strerror(errno));
		goto bail;
	}

	if (dapli_cq_thread_init(hca_ptr)) {
                dapl_log(DAPL_DBG_TYPE_ERR,
                         " open_hca: cq_thread_init failed for %s\n",
                         ibv_get_device_name(hca_ptr->ib_trans.ib_dev));
                goto bail;
        }
#endif
	/* initialize cr_list lock */
	dat_status = dapl_os_lock_init(&hca_ptr->ib_trans.lock);
	if (dat_status != DAT_SUCCESS) {
		dapl_log(DAPL_DBG_TYPE_ERR, 
			 " open_hca: failed to init cr_list lock\n");
		goto bail;
	}

	/* initialize CM list for listens on this HCA */
	dapl_llist_init_head(&hca_ptr->ib_trans.list);

	/* create thread to process inbound connect request */
	hca_ptr->ib_trans.cr_state = IB_THREAD_INIT;
	dat_status = dapl_os_thread_create(cr_thread, 
					   (void*)hca_ptr, 
					   &hca_ptr->ib_trans.thread );
	if (dat_status != DAT_SUCCESS) {
		dapl_log(DAPL_DBG_TYPE_ERR, 
			 " open_hca: failed to create thread\n");
		goto bail;
	}
	
	/* wait for thread */
	while (hca_ptr->ib_trans.cr_state != IB_THREAD_RUN) {
		struct timespec	sleep, remain;
		sleep.tv_sec = 0;
		sleep.tv_nsec = 2000000; /* 2 ms */
		dapl_dbg_log(DAPL_DBG_TYPE_UTIL, 
			     " open_hca: waiting for cr_thread\n");
		nanosleep (&sleep, &remain);
	}

	/* get the IP address of the device */
	dat_status = getipaddr((char*)&hca_ptr->hca_address, 
				sizeof(DAT_SOCK_ADDR6));
	
	dapl_dbg_log(DAPL_DBG_TYPE_UTIL, 
		     " open_hca: devname %s, port %d, hostname_IP %s\n",  
		     ibv_get_device_name(hca_ptr->ib_trans.ib_dev), 
		     hca_ptr->port_num,
		     inet_ntoa(((struct sockaddr_in *)
				&hca_ptr->hca_address)->sin_addr));
		
	ibv_free_device_list(dev_list);
	return dat_status;

bail:
	ibv_close_device(hca_ptr->ib_hca_handle); 
	hca_ptr->ib_hca_handle = IB_INVALID_HANDLE;
err:
	ibv_free_device_list(dev_list);
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
DAT_RETURN dapls_ib_close_hca (	IN   DAPL_HCA	*hca_ptr )
{
	dapl_dbg_log (DAPL_DBG_TYPE_UTIL," close_hca: %p\n",hca_ptr);

#ifndef CQ_WAIT_OBJECT
	dapli_cq_thread_destroy(hca_ptr);
	dapl_os_lock_destroy(&hca_ptr->ib_trans.cq_lock);
#endif

	if (hca_ptr->ib_hca_handle != IB_INVALID_HANDLE) {
		if (ibv_close_device(hca_ptr->ib_hca_handle)) 
			return(dapl_convert_errno(errno,"ib_close_device"));
		hca_ptr->ib_hca_handle = IB_INVALID_HANDLE;
	}

	/* destroy cr_thread and lock */
	hca_ptr->ib_trans.cr_state = IB_THREAD_CANCEL;
	if (write(g_scm_pipe[1], "w", sizeof "w") == -1)
		dapl_log(DAPL_DBG_TYPE_UTIL,
			 " close_hca: thread wakeup error = %s\n",
			 strerror(errno));
	while (hca_ptr->ib_trans.cr_state != IB_THREAD_EXIT) {
		struct timespec	sleep, remain;
		sleep.tv_sec = 0;
		sleep.tv_nsec = 2000000; /* 2 ms */
		if (write(g_scm_pipe[1], "w", sizeof "w") == -1)
			dapl_log(DAPL_DBG_TYPE_UTIL,
				 " close_hca: thread wakeup error = %s\n",
				 strerror(errno));
		dapl_dbg_log(DAPL_DBG_TYPE_UTIL, 
			     " close_hca: waiting for cr_thread\n");
		nanosleep (&sleep, &remain);
	}
	dapl_os_lock_destroy(&hca_ptr->ib_trans.lock);

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

DAT_RETURN dapls_ib_query_hca (
	IN  DAPL_HCA                       *hca_ptr,
	OUT DAT_IA_ATTR                    *ia_attr,
	OUT DAT_EP_ATTR                    *ep_attr,
	OUT DAT_SOCK_ADDR6                 *ip_addr)
{
	struct ibv_device_attr	dev_attr;
	struct ibv_port_attr	port_attr;

	if (hca_ptr->ib_hca_handle == NULL) {
		dapl_dbg_log (DAPL_DBG_TYPE_ERR," query_hca: BAD handle\n");
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
		ia_attr->ia_address_ptr = (DAT_IA_ADDRESS_PTR)&hca_ptr->hca_address;

		dapl_dbg_log(DAPL_DBG_TYPE_UTIL, 
			     " query_hca: %s %s \n", 
			     ibv_get_device_name(hca_ptr->ib_trans.ib_dev),
			     inet_ntoa(((struct sockaddr_in *)
					&hca_ptr->hca_address)->sin_addr));
		
		ia_attr->hardware_version_major   = dev_attr.hw_ver;
		/* ia_attr->hardware_version_minor   = dev_attr.fw_ver; */
		ia_attr->max_eps                  = dev_attr.max_qp;
		ia_attr->max_dto_per_ep           = dev_attr.max_qp_wr;
		ia_attr->max_rdma_read_in         = dev_attr.max_qp_rd_atom;
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
		ia_attr->max_iov_segments_per_rdma_read = dev_attr.max_sge;
		ia_attr->max_iov_segments_per_rdma_write = dev_attr.max_sge;
		ia_attr->num_transport_attr       = 0;
		ia_attr->transport_attr           = NULL;
		ia_attr->num_vendor_attr          = 0;
		ia_attr->vendor_attr              = NULL;
		hca_ptr->ib_trans.ack_timer	  = DAPL_MAX(dev_attr.local_ca_ack_delay,
							     hca_ptr->ib_trans.ack_timer);
		hca_ptr->ib_trans.mtu		  = DAPL_MIN(port_attr.active_mtu,
							     hca_ptr->ib_trans.mtu);
#ifdef DEFINE_ATTR_LINK_LAYER
                if (port_attr.link_layer == IBV_LINK_LAYER_ETHERNET)
                        hca_ptr->ib_trans.global = 1;

                dapl_log(DAPL_DBG_TYPE_UTIL,
                         " query_hca: port.link_layer = 0x%x\n",
                         port_attr.link_layer);
#endif
		dapl_dbg_log (DAPL_DBG_TYPE_UTIL, 
			" query_hca: (%x.%x) ep %d ep_q %d evd %d evd_q %d mtu %d\n", 
			ia_attr->hardware_version_major,
			ia_attr->hardware_version_minor,
			ia_attr->max_eps, ia_attr->max_dto_per_ep,
			ia_attr->max_evds, ia_attr->max_evd_qlen,
			128 << hca_ptr->ib_trans.mtu);
		dapl_dbg_log (DAPL_DBG_TYPE_UTIL, 
			" query_hca: msg %llu rdma %llu iov %d lmr %d rmr %d ack_time %d\n", 
			ia_attr->max_mtu_size, ia_attr->max_rdma_size,
			ia_attr->max_iov_segments_per_dto, ia_attr->max_lmrs, 
			ia_attr->max_rmrs,hca_ptr->ib_trans.ack_timer );
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
		ep_attr->max_rdma_read_iov= dev_attr.max_sge;
		ep_attr->max_rdma_write_iov= dev_attr.max_sge;
		dapl_dbg_log (DAPL_DBG_TYPE_UTIL, 
			" query_hca: MAX msg %llu dto %d iov %d rdma i%d,o%d\n", 
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
DAT_RETURN dapls_ib_setup_async_callback (
	IN  DAPL_IA			*ia_ptr,
	IN  DAPL_ASYNC_HANDLER_TYPE	handler_type,
	IN  DAPL_EVD			*evd_ptr,
	IN  ib_async_handler_t		callback,
	IN  void			*context )

{
    ib_hca_transport_t	*hca_ptr;

    dapl_dbg_log (DAPL_DBG_TYPE_UTIL,
		  " setup_async_cb: ia %p type %d handle %p cb %p ctx %p\n",
		  ia_ptr, handler_type, evd_ptr, callback, context);

    hca_ptr = &ia_ptr->hca_ptr->ib_trans;
    switch(handler_type)
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

