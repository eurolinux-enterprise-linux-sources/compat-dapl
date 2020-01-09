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
 *   Filename:		 dapl_ib_cm.c
 *
 *   Author:		 Arlin Davis
 *
 *   Created:		 3/10/2005
 *
 *   Description: 
 *
 *   The uDAPL openib provider - connection management
 *
 ****************************************************************************
 *		   Source Control System Information
 *
 *    $Id: $
 *
 *	Copyright (c) 2005 Intel Corporation.  All rights reserved.
 *
 **************************************************************************/

#include "dapl.h"
#include "dapl_adapter_util.h"
#include "dapl_evd_util.h"
#include "dapl_cr_util.h"
#include "dapl_name_service.h"
#include "dapl_ib_util.h"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <byteswap.h>
#include <poll.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline uint64_t cpu_to_be64(uint64_t x) {return bswap_64(x);}
#elif __BYTE_ORDER == __BIG_ENDIAN
static inline uint64_t cpu_to_be64(uint64_t x) {return x;}
#endif

extern int g_scm_pipe[2];

static struct ib_cm_handle *dapli_cm_create(void)
{ 
	struct ib_cm_handle *cm_ptr;

	/* Allocate CM, init lock, and initialize */
	if ((cm_ptr = dapl_os_alloc(sizeof(*cm_ptr))) == NULL) 
		return NULL;

        if (dapl_os_lock_init(&cm_ptr->lock)) 
		goto bail;

	(void)dapl_os_memzero(cm_ptr, sizeof(*cm_ptr));
	cm_ptr->dst.ver = htons(DSCM_VER);
	cm_ptr->socket = -1;
	return cm_ptr;
bail:
	dapl_os_free(cm_ptr, sizeof(*cm_ptr));
	return NULL;
}

/* mark for destroy, remove all references, schedule cleanup */
static void dapli_cm_destroy(struct ib_cm_handle *cm_ptr)
{
	dapl_dbg_log(DAPL_DBG_TYPE_CM, 
		     " cm_destroy: cm %p ep %p\n", cm_ptr,cm_ptr->ep);
	
	/* cleanup, never made it to work queue */
	if (cm_ptr->state == SCM_INIT) {
		if (cm_ptr->socket >= 0)  
			close(cm_ptr->socket);
		dapl_os_free(cm_ptr, sizeof(*cm_ptr));
		return;
	}

	dapl_os_lock(&cm_ptr->lock);
	cm_ptr->state = SCM_DESTROY;
	if (cm_ptr->ep) 
		cm_ptr->ep->cm_handle = IB_INVALID_HANDLE;

	/* close socket if still active */
	if (cm_ptr->socket >= 0) {
		close(cm_ptr->socket);
		cm_ptr->socket = -1;
	}
	dapl_os_unlock(&cm_ptr->lock);

	/* wakeup work thread */
	if (write(g_scm_pipe[1], "w", sizeof "w") == -1)
		dapl_log(DAPL_DBG_TYPE_UTIL,
			 " cm_destroy: thread wakeup error = %s\n",
			 strerror(errno));
}

/* queue socket for processing CM work */
static void dapli_cm_queue(struct ib_cm_handle *cm_ptr)
{
	/* add to work queue for cr thread processing */
	dapl_llist_init_entry((DAPL_LLIST_ENTRY*)&cm_ptr->entry);
	dapl_os_lock(&cm_ptr->hca->ib_trans.lock);
	dapl_llist_add_tail(&cm_ptr->hca->ib_trans.list, 
			    (DAPL_LLIST_ENTRY*)&cm_ptr->entry, cm_ptr);
	dapl_os_unlock(&cm_ptr->hca->ib_trans.lock);

        /* wakeup CM work thread */
	if (write(g_scm_pipe[1], "w", sizeof "w") == -1)
		dapl_log(DAPL_DBG_TYPE_UTIL,
			 " cm_queue: thread wakeup error = %s\n",
			 strerror(errno));
}

static uint16_t dapli_get_lid(IN struct ibv_context *ctx, IN uint8_t port)
{
	struct ibv_port_attr port_attr;

	if(ibv_query_port(ctx, port,&port_attr))
		return(0xffff);
	else
		return(port_attr.lid);
}

/*
 * ACTIVE/PASSIVE: called from CR thread or consumer via ep_disconnect
 */
static DAT_RETURN 
dapli_socket_disconnect(ib_cm_handle_t	cm_ptr)
{
	DAPL_EP	*ep_ptr = cm_ptr->ep;
	DAT_UINT32 disc_data = htonl(0xdead);

	if (ep_ptr == NULL)
		return DAT_SUCCESS;
	
	dapl_os_lock(&cm_ptr->lock);
	if ((cm_ptr->state == SCM_INIT) ||
	    (cm_ptr->state == SCM_DISCONNECTED) ||
	    (cm_ptr->state == SCM_DESTROY)) {
		dapl_os_unlock(&cm_ptr->lock);
		return DAT_SUCCESS;
	} else {
		/* send disc date, close socket, schedule destroy */
		if (cm_ptr->socket >= 0) { 
			if (write(cm_ptr->socket,
				  &disc_data, sizeof(disc_data)) == -1)
				dapl_log(DAPL_DBG_TYPE_WARN,
					 " cm_disc: write error = %s\n",
					 strerror(errno));
			close(cm_ptr->socket);
			cm_ptr->socket = -1;
		}
		cm_ptr->state = SCM_DISCONNECTED;
	}
	dapl_os_unlock(&cm_ptr->lock);

	if (ep_ptr->cr_ptr) {
		dapls_cr_callback(cm_ptr,
				  IB_CME_DISCONNECTED,
				  NULL,
				  ((DAPL_CR *)ep_ptr->cr_ptr)->sp_ptr);
	} else {
		dapl_evd_connection_callback(ep_ptr->cm_handle,
					     IB_CME_DISCONNECTED,
					     NULL,
					     ep_ptr);
	}	

	/* scheduled destroy via disconnect clean in callback */
	return DAT_SUCCESS;
}

/*
 * ACTIVE: socket connected, send QP information to peer 
 */
void
dapli_socket_connected(ib_cm_handle_t cm_ptr, int err)
{
	int		len, opt = 1;
	struct iovec    iovec[2];
	struct dapl_ep	*ep_ptr = cm_ptr->ep;

	if (err) {
		dapl_log(DAPL_DBG_TYPE_ERR, 
			 " CONN_PENDING: socket ERR %s -> %s\n", 
			 strerror(err),
			 inet_ntoa(((struct sockaddr_in *)
		           ep_ptr->param.remote_ia_address_ptr)->sin_addr)); 
		goto bail;
	}
	dapl_dbg_log(DAPL_DBG_TYPE_EP,
		     " socket connected, write QP and private data\n"); 

	/* no delay for small packets */
	setsockopt(cm_ptr->socket,IPPROTO_TCP,TCP_NODELAY,&opt,sizeof(opt));

	/* send qp info and pdata to remote peer */
	iovec[0].iov_base = &cm_ptr->dst;
	iovec[0].iov_len  = sizeof(ib_qp_cm_t);
	if (cm_ptr->dst.p_size) {
		iovec[1].iov_base = cm_ptr->p_data;
		iovec[1].iov_len  = ntohl(cm_ptr->dst.p_size);
	}

	len = writev(cm_ptr->socket, iovec, (cm_ptr->dst.p_size ? 2:1));
    	if (len != (ntohl(cm_ptr->dst.p_size) + sizeof(ib_qp_cm_t))) {
		dapl_log(DAPL_DBG_TYPE_ERR, 
			 " CONN_PENDING write: ERR %s, wcnt=%d -> %s\n",
			 strerror(errno), len,
			 inet_ntoa(((struct sockaddr_in *)
		           ep_ptr->param.remote_ia_address_ptr)->sin_addr)); 
		goto bail;
	}
	dapl_dbg_log(DAPL_DBG_TYPE_CM, 
		     " connected: sending SRC port=0x%x lid=0x%x,"
		     " qpn=0x%x, psize=%d\n",
		     ntohs(cm_ptr->dst.port), ntohs(cm_ptr->dst.lid), 
		     ntohl(cm_ptr->dst.qpn), ntohl(cm_ptr->dst.p_size)); 
        dapl_dbg_log(DAPL_DBG_TYPE_CM,
                     " connected: sending SRC GID subnet %016llx id %016llx\n",
                     (unsigned long long) 
			cpu_to_be64(cm_ptr->dst.gid.global.subnet_prefix),
                     (unsigned long long) 
			cpu_to_be64(cm_ptr->dst.gid.global.interface_id));

	/* queue up to work thread to avoid blocking consumer */
	cm_ptr->state = SCM_RTU_PENDING;
	return;
bail:
	/* close socket, free cm structure and post error event */
	dapli_cm_destroy(cm_ptr);
	dapl_evd_connection_callback(NULL, IB_CME_LOCAL_FAILURE, NULL, ep_ptr);
}


/*
 * ACTIVE: Create socket, connect, defer exchange QP information to CR thread
 * to avoid blocking. 
 */
DAT_RETURN 
dapli_socket_connect(DAPL_EP		*ep_ptr,
	   	     DAT_IA_ADDRESS_PTR	r_addr,
		     DAT_CONN_QUAL	r_qual,
		     DAT_COUNT		p_size,
		     DAT_PVOID		p_data)
{
	ib_cm_handle_t cm_ptr;
	int		ret;
	DAPL_IA		*ia_ptr = ep_ptr->header.owner_ia;

	dapl_dbg_log(DAPL_DBG_TYPE_EP, " connect: r_qual %d p_size=%d\n", 
		     r_qual,p_size);
			
	cm_ptr = dapli_cm_create();
	if (cm_ptr == NULL)
		return DAT_INSUFFICIENT_RESOURCES;

	/* create, connect, sockopt, and exchange QP information */
	if ((cm_ptr->socket = socket(AF_INET,SOCK_STREAM,0)) < 0 ) {
		dapl_os_free( cm_ptr, sizeof( *cm_ptr ) );
		return DAT_INSUFFICIENT_RESOURCES;
	}

	/* non-blocking */
	ret = fcntl(cm_ptr->socket, F_GETFL); 
        if (ret < 0 || fcntl(cm_ptr->socket,
                              F_SETFL, ret | O_NONBLOCK) < 0) {
                dapl_log(DAPL_DBG_TYPE_ERR,
                         " socket connect: fcntl on socket %d ERR %d %s\n",
                         cm_ptr->socket, ret,
                         strerror(errno));
                goto bail;
        }

	((struct sockaddr_in*)r_addr)->sin_port = htons(r_qual);
	ret = connect(cm_ptr->socket, r_addr, sizeof(*r_addr));
	if (ret && errno != EINPROGRESS) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			 " socket connect ERROR: %s -> %s r_qual %d\n",
			 strerror(errno), 
		     	 inet_ntoa(((struct sockaddr_in *)r_addr)->sin_addr),
			 (unsigned int)r_qual);
		dapli_cm_destroy(cm_ptr);
		return DAT_INVALID_ADDRESS;
	} 

	/* Send QP info, IA address, and private data */
	cm_ptr->dst.qpn = htonl(ep_ptr->qp_handle->qp_num);
	cm_ptr->dst.port = htons(ia_ptr->hca_ptr->port_num);
	cm_ptr->dst.lid = 
		htons(dapli_get_lid(ia_ptr->hca_ptr->ib_hca_handle, 
				    (uint8_t)ia_ptr->hca_ptr->port_num));
	if (cm_ptr->dst.lid == 0xffff) {
		dapl_log(DAPL_DBG_TYPE_ERR, 
			 " CONNECT: query LID ERR %s -> %s\n",
			 strerror(errno), 
			 inet_ntoa(((struct sockaddr_in *)r_addr)->sin_addr));
		goto bail;
	}

        /* in network order */
        if (ibv_query_gid(ia_ptr->hca_ptr->ib_hca_handle,
				    (uint8_t)ia_ptr->hca_ptr->port_num,
				    0, &cm_ptr->dst.gid)) {
		dapl_log(DAPL_DBG_TYPE_ERR, 
			 " CONNECT: query GID ERR %s -> %s\n",
			 strerror(errno), 
			 inet_ntoa(((struct sockaddr_in *)r_addr)->sin_addr));
		goto bail;
	}

	/* save references */
	cm_ptr->hca = ia_ptr->hca_ptr;
	cm_ptr->ep = ep_ptr;
	cm_ptr->dst.ia_address = ia_ptr->hca_ptr->hca_address;
	if (p_size) {
		cm_ptr->dst.p_size = htonl(p_size);
		dapl_os_memcpy(cm_ptr->p_data, p_data, p_size);
	}

	/* connected or pending, either way results via async event */
	if (ret == 0) 
		dapli_socket_connected(cm_ptr,0);
	else 
		cm_ptr->state = SCM_CONN_PENDING;
	
	dapl_dbg_log(DAPL_DBG_TYPE_EP,
	             " connect: socket %d to %s r_qual %d pending\n",
		     cm_ptr->socket,
		     inet_ntoa(((struct sockaddr_in *)r_addr)->sin_addr),
		     (unsigned int)r_qual);
			
	dapli_cm_queue(cm_ptr);
	return DAT_SUCCESS;
bail:
	dapl_log(DAPL_DBG_TYPE_ERR,
		 " socket connect ERROR: %s query lid(0x%x)/gid"
		 " -> %s r_qual %d\n",
		 strerror(errno), ntohs(cm_ptr->dst.lid), 
		 inet_ntoa(((struct sockaddr_in *)r_addr)->sin_addr),
		 (unsigned int)r_qual);

	/* close socket, free cm structure */
	dapli_cm_destroy(cm_ptr);
	return DAT_INTERNAL_ERROR;
}
	

/*
 * ACTIVE: exchange QP information, called from CR thread
 */
void 
dapli_socket_connect_rtu(ib_cm_handle_t	cm_ptr)
{
	DAPL_EP		*ep_ptr = cm_ptr->ep;
	int		len;
	struct iovec    iovec[2];
	short		rtu_data = htons(0x0E0F);
	ib_cm_events_t	event = IB_CME_DESTINATION_REJECT;

	/* read DST information into cm_ptr, overwrite SRC info */
	dapl_dbg_log(DAPL_DBG_TYPE_EP," connect_rtu: recv peer QP data\n"); 

	iovec[0].iov_base = &cm_ptr->dst;
	iovec[0].iov_len  = sizeof(ib_qp_cm_t);
	len = readv(cm_ptr->socket, iovec, 1);
	if (len != sizeof(ib_qp_cm_t) || ntohs(cm_ptr->dst.ver) != DSCM_VER) {
		dapl_log(DAPL_DBG_TYPE_ERR, 
		     " CONN_RTU read: ERR %s, rcnt=%d, ver=%d -> %s\n",
		     strerror(errno), len, cm_ptr->dst.ver,
		     inet_ntoa(((struct sockaddr_in *)
		         ep_ptr->param.remote_ia_address_ptr)->sin_addr)); 
		goto bail;
	}
	/* check for consumer reject */
	if (cm_ptr->dst.rej) {
		dapl_log(DAPL_DBG_TYPE_CM, 
			 " CONN_RTU read: PEER REJ reason=0x%x -> %s\n",
			 ntohs(cm_ptr->dst.rej),
			 inet_ntoa(((struct sockaddr_in *)
			   ep_ptr->param.remote_ia_address_ptr)->sin_addr));
		event = IB_CME_DESTINATION_REJECT_PRIVATE_DATA;
		goto bail;
	}

	/* convert peer response values to host order */
	cm_ptr->dst.port = ntohs(cm_ptr->dst.port);
	cm_ptr->dst.lid = ntohs(cm_ptr->dst.lid);
	cm_ptr->dst.qpn = ntohl(cm_ptr->dst.qpn);
	cm_ptr->dst.p_size = ntohl(cm_ptr->dst.p_size);

	/* save remote address information */
	dapl_os_memcpy( &ep_ptr->remote_ia_address, 
			&cm_ptr->dst.ia_address, 
			sizeof(ep_ptr->remote_ia_address));

	dapl_dbg_log(DAPL_DBG_TYPE_EP, 
		     " CONN_RTU: DST %s port=0x%x lid=0x%x, qpn=0x%x, psize=%d\n",
		     inet_ntoa(((struct sockaddr_in *)&cm_ptr->dst.ia_address)->sin_addr),
		     cm_ptr->dst.port, cm_ptr->dst.lid, 
		     cm_ptr->dst.qpn, cm_ptr->dst.p_size); 

	/* validate private data size before reading */
	if (cm_ptr->dst.p_size > IB_MAX_REP_PDATA_SIZE) {
		dapl_log(DAPL_DBG_TYPE_ERR, 
			 " CONN_RTU read: psize (%d) wrong -> %s\n",
			 cm_ptr->dst.p_size,
			 inet_ntoa(((struct sockaddr_in *)
			   ep_ptr->param.remote_ia_address_ptr)->sin_addr)); 
		goto bail;
	}

	/* read private data into cm_handle if any present */
	dapl_dbg_log(DAPL_DBG_TYPE_EP," socket connected, read private data\n"); 
	if (cm_ptr->dst.p_size) {
		iovec[0].iov_base = cm_ptr->p_data;
		iovec[0].iov_len  = cm_ptr->dst.p_size;
		len = readv(cm_ptr->socket, iovec, 1);
		if (len != cm_ptr->dst.p_size) {
			dapl_log(DAPL_DBG_TYPE_ERR, 
			    " CONN_RTU read pdata: ERR %s, rcnt=%d -> %s\n",
			    strerror(errno), len,
			    inet_ntoa(((struct sockaddr_in *)
			      ep_ptr->param.remote_ia_address_ptr)->sin_addr)); 
			goto bail;
		}
	}

	/* modify QP to RTR and then to RTS with remote info */
	if (dapls_modify_qp_state(ep_ptr->qp_handle, 
				  IBV_QPS_RTR, &cm_ptr->dst) != DAT_SUCCESS) {
		dapl_log(DAPL_DBG_TYPE_ERR, 
			 " CONN_RTU: QPS_RTR ERR %s -> %s\n",
			 strerror(errno), 
			 inet_ntoa(((struct sockaddr_in *)
			   ep_ptr->param.remote_ia_address_ptr)->sin_addr)); 
		goto bail;
	}

	if (dapls_modify_qp_state(ep_ptr->qp_handle, 
				  IBV_QPS_RTS, &cm_ptr->dst) != DAT_SUCCESS) {
		dapl_log(DAPL_DBG_TYPE_ERR, 
			 " CONN_RTU: QPS_RTS ERR %s -> %s\n",
			 strerror(errno), 
			 inet_ntoa(((struct sockaddr_in *)
			   ep_ptr->param.remote_ia_address_ptr)->sin_addr)); 
		goto bail;
	}
		 
	ep_ptr->qp_state = IB_QP_STATE_RTS;

	dapl_dbg_log(DAPL_DBG_TYPE_EP," connect_rtu: send RTU\n"); 

	/* complete handshake after final QP state change */
	if (write(cm_ptr->socket, &rtu_data, sizeof(rtu_data)) == -1)
		dapl_log(DAPL_DBG_TYPE_UTIL,
			 " CONN_RTU: write error = %s\n",
			 strerror(errno));

	/* init cm_handle and post the event with private data */
	ep_ptr->cm_handle = cm_ptr;
	cm_ptr->state = SCM_CONNECTED;
	dapl_dbg_log(DAPL_DBG_TYPE_EP," ACTIVE: connected!\n"); 
	dapl_evd_connection_callback(cm_ptr, 
				     IB_CME_CONNECTED, 
				     cm_ptr->p_data, 
				     ep_ptr);	
	return;
bail:
	/* close socket, free cm structure and post error event */
	dapli_cm_destroy(cm_ptr);
	dapls_ib_reinit_ep(ep_ptr); /* reset QP state */
	dapl_evd_connection_callback(NULL, event, NULL, ep_ptr);
}

/*
 * PASSIVE: Create socket, listen, accept, exchange QP information 
 */
DAT_RETURN 
dapli_socket_listen(DAPL_IA		*ia_ptr,
		    DAT_CONN_QUAL	serviceID,
		    DAPL_SP		*sp_ptr )
{
	struct sockaddr_in	addr;
	ib_cm_srvc_handle_t	cm_ptr = NULL;
	int			opt = 1;
	DAT_RETURN		dat_status = DAT_SUCCESS;

	dapl_dbg_log(DAPL_DBG_TYPE_EP,
		     " listen(ia_ptr %p ServiceID %d sp_ptr %p)\n",
		     ia_ptr, serviceID, sp_ptr);

	cm_ptr = dapli_cm_create();
	if (cm_ptr == NULL)
		return DAT_INSUFFICIENT_RESOURCES;

	cm_ptr->sp = sp_ptr;
	cm_ptr->hca = ia_ptr->hca_ptr;
	
	/* bind, listen, set sockopt, accept, exchange data */
	if ((cm_ptr->socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		dapl_log(DAPL_DBG_TYPE_ERR, 
			 " ERR: listen socket create: %s\n", 
			 strerror(errno));
		dat_status = DAT_INSUFFICIENT_RESOURCES;
		goto bail;
	}

	setsockopt(cm_ptr->socket,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
	addr.sin_port        = htons(serviceID);
	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;

	if ((bind(cm_ptr->socket,(struct sockaddr*)&addr, sizeof(addr)) < 0) ||
	    (listen(cm_ptr->socket, 128) < 0)) {
		dapl_dbg_log(DAPL_DBG_TYPE_CM,
			     " listen: ERROR %s on conn_qual 0x%x\n",
			     strerror(errno),serviceID); 
		if (errno == EADDRINUSE)
			dat_status = DAT_CONN_QUAL_IN_USE;
		else
			dat_status = DAT_CONN_QUAL_UNAVAILABLE;
		goto bail;
	}
	
	/* set cm_handle for this service point, save listen socket */
	sp_ptr->cm_srvc_handle = cm_ptr;

	/* queue up listen socket to process inbound CR's */
	cm_ptr->state = SCM_LISTEN;
	dapli_cm_queue(cm_ptr);

	dapl_dbg_log(DAPL_DBG_TYPE_CM,
		     " listen: qual 0x%x cr %p s_fd %d\n",
		     ntohs(serviceID), cm_ptr, cm_ptr->socket ); 

	return dat_status;
bail:
	dapl_dbg_log( DAPL_DBG_TYPE_CM,
			" listen: ERROR on conn_qual 0x%x\n",serviceID); 
	dapli_cm_destroy(cm_ptr);
	return dat_status;
}

/*
 * PASSIVE: accept socket 
 */
void 
dapli_socket_accept(ib_cm_srvc_handle_t cm_ptr)
{
	ib_cm_handle_t	acm_ptr;
	int		len;
		
	dapl_dbg_log(DAPL_DBG_TYPE_EP," socket_accept\n"); 

	/* Allocate accept CM and initialize */
	if ((acm_ptr = dapl_os_alloc(sizeof(*acm_ptr))) == NULL) 
		goto bail;

	(void) dapl_os_memzero(acm_ptr, sizeof(*acm_ptr));
	
	acm_ptr->socket = -1;
	acm_ptr->sp = cm_ptr->sp;
	acm_ptr->hca = cm_ptr->hca;

	len = sizeof(acm_ptr->dst.ia_address);
	acm_ptr->socket = accept(cm_ptr->socket, 
				(struct sockaddr*)&acm_ptr->dst.ia_address, 
				(socklen_t*)&len);
	if (acm_ptr->socket < 0) {
		dapl_log(DAPL_DBG_TYPE_ERR, 
			" accept: ERR %s on FD %d l_cr %p\n",
			strerror(errno),cm_ptr->socket,cm_ptr); 
		goto bail;
   	}

	dapl_dbg_log(DAPL_DBG_TYPE_EP,
		     " socket accepted, queue new cm %p\n",acm_ptr); 

	acm_ptr->state = SCM_ACCEPTING;
	dapli_cm_queue(acm_ptr);
	return;
bail:
	/* close socket, free cm structure, active will see socket close as reject */
	if (acm_ptr)
		dapli_cm_destroy(acm_ptr);
}

/*
 * PASSIVE: receive peer QP information, private data, post cr_event 
 */
void 
dapli_socket_accept_data(ib_cm_srvc_handle_t acm_ptr)
{
	int len;
	void *p_data = NULL;

	dapl_dbg_log(DAPL_DBG_TYPE_EP," socket accepted, read QP data\n"); 

	/* read in DST QP info, IA address. check for private data */
	len = read(acm_ptr->socket, &acm_ptr->dst, sizeof(ib_qp_cm_t));
	if (len != sizeof(ib_qp_cm_t) || 
	    ntohs(acm_ptr->dst.ver) != DSCM_VER) {
		dapl_log(DAPL_DBG_TYPE_ERR, 
			     " accept read: ERR %s, rcnt=%d, ver=%d\n",
			     strerror(errno), len, acm_ptr->dst.ver); 
		goto bail;
	}

	/* convert accepted values to host order */
	acm_ptr->dst.port = ntohs(acm_ptr->dst.port);
	acm_ptr->dst.lid = ntohs(acm_ptr->dst.lid);
	acm_ptr->dst.qpn = ntohl(acm_ptr->dst.qpn);
	acm_ptr->dst.p_size = ntohl(acm_ptr->dst.p_size);

	dapl_dbg_log(DAPL_DBG_TYPE_EP, 
		     " accept: DST %s port=0x%x lid=0x%x, qpn=0x%x, psize=%d\n",
		     inet_ntoa(((struct sockaddr_in *)&acm_ptr->dst.ia_address)->sin_addr),
		     acm_ptr->dst.port, acm_ptr->dst.lid, 
		     acm_ptr->dst.qpn, acm_ptr->dst.p_size); 

	/* validate private data size before reading */
	if (acm_ptr->dst.p_size > IB_MAX_REQ_PDATA_SIZE) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR, 
			     " accept read: psize (%d) wrong\n",
			     acm_ptr->dst.p_size); 
		goto bail;
	}

	dapl_dbg_log(DAPL_DBG_TYPE_EP," socket accepted, read private data\n"); 

	/* read private data into cm_handle if any present */
	if (acm_ptr->dst.p_size) {
		len = read( acm_ptr->socket, 
			    acm_ptr->p_data, acm_ptr->dst.p_size);
		if (len != acm_ptr->dst.p_size) {
			dapl_log(DAPL_DBG_TYPE_ERR, 
				     " accept read pdata: ERR %s, rcnt=%d\n",
				     strerror(errno), len); 
			goto bail;
		}
		dapl_dbg_log(DAPL_DBG_TYPE_EP," accept: psize=%d read\n",len);
		p_data = acm_ptr->p_data;
	}
	
	acm_ptr->state = SCM_ACCEPTING_DATA;

	/* trigger CR event and return SUCCESS */
	dapls_cr_callback(acm_ptr,
			  IB_CME_CONNECTION_REQUEST_PENDING,
		          p_data,
			  acm_ptr->sp );
	return;
bail:
	/* close socket, free cm structure, active will see socket close as reject */
	dapli_cm_destroy(acm_ptr);
	return;
}

/*
 * PASSIVE: consumer accept, send local QP information, private data, 
 * queue on work thread to receive RTU information to avoid blocking
 * user thread. 
 */
DAT_RETURN 
dapli_socket_accept_usr(DAPL_EP		*ep_ptr,
			DAPL_CR		*cr_ptr,
			DAT_COUNT	p_size,
			DAT_PVOID	p_data)
{
	DAPL_IA		*ia_ptr = ep_ptr->header.owner_ia;
	ib_cm_handle_t  cm_ptr = cr_ptr->ib_cm_handle;
	struct iovec    iovec[2];
	int		len;

	if (p_size > IB_MAX_REP_PDATA_SIZE) 
		return DAT_LENGTH_ERROR;

	/* must have a accepted socket */
	if (cm_ptr->socket < 0)
		return DAT_INTERNAL_ERROR;
	
	dapl_dbg_log(DAPL_DBG_TYPE_EP, 
		     " ACCEPT_USR: remote port=0x%x lid=0x%x"
		     " qpn=0x%x psize=%d\n",
		     cm_ptr->dst.port, cm_ptr->dst.lid,
		     cm_ptr->dst.qpn, cm_ptr->dst.p_size); 

	/* modify QP to RTR and then to RTS with remote info already read */
	if (dapls_modify_qp_state(ep_ptr->qp_handle, 
				  IBV_QPS_RTR, &cm_ptr->dst) != DAT_SUCCESS) {
		dapl_log(DAPL_DBG_TYPE_ERR, 
			 " ACCEPT_USR: QPS_RTR ERR %s -> %s\n",
			 strerror(errno), 
			 inet_ntoa(((struct sockaddr_in *)
				&cm_ptr->dst.ia_address)->sin_addr)); 
		goto bail;
	}
	if (dapls_modify_qp_state(ep_ptr->qp_handle, 
				  IBV_QPS_RTS, &cm_ptr->dst) != DAT_SUCCESS) {
		dapl_log(DAPL_DBG_TYPE_ERR, 
			 " ACCEPT_USR: QPS_RTS ERR %s -> %s\n",
			 strerror(errno), 
			 inet_ntoa(((struct sockaddr_in *)
				&cm_ptr->dst.ia_address)->sin_addr)); 
		goto bail;
	}
	ep_ptr->qp_state = IB_QP_STATE_RTS;
	
	/* save remote address information */
	dapl_os_memcpy( &ep_ptr->remote_ia_address, 
			&cm_ptr->dst.ia_address, 
			sizeof(ep_ptr->remote_ia_address));

	/* send our QP info, IA address, and private data */
	cm_ptr->dst.qpn = htonl(ep_ptr->qp_handle->qp_num);
	cm_ptr->dst.port = htons(ia_ptr->hca_ptr->port_num);
	cm_ptr->dst.lid = htons(dapli_get_lid(ia_ptr->hca_ptr->ib_hca_handle, 
				        (uint8_t)ia_ptr->hca_ptr->port_num));
	if (cm_ptr->dst.lid == 0xffff) {
		dapl_log(DAPL_DBG_TYPE_ERR, 
			 " ACCEPT_USR: query LID ERR %s -> %s\n",
			 strerror(errno), 
			 inet_ntoa(((struct sockaddr_in *)
				&cm_ptr->dst.ia_address)->sin_addr)); 
		goto bail;
	}

        /* in network order */
	if (ibv_query_gid(ia_ptr->hca_ptr->ib_hca_handle,
			  (uint8_t)ia_ptr->hca_ptr->port_num,
			  0, &cm_ptr->dst.gid)) {
		dapl_log(DAPL_DBG_TYPE_ERR, 
			 " ACCEPT_USR: query GID ERR %s -> %s\n",
			 strerror(errno), 
			 inet_ntoa(((struct sockaddr_in *)
				&cm_ptr->dst.ia_address)->sin_addr)); 
		goto bail;
	}

	cm_ptr->dst.ia_address = ia_ptr->hca_ptr->hca_address;
	cm_ptr->dst.p_size = htonl(p_size);
	iovec[0].iov_base = &cm_ptr->dst;
	iovec[0].iov_len  = sizeof(ib_qp_cm_t);
	if (p_size) {
		iovec[1].iov_base = p_data;
		iovec[1].iov_len  = p_size;
	}
	len = writev(cm_ptr->socket, iovec, (p_size ? 2:1));
    	if (len != (p_size + sizeof(ib_qp_cm_t))) {
		dapl_log(DAPL_DBG_TYPE_ERR, 
			 " ACCEPT_USR: ERR %s, wcnt=%d -> %s\n",
			 strerror(errno), len,
			 inet_ntoa(((struct sockaddr_in *)
			     &cm_ptr->dst.ia_address)->sin_addr)); 
		goto bail;
	}
	dapl_dbg_log(DAPL_DBG_TYPE_CM, 
		     " ACCEPT_USR: local port=0x%x lid=0x%x"
		     " qpn=0x%x psize=%d\n",
		     ntohs(cm_ptr->dst.port), ntohs(cm_ptr->dst.lid), 
		     ntohl(cm_ptr->dst.qpn), ntohl(cm_ptr->dst.p_size)); 
        dapl_dbg_log(DAPL_DBG_TYPE_CM,
                     " ACCEPT_USR SRC GID subnet %016llx id %016llx\n",
                     (unsigned long long) 
			cpu_to_be64(cm_ptr->dst.gid.global.subnet_prefix),
                     (unsigned long long) 
			cpu_to_be64(cm_ptr->dst.gid.global.interface_id));

	/* save state and reference to EP, queue for RTU data */
	cm_ptr->ep = ep_ptr;
	cm_ptr->hca = ia_ptr->hca_ptr;
	cm_ptr->state = SCM_ACCEPTED;

	/* restore remote address information for query */
	dapl_os_memcpy( &cm_ptr->dst.ia_address, 
			&ep_ptr->remote_ia_address,
			sizeof(cm_ptr->dst.ia_address));

	dapl_dbg_log( DAPL_DBG_TYPE_EP," PASSIVE: accepted!\n" ); 
	return DAT_SUCCESS;
bail:
	dapli_cm_destroy(cm_ptr);
	dapls_ib_reinit_ep(ep_ptr); /* reset QP state */
	return DAT_INTERNAL_ERROR;
}

/*
 * PASSIVE: read RTU from active peer, post CONN event
 */
void 
dapli_socket_accept_rtu(ib_cm_handle_t	cm_ptr)
{
	int		len;
	short		rtu_data = 0;

	/* complete handshake after final QP state change */
	len = read(cm_ptr->socket, &rtu_data, sizeof(rtu_data));
	if (len != sizeof(rtu_data) || ntohs(rtu_data) != 0x0e0f) {
		dapl_log(DAPL_DBG_TYPE_ERR, 
			 " ACCEPT_RTU: ERR %s, rcnt=%d rdata=%x\n",
			 strerror(errno), len, ntohs(rtu_data),
			 inet_ntoa(((struct sockaddr_in *)
				&cm_ptr->dst.ia_address)->sin_addr)); 
		goto bail;
	}

	/* save state and reference to EP, queue for disc event */
	cm_ptr->state = SCM_CONNECTED;

	/* final data exchange if remote QP state is good to go */
	dapl_dbg_log( DAPL_DBG_TYPE_EP," PASSIVE: connected!\n" ); 
	dapls_cr_callback(cm_ptr, IB_CME_CONNECTED, NULL, cm_ptr->sp);
	return;
bail:
	dapls_ib_reinit_ep(cm_ptr->ep); /* reset QP state */
	dapli_cm_destroy(cm_ptr);
	dapls_cr_callback(cm_ptr, IB_CME_DESTINATION_REJECT, NULL, cm_ptr->sp);
}


/*
 * dapls_ib_connect
 *
 * Initiate a connection with the passive listener on another node
 *
 * Input:
 *	ep_handle,
 *	remote_ia_address,
 *	remote_conn_qual,
 *	prd_size		size of private data and structure
 *	prd_prt			pointer to private data structure
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *	DAT_INVALID_PARAMETER
 *
 */
DAT_RETURN
dapls_ib_connect (
	IN  DAT_EP_HANDLE		ep_handle,
	IN  DAT_IA_ADDRESS_PTR		remote_ia_address,
	IN  DAT_CONN_QUAL		remote_conn_qual,
	IN  DAT_COUNT			private_data_size,
	IN  void			*private_data )
{
	DAPL_EP		*ep_ptr;
	ib_qp_handle_t	qp_ptr;
	
	dapl_dbg_log ( DAPL_DBG_TYPE_EP,
			" connect(ep_handle %p ....)\n", ep_handle);

	ep_ptr = (DAPL_EP*)ep_handle;
	qp_ptr = ep_ptr->qp_handle;

	return (dapli_socket_connect(ep_ptr, remote_ia_address, 
				     remote_conn_qual,
				     private_data_size, private_data));
}

/*
 * dapls_ib_disconnect
 *
 * Disconnect an EP
 *
 * Input:
 *	ep_handle,
 *	disconnect_flags
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 */
DAT_RETURN
dapls_ib_disconnect(
	IN	DAPL_EP			*ep_ptr,
	IN	DAT_CLOSE_FLAGS		close_flags)
{
	dapl_dbg_log (DAPL_DBG_TYPE_EP,
			"dapls_ib_disconnect(ep_handle %p ....)\n",
			ep_ptr);

	/* reinit to modify QP state */
	dapls_ib_reinit_ep(ep_ptr);

	if (ep_ptr->cm_handle == NULL ||
	    ep_ptr->param.ep_state == DAT_EP_STATE_DISCONNECTED)
		return DAT_SUCCESS;
	else
		return(dapli_socket_disconnect(ep_ptr->cm_handle));
}

/*
 * dapls_ib_disconnect_clean
 *
 * Clean up outstanding connection data. This routine is invoked
 * after the final disconnect callback has occurred. Only on the
 * ACTIVE side of a connection.
 *
 * Input:
 *	ep_ptr		DAPL_EP
 *	active		Indicates active side of connection
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	void
 *
 */
void
dapls_ib_disconnect_clean (
	IN  DAPL_EP			*ep_ptr,
	IN  DAT_BOOLEAN			active,
	IN  const ib_cm_events_t	ib_cm_event )
{
    if (ep_ptr->cm_handle)
        dapli_cm_destroy(ep_ptr->cm_handle);
	
    return;
}

/*
 * dapl_ib_setup_conn_listener
 *
 * Have the CM set up a connection listener.
 *
 * Input:
 *	ibm_hca_handle		HCA handle
 *	qp_handle			QP handle
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *	DAT_INTERNAL_ERROR
 *	DAT_CONN_QUAL_UNAVAILBLE
 *	DAT_CONN_QUAL_IN_USE
 *
 */
DAT_RETURN
dapls_ib_setup_conn_listener (
	IN  DAPL_IA		*ia_ptr,
	IN  DAT_UINT64		ServiceID,
	IN  DAPL_SP		*sp_ptr )
{
	return (dapli_socket_listen( ia_ptr, ServiceID, sp_ptr ));
}


/*
 * dapl_ib_remove_conn_listener
 *
 * Have the CM remove a connection listener.
 *
 * Input:
 *	ia_handle		IA handle
 *	ServiceID		IB Channel Service ID
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INVALID_STATE
 *
 */
DAT_RETURN
dapls_ib_remove_conn_listener (
	IN  DAPL_IA		*ia_ptr,
	IN  DAPL_SP		*sp_ptr )
{
	ib_cm_srvc_handle_t	cm_ptr = sp_ptr->cm_srvc_handle;

	dapl_dbg_log (DAPL_DBG_TYPE_EP,
			"dapls_ib_remove_conn_listener(ia_ptr %p sp_ptr %p cm_ptr %p)\n",
			ia_ptr, sp_ptr, cm_ptr );

	/* close accepted socket, free cm_srvc_handle and return */
	if (cm_ptr != NULL) {
		if (cm_ptr->socket >= 0) {
			close(cm_ptr->socket );
			cm_ptr->socket = -1;
		}
	    	/* cr_thread will free */
		cm_ptr->state = SCM_DESTROY;
		sp_ptr->cm_srvc_handle = NULL;
		if (write(g_scm_pipe[1], "w", sizeof "w") == -1)
			dapl_log(DAPL_DBG_TYPE_UTIL,
				 " remove_listen: thread wakeup error = %s\n",
				 strerror(errno));
	}
	return DAT_SUCCESS;
}

/*
 * dapls_ib_accept_connection
 *
 * Perform necessary steps to accept a connection
 *
 * Input:
 *	cr_handle
 *	ep_handle
 *	private_data_size
 *	private_data
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *	DAT_INTERNAL_ERROR
 *
 */
DAT_RETURN
dapls_ib_accept_connection (
	IN  DAT_CR_HANDLE	cr_handle,
	IN  DAT_EP_HANDLE	ep_handle,
	IN  DAT_COUNT		p_size,
	IN  const DAT_PVOID	p_data )
{
	DAPL_CR			*cr_ptr;
	DAPL_EP			*ep_ptr;
	
	dapl_dbg_log(DAPL_DBG_TYPE_EP,
		     "dapls_ib_accept_connection(cr %p ep %p prd %p,%d)\n",
		     cr_handle, ep_handle, p_data, p_size  );

	cr_ptr = (DAPL_CR *)cr_handle;
	ep_ptr = (DAPL_EP *)ep_handle;
	
	/* allocate and attach a QP if necessary */
	if (ep_ptr->qp_state == DAPL_QP_STATE_UNATTACHED) {
		DAT_RETURN status;
		status = dapls_ib_qp_alloc(ep_ptr->header.owner_ia, 
					   ep_ptr, ep_ptr);
		if (status != DAT_SUCCESS)
    			return status;
	}
	return(dapli_socket_accept_usr(ep_ptr, cr_ptr, p_size, p_data));
}


/*
 * dapls_ib_reject_connection
 *
 * Reject a connection
 *
 * Input:
 *	cr_handle
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INTERNAL_ERROR
 *
 */
DAT_RETURN
dapls_ib_reject_connection (
	IN  ib_cm_handle_t	ib_cm_handle,
	IN  int			reject_reason)
{
    	ib_cm_srvc_handle_t	cm_ptr = ib_cm_handle;
	struct iovec    	iovec;

	dapl_dbg_log (DAPL_DBG_TYPE_EP,
		      "dapls_ib_reject_connection(cm_handle %p reason %x)\n",
		      ib_cm_handle, reject_reason);

	/* write reject data to indicate reject */
	if (cm_ptr->socket >= 0) {
		cm_ptr->dst.rej = (uint16_t)reject_reason;
		cm_ptr->dst.rej = htons(cm_ptr->dst.rej);
		iovec.iov_base = &cm_ptr->dst;
		iovec.iov_len  = sizeof(ib_qp_cm_t);
		writev(cm_ptr->socket, &iovec, 1);
		close(cm_ptr->socket);
		cm_ptr->socket = -1;
	}

	/* cr_thread will destroy CR */
	cm_ptr->state = SCM_REJECTED;
	if (write(g_scm_pipe[1], "w", sizeof "w") == -1)
		dapl_log(DAPL_DBG_TYPE_UTIL,
			 " reject_connection: thread wakeup error = %s\n",
			 strerror(errno));
	return DAT_SUCCESS;
}

/*
 * dapls_ib_cm_remote_addr
 *
 * Obtain the remote IP address given a connection
 *
 * Input:
 *	cr_handle
 *
 * Output:
 *	remote_ia_address: where to place the remote address
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INVALID_HANDLE
 *
 */
DAT_RETURN
dapls_ib_cm_remote_addr (
	IN      DAT_HANDLE	dat_handle,
	OUT	DAT_SOCK_ADDR6	*remote_ia_address )
{
	DAPL_HEADER	*header;
	ib_cm_handle_t	ib_cm_handle;

	dapl_dbg_log (DAPL_DBG_TYPE_EP,
		      "dapls_ib_cm_remote_addr(dat_handle %p, ....)\n",
		      dat_handle );

	header = (DAPL_HEADER *)dat_handle;

	if (header->magic == DAPL_MAGIC_EP) 
		ib_cm_handle = ((DAPL_EP *) dat_handle)->cm_handle;
	else if (header->magic == DAPL_MAGIC_CR) 
		ib_cm_handle = ((DAPL_CR *) dat_handle)->ib_cm_handle;
	else 
		return DAT_INVALID_HANDLE;

	dapl_os_memcpy(	remote_ia_address, 
			&ib_cm_handle->dst.ia_address, 
			sizeof(DAT_SOCK_ADDR6) );

	return DAT_SUCCESS;
}

/*
 * dapls_ib_private_data_size
 *
 * Return the size of private data given a connection op type
 *
 * Input:
 *	prd_ptr		private data pointer
 *	conn_op		connection operation type
 *
 * If prd_ptr is NULL, this is a query for the max size supported by
 * the provider, otherwise it is the actual size of the private data
 * contained in prd_ptr.
 *
 *
 * Output:
 *	None
 *
 * Returns:
 * 	length of private data
 *
 */
int dapls_ib_private_data_size (
	IN      DAPL_PRIVATE	*prd_ptr,
	IN	DAPL_PDATA_OP	conn_op)
{
	int  size;

	switch (conn_op)
	{
		case DAPL_PDATA_CONN_REQ:
		{
			size = IB_MAX_REQ_PDATA_SIZE;
			break;
		}
		case DAPL_PDATA_CONN_REP:
		{
			size = IB_MAX_REP_PDATA_SIZE;
			break;
		}
		case DAPL_PDATA_CONN_REJ:
		{
			size = IB_MAX_REJ_PDATA_SIZE;
			break;
		}
		case DAPL_PDATA_CONN_DREQ:
		{
			size = IB_MAX_DREQ_PDATA_SIZE;
			break;
		}
		case DAPL_PDATA_CONN_DREP:
		{
			size = IB_MAX_DREP_PDATA_SIZE;
			break;
		}
		default:
		{
			size = 0;
		}

	} /* end case */

	return size;
}

/*
 * Map all socket CM event codes to the DAT equivelent.
 */
#define DAPL_IB_EVENT_CNT	11

static struct ib_cm_event_map
{
	const ib_cm_events_t	ib_cm_event;
	DAT_EVENT_NUMBER	dat_event_num;
	} ib_cm_event_map[DAPL_IB_EVENT_CNT] = {
	/* 00 */  { IB_CME_CONNECTED,	
					DAT_CONNECTION_EVENT_ESTABLISHED}, 
	/* 01 */  { IB_CME_DISCONNECTED,	
					DAT_CONNECTION_EVENT_DISCONNECTED},
	/* 02 */  { IB_CME_DISCONNECTED_ON_LINK_DOWN, 
					DAT_CONNECTION_EVENT_DISCONNECTED},
	/* 03 */  { IB_CME_CONNECTION_REQUEST_PENDING,	
					DAT_CONNECTION_REQUEST_EVENT},
	/* 04 */  { IB_CME_CONNECTION_REQUEST_PENDING_PRIVATE_DATA,
					DAT_CONNECTION_REQUEST_EVENT},
	/* 05 */  { IB_CME_DESTINATION_REJECT,
					DAT_CONNECTION_EVENT_NON_PEER_REJECTED},
	/* 06 */  { IB_CME_DESTINATION_REJECT_PRIVATE_DATA,		
					DAT_CONNECTION_EVENT_PEER_REJECTED},
	/* 07 */  { IB_CME_DESTINATION_UNREACHABLE,	
					DAT_CONNECTION_EVENT_UNREACHABLE},
	/* 08 */  { IB_CME_TOO_MANY_CONNECTION_REQUESTS,
					DAT_CONNECTION_EVENT_NON_PEER_REJECTED},
	/* 09 */  { IB_CME_LOCAL_FAILURE,
					DAT_CONNECTION_EVENT_BROKEN},
	/* 10 */  { IB_CM_LOCAL_FAILURE,
					DAT_CONNECTION_EVENT_BROKEN}
};
 
/*
 * dapls_ib_get_cm_event
 *
 * Return a DAT connection event given a provider CM event.
 *
 * Input:
 *	dat_event_num	DAT event we need an equivelent CM event for
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	ib_cm_event of translated DAPL value
 */
DAT_EVENT_NUMBER
dapls_ib_get_dat_event (
	IN    const ib_cm_events_t	ib_cm_event,
	IN    DAT_BOOLEAN		active)
{
	DAT_EVENT_NUMBER	dat_event_num;
	int			i;
	
	active = active;

	if (ib_cm_event > IB_CM_LOCAL_FAILURE)
		return (DAT_EVENT_NUMBER) 0;

	dat_event_num = 0;
	for (i = 0; i < DAPL_IB_EVENT_CNT; i++) {
		if (ib_cm_event == ib_cm_event_map[i].ib_cm_event) {
			dat_event_num = ib_cm_event_map[i].dat_event_num;
			break;
		}
	}
	dapl_dbg_log (DAPL_DBG_TYPE_CALLBACK,
		"dapls_ib_get_dat_event: event translate(%s) ib=0x%x dat=0x%x\n",
		active ? "active" : "passive",  ib_cm_event, dat_event_num);

	return dat_event_num;
}


/*
 * dapls_ib_get_dat_event
 *
 * Return a DAT connection event given a provider CM event.
 * 
 * Input:
 *	ib_cm_event	event provided to the dapl callback routine
 *	active		switch indicating active or passive connection
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_EVENT_NUMBER of translated provider value
 */
ib_cm_events_t
dapls_ib_get_cm_event (
	IN    DAT_EVENT_NUMBER		dat_event_num)
{
    ib_cm_events_t	ib_cm_event;
    int			i;

    ib_cm_event = 0;
    for (i = 0; i < DAPL_IB_EVENT_CNT; i++) {
	if ( dat_event_num == ib_cm_event_map[i].dat_event_num ) {
		ib_cm_event = ib_cm_event_map[i].ib_cm_event;
		break;
	}
    }
    return ib_cm_event;
}

/* outbound/inbound CR processing thread to avoid blocking applications */
#define SCM_MAX_CONN 8192
void cr_thread(void *arg) 
{
    struct dapl_hca	*hca_ptr = arg;
    ib_cm_handle_t	cr, next_cr;
    int 		opt,ret,idx;
    socklen_t		opt_len;
    char		rbuf[2];
    struct pollfd	ufds[SCM_MAX_CONN];
     
    dapl_dbg_log(DAPL_DBG_TYPE_UTIL," cr_thread: ENTER hca %p\n",hca_ptr);

    dapl_os_lock( &hca_ptr->ib_trans.lock );
    hca_ptr->ib_trans.cr_state = IB_THREAD_RUN;
    while (hca_ptr->ib_trans.cr_state == IB_THREAD_RUN) {
	idx=0;
	ufds[idx].fd = g_scm_pipe[0]; /* wakeup and process work */
        ufds[idx].events = POLLIN;
	ufds[idx].revents = 0;
	
	if (!dapl_llist_is_empty(&hca_ptr->ib_trans.list))
            next_cr = dapl_llist_peek_head (&hca_ptr->ib_trans.list);
	else
	    next_cr = NULL;

	while (next_cr) {
	    cr = next_cr;
	    if ((cr->socket == -1 && cr->state == SCM_DESTROY) || 
		 hca_ptr->ib_trans.cr_state != IB_THREAD_RUN) {

		dapl_dbg_log(DAPL_DBG_TYPE_CM," cr_thread: Free %p\n", cr);
		next_cr = dapl_llist_next_entry(&hca_ptr->ib_trans.list,
						(DAPL_LLIST_ENTRY*)&cr->entry );
		dapl_llist_remove_entry(&hca_ptr->ib_trans.list, 
					(DAPL_LLIST_ENTRY*)&cr->entry);
		dapl_os_free(cr, sizeof(*cr));
		continue;
	    }
	    if (idx==SCM_MAX_CONN-1) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR, 
			     "SCM ERR: cm_thread exceeded FD_SETSIZE %d\n",idx+1);
		continue;
	    }
		
	    /* Add to ufds for poll, check for immediate work */
	    ufds[++idx].fd = cr->socket; /* add listen or cr */
	    ufds[idx].revents = 0;
	    if (cr->state == SCM_CONN_PENDING)
	    	ufds[idx].events = POLLOUT;
	    else
		ufds[idx].events = POLLIN;

	    /* check socket for event, accept in or connect out */
	    dapl_dbg_log(DAPL_DBG_TYPE_CM," poll cr=%p, fd=%d,%d\n", 
				cr, cr->socket, ufds[idx].fd);
	    dapl_os_unlock(&hca_ptr->ib_trans.lock);
	    ret = poll(&ufds[idx],1,0);
	    dapl_dbg_log(DAPL_DBG_TYPE_CM,
			 " poll wakeup ret=%d cr->st=%d"
			 " ev=0x%x fd=%d\n",
			 ret,cr->state,ufds[idx].revents,ufds[idx].fd);

	    /* data on listen, qp exchange, and on disconnect request */
	    if ((ret == 1) && ufds[idx].revents == POLLIN) {
		if (cr->socket > 0) {
			if (cr->state == SCM_LISTEN)
				dapli_socket_accept(cr);
			else if (cr->state == SCM_ACCEPTING)
				dapli_socket_accept_data(cr);
			else if (cr->state == SCM_ACCEPTED)
				dapli_socket_accept_rtu(cr);
			else if (cr->state == SCM_RTU_PENDING)
				dapli_socket_connect_rtu(cr);
			else if (cr->state == SCM_CONNECTED)
				dapli_socket_disconnect(cr);
		}
	    /* connect socket is writable, check status */
	    } else if ((ret == 1) && 
			(ufds[idx].revents & POLLOUT ||
			 ufds[idx].revents & POLLERR)) {
		if (cr->state == SCM_CONN_PENDING) {
			opt = 0;
			ret = getsockopt(cr->socket, SOL_SOCKET, 
					 SO_ERROR, &opt, &opt_len);
			if (!ret)
				dapli_socket_connected(cr,opt);
			else
				dapli_socket_connected(cr,errno);
		} else {
			dapl_log(DAPL_DBG_TYPE_WARN,
				 " CM poll ERR, wrong state(%d) -> %s SKIP\n",
				 cr->state,
				 inet_ntoa(((struct sockaddr_in*)
					&cr->dst.ia_address)->sin_addr));
		}
	    } else if (ret != 0) {
    		dapl_log(DAPL_DBG_TYPE_CM,
			 " CM poll warning %s, ret=%d revnt=%x st=%d -> %s\n",
			 strerror(errno), ret, ufds[idx].revents, cr->state,
			 inet_ntoa(((struct sockaddr_in*)
				&cr->dst.ia_address)->sin_addr));

		/* POLLUP, NVAL, or poll error, issue event if connected */
		if (cr->state == SCM_CONNECTED)
			dapli_socket_disconnect(cr);
	    } 
	    dapl_os_lock(&hca_ptr->ib_trans.lock);
	    next_cr =  dapl_llist_next_entry(&hca_ptr->ib_trans.list,
					     (DAPL_LLIST_ENTRY*)&cr->entry);
	} 
	dapl_os_unlock(&hca_ptr->ib_trans.lock);
	dapl_dbg_log(DAPL_DBG_TYPE_CM," cr_thread: sleep, %d\n", idx+1);
	poll(ufds,idx+1,-1); /* infinite, all sockets and pipe */
	/* if pipe used to wakeup, consume */
	if (ufds[0].revents == POLLIN)
		if (read(g_scm_pipe[0], rbuf, 2) == -1)
			dapl_log(DAPL_DBG_TYPE_CM,
				 " cr_thread: read pipe error = %s\n",
				 strerror(errno));
	dapl_dbg_log(DAPL_DBG_TYPE_CM," cr_thread: wakeup\n");
	dapl_os_lock(&hca_ptr->ib_trans.lock);
    } 
    dapl_os_unlock(&hca_ptr->ib_trans.lock);	
    hca_ptr->ib_trans.cr_state = IB_THREAD_EXIT;
    dapl_dbg_log(DAPL_DBG_TYPE_UTIL," cr_thread(hca %p) exit\n",hca_ptr);
}

/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 8
 * End:
 */
