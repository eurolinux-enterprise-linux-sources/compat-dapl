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
 *   The OpenIB uCMA provider - uCMA connection management
 *
 ****************************************************************************
 *		   Source Control System Information
 *
 *    $Id: $
 *
 * Copyright (c) 2005 Voltaire Inc.  All rights reserved.
 * Copyright (c) 2005 Intel Corporation. All rights reserved.
 * Copyright (c) 2004-2005, Mellanox Technologies, Inc. All rights reserved. 
 * Copyright (c) 2003 Topspin Corporation.  All rights reserved. 
 * Copyright (c) 2005 Sun Microsystems, Inc. All rights reserved.
 *
 **************************************************************************/

#include "dapl.h"
#include "dapl_adapter_util.h"
#include "dapl_evd_util.h"
#include "dapl_cr_util.h"
#include "dapl_name_service.h"
#include "dapl_ib_util.h"
#include <sys/poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

extern struct rdma_event_channel *g_cm_events;

/* local prototypes */
static struct dapl_cm_id * dapli_req_recv(struct dapl_cm_id *conn, 
					  struct rdma_cm_event *event);
static void dapli_cm_active_cb(struct dapl_cm_id *conn, 
			      struct rdma_cm_event *event);
static void dapli_cm_passive_cb(struct dapl_cm_id *conn, 
			       struct rdma_cm_event *event);
static void dapli_addr_resolve(struct dapl_cm_id *conn);
static void dapli_route_resolve(struct dapl_cm_id *conn);

#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline uint64_t cpu_to_be64(uint64_t x) { return bswap_64(x); }
#elif __BYTE_ORDER == __BIG_ENDIAN
static inline uint64_t cpu_to_be64(uint64_t x) { return x; }
#endif

/* cma requires 16 bit SID */
#define IB_PORT_MOD 32001
#define IB_PORT_BASE (65535 - IB_PORT_MOD)
#define SID_TO_PORT(SID) \
    (SID > 0xffff ? \
    htons((unsigned short)((SID % IB_PORT_MOD) + IB_PORT_BASE)) :\
    htons((unsigned short)SID))

#define PORT_TO_SID(p) ntohs(p)

static void dapli_addr_resolve(struct dapl_cm_id *conn)
{
	int ret;
#ifdef DAPL_DBG
	struct rdma_addr *ipaddr = &conn->cm_id->route.addr;
#endif
	dapl_dbg_log(DAPL_DBG_TYPE_CM, 
		" addr_resolve: cm_id %p SRC %x DST %x\n", 
		conn->cm_id, 
		ntohl(((struct sockaddr_in *)
			&ipaddr->src_addr)->sin_addr.s_addr),
		ntohl(((struct sockaddr_in *)
			&ipaddr->dst_addr)->sin_addr.s_addr));
	
	ret =  rdma_resolve_route(conn->cm_id, conn->route_timeout);
	if (ret) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			 " dapl_cma_connect: rdma_resolve_route ERR %d %s\n",
			 ret, strerror(errno));

		dapl_evd_connection_callback(conn, 
					     IB_CME_LOCAL_FAILURE, 
					     NULL, conn->ep);
	}
}

static void dapli_route_resolve(struct dapl_cm_id *conn)
{
	int ret;
#ifdef DAPL_DBG
	struct rdma_addr *ipaddr = &conn->cm_id->route.addr;
	struct ib_addr   *ibaddr = &conn->cm_id->route.addr.addr.ibaddr;
#endif

	dapl_dbg_log(DAPL_DBG_TYPE_CM, 
		" route_resolve: cm_id %p SRC %x DST %x PORT %d\n", 
		conn->cm_id, 
		ntohl(((struct sockaddr_in *)
			&ipaddr->src_addr)->sin_addr.s_addr),
		ntohl(((struct sockaddr_in *)
			&ipaddr->dst_addr)->sin_addr.s_addr),
		ntohs(((struct sockaddr_in *)
			&ipaddr->dst_addr)->sin_port) );

	dapl_dbg_log(DAPL_DBG_TYPE_CM, 
		" route_resolve: SRC GID subnet %016llx id %016llx\n",
		(unsigned long long)
			cpu_to_be64(ibaddr->sgid.global.subnet_prefix),
		(unsigned long long)
			cpu_to_be64(ibaddr->sgid.global.interface_id));

	dapl_dbg_log(DAPL_DBG_TYPE_CM, 
		" route_resolve: DST GID subnet %016llx id %016llx\n",
		(unsigned long long)
			cpu_to_be64(ibaddr->dgid.global.subnet_prefix),
		(unsigned long long)
			cpu_to_be64(ibaddr->dgid.global.interface_id));
	
	dapl_dbg_log(DAPL_DBG_TYPE_CM, 
		" route_resolve: cm_id %p pdata %p plen %d rr %d ind %d\n",
		conn->cm_id,
		conn->params.private_data, 
		conn->params.private_data_len,
		conn->params.responder_resources, 
		conn->params.initiator_depth );
	ret = rdma_connect(conn->cm_id, &conn->params);

	if (ret) {
		dapl_log(DAPL_DBG_TYPE_ERR,
			 " dapl_cma_connect: rdma_connect ERR %d %s\n",
			 ret, strerror(errno));
		goto bail;
	}
	return;

bail:
	dapl_evd_connection_callback(conn, 
				     IB_CME_LOCAL_FAILURE, 
				     NULL, conn->ep);
}

/* 
 * Called from consumer thread via dat_ep_free().
 * CANNOT be called from the async event processing thread
 * dapli_cma_event_cb() since a cm_id reference is held and
 * a deadlock will occur.
 */
void dapli_destroy_conn(struct dapl_cm_id *conn)
{
	struct rdma_cm_id *cm_id;

	dapl_dbg_log(DAPL_DBG_TYPE_CM, 
		     " destroy_conn: conn %p id %d\n",
		     conn,conn->cm_id);
	
	dapl_os_lock(&conn->lock);
	conn->destroy = 1;
	
	if (conn->ep) {
		conn->ep->cm_handle = IB_INVALID_HANDLE;
		conn->ep->qp_handle = IB_INVALID_HANDLE;
	}

	cm_id = conn->cm_id;
	conn->cm_id = NULL;
	dapl_os_unlock(&conn->lock);

	/* 
	 * rdma_destroy_id will force synchronization with async CM event 
	 * thread since it blocks until the in-process event reference
	 * is cleared during our event processing call exit.
	 */
	if (cm_id) {
		if (cm_id->qp)
			rdma_destroy_qp(cm_id);

		rdma_destroy_id(cm_id);
	}
	dapl_os_free(conn, sizeof(*conn));
}

static struct dapl_cm_id * dapli_req_recv(struct dapl_cm_id *conn,
					  struct rdma_cm_event *event)
{
	struct dapl_cm_id *new_conn;
#ifdef DAPL_DBG
	struct rdma_addr *ipaddr = &event->id->route.addr;
#endif
	
	if (conn->sp == NULL) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR, 
			     " dapli_rep_recv: on invalid listen "
			     "handle\n");
		return NULL;
	}

	/* allocate new cm_id and merge listen parameters */
	new_conn = dapl_os_alloc(sizeof(*new_conn)); 
	if (new_conn) {
		(void)dapl_os_memzero(new_conn, sizeof(*new_conn));
		new_conn->cm_id = event->id; /* provided by uCMA */
		event->id->context = new_conn; /* update CM_ID context */
		new_conn->sp = conn->sp;
		new_conn->hca = conn->hca;
		
		/* Get requesters connect data, setup for accept */
                new_conn->params.responder_resources =
                        DAPL_MIN(event->param.conn.responder_resources,
                                 conn->hca->ib_trans.max_rdma_rd_in);
                new_conn->params.initiator_depth =
                        DAPL_MIN(event->param.conn.initiator_depth,
                                 conn->hca->ib_trans.max_rdma_rd_out);

		new_conn->params.flow_control = event->param.conn.flow_control;
		new_conn->params.rnr_retry_count = event->param.conn.rnr_retry_count;
		new_conn->params.retry_count = event->param.conn.retry_count;

		/* save private data */
		if (event->param.conn.private_data_len) {
			dapl_os_memcpy(new_conn->p_data, 
				       event->param.conn.private_data,
				       event->param.conn.private_data_len);
			new_conn->params.private_data = new_conn->p_data;
			new_conn->params.private_data_len = 
						event->param.conn.private_data_len;
		}

		dapl_dbg_log(DAPL_DBG_TYPE_CM, " passive_cb: "
			     "REQ: SP %p PORT %d LID %d "
			     "NEW CONN %p ID %p pD %p,%d\n",
			     new_conn->sp,
			     ntohs(((struct sockaddr_in *)
					&ipaddr->src_addr)->sin_port),
			     event->listen_id, new_conn, event->id,
			     event->param.conn.private_data, event->param.conn.private_data_len);
		
		dapl_dbg_log(DAPL_DBG_TYPE_CM, " passive_cb: "
			     "REQ: IP SRC %x PORT %d DST %x PORT %d "
			     "rr %d init %d\n", 
			     ntohl(((struct sockaddr_in *)
				&ipaddr->src_addr)->sin_addr.s_addr),
			     ntohs(((struct sockaddr_in *)
				&ipaddr->src_addr)->sin_port),
			     ntohl(((struct sockaddr_in *)
				&ipaddr->dst_addr)->sin_addr.s_addr),
			     ntohs(((struct sockaddr_in *)
				&ipaddr->dst_addr)->sin_port),
			     new_conn->params.responder_resources,
			     new_conn->params.initiator_depth);
	}
	return new_conn;
}

static void dapli_cm_active_cb(struct dapl_cm_id *conn,
			      struct rdma_cm_event *event)
{
	dapl_dbg_log(DAPL_DBG_TYPE_CM, 
		     " active_cb: conn %p id %d event %d\n",
		     conn, conn->cm_id, event->event );

	dapl_os_lock(&conn->lock);
	if (conn->destroy) {
		dapl_os_unlock(&conn->lock);
		return;
	}
	dapl_os_unlock(&conn->lock);

        /* There is a chance that we can get events after
         * the consumer calls disconnect in a pending state
         * since the IB CM and uDAPL states are not shared.
         * In some cases, IB CM could generate either a DCONN
         * or CONN_ERR after the consumer returned from
         * dapl_ep_disconnect with a DISCONNECTED event
         * already queued. Check state here and bail to
         * avoid any events after a disconnect.
         */
        if (DAPL_BAD_HANDLE(conn->ep, DAPL_MAGIC_EP))
                return;

        dapl_os_lock(&conn->ep->header.lock);
        if (conn->ep->param.ep_state == DAT_EP_STATE_DISCONNECTED) {
                dapl_os_unlock(&conn->ep->header.lock);
                return;
        }
        if (event->event == RDMA_CM_EVENT_DISCONNECTED)
                conn->ep->param.ep_state = DAT_EP_STATE_DISCONNECTED;

        dapl_os_unlock(&conn->ep->header.lock);

	switch (event->event) {
	case RDMA_CM_EVENT_UNREACHABLE:
	case RDMA_CM_EVENT_CONNECT_ERROR:
	{
		dapl_log(DAPL_DBG_TYPE_WARN,
			 "dapl_cma_active: CONN_ERR event=0x%x"
			 " status=%d %s DST %s, %d\n",
			 event->event, event->status,
			 (event->status == -ETIMEDOUT)?"TIMEOUT":"",
			 inet_ntoa(((struct sockaddr_in *)
			     &conn->cm_id->route.addr.dst_addr)->sin_addr),
			 ntohs(((struct sockaddr_in *)
			     &conn->cm_id->route.addr.dst_addr)->sin_port));

		/* per DAT SPEC provider always returns UNREACHABLE */
		dapl_evd_connection_callback(conn, 
					     IB_CME_DESTINATION_UNREACHABLE, 
					     NULL, conn->ep);
		break;
	}
	case RDMA_CM_EVENT_REJECTED:
	{
		ib_cm_events_t cm_event;

		/* no device type specified so assume IB for now */
		if (event->status == 28) /* IB_CM_REJ_CONSUMER_DEFINED */
			cm_event = IB_CME_DESTINATION_REJECT_PRIVATE_DATA;
		else {
			cm_event = IB_CME_DESTINATION_REJECT;

			dapl_log(DAPL_DBG_TYPE_WARN,
			    "dapl_cma_active: non-consumer REJ,"
			    " reason=%d, DST %s, %d\n",
			    event->status,
			    inet_ntoa(((struct sockaddr_in *)
			      &conn->cm_id->route.addr.dst_addr)->sin_addr),
			    ntohs(((struct sockaddr_in *)
			      &conn->cm_id->route.addr.dst_addr)->sin_port));
		}
		dapl_evd_connection_callback(conn, cm_event, NULL, conn->ep);
		break;
	}
	case RDMA_CM_EVENT_ESTABLISHED:
                dapl_dbg_log(DAPL_DBG_TYPE_CM,
                     " active_cb: cm_id %d PORT %d CONNECTED to %s!\n",
                     conn->cm_id,
                     ntohs(((struct sockaddr_in *)
                        &conn->cm_id->route.addr.dst_addr)->sin_port),
                     inet_ntoa(((struct sockaddr_in *)
                            &conn->cm_id->route.addr.dst_addr)->sin_addr));

		/* setup local and remote ports for ep query */
		conn->ep->param.remote_port_qual = 
			PORT_TO_SID(rdma_get_dst_port(conn->cm_id));
		conn->ep->param.local_port_qual = 
			PORT_TO_SID(rdma_get_src_port(conn->cm_id));

		dapl_evd_connection_callback(conn, IB_CME_CONNECTED,
					     event->param.conn.private_data, conn->ep);
		break;

	case RDMA_CM_EVENT_DISCONNECTED:
		rdma_disconnect(conn->cm_id); /* required for DREP */
		/* validate EP handle */
		if (!DAPL_BAD_HANDLE(conn->ep, DAPL_MAGIC_EP)) 
			dapl_evd_connection_callback(conn, 
						     IB_CME_DISCONNECTED,
						     NULL, 
						     conn->ep);
		break;
	default:
		dapl_dbg_log(
			DAPL_DBG_TYPE_ERR,
			" dapli_cm_active_cb_handler: Unexpected CM "
			"event %d on ID 0x%p\n", event->event, conn->cm_id);
		break;
	}

	return;
}

static void dapli_cm_passive_cb(struct dapl_cm_id *conn,
			       struct rdma_cm_event *event)
{
	struct dapl_cm_id *new_conn;

	dapl_dbg_log(DAPL_DBG_TYPE_CM, 
		     " passive_cb: conn %p id %d event %d\n",
		     conn, event->id, event->event);

	dapl_os_lock(&conn->lock);
	if (conn->destroy) {
		dapl_os_unlock(&conn->lock);
		return;
	}
	dapl_os_unlock(&conn->lock);

	switch (event->event) {
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		/* create new conn object with new conn_id from event */
		new_conn = dapli_req_recv(conn,event);

		if (new_conn)	
			dapls_cr_callback(new_conn, 
					  IB_CME_CONNECTION_REQUEST_PENDING, 
				 	  event->param.conn.private_data, new_conn->sp);
		break;
	case RDMA_CM_EVENT_UNREACHABLE:
	case RDMA_CM_EVENT_CONNECT_ERROR:
                dapl_log(DAPL_DBG_TYPE_WARN,
                        "dapl_cm_passive: CONN_ERR event=0x%x status=%d %s,"
                        " DST %s,%d\n",
                        event->event, event->status,
                        (event->status == -ETIMEDOUT)?"TIMEOUT":"",
                        inet_ntoa(((struct sockaddr_in *)
                            &conn->cm_id->route.addr.dst_addr)->sin_addr),
                        ntohs(((struct sockaddr_in *)
                            &conn->cm_id->route.addr.dst_addr)->sin_port));

		dapls_cr_callback(conn, IB_CME_DESTINATION_UNREACHABLE,
				 NULL, conn->sp);
		break;

	case RDMA_CM_EVENT_REJECTED:
	{
                /* will alwasys be abnormal NON-consumer from active side */
                dapl_log(DAPL_DBG_TYPE_WARN,
                        "dapl_cm_passive: non-consumer REJ, reason=%d,"
                        " DST %s, %d\n",
                        event->status,
                        inet_ntoa(((struct sockaddr_in *)
                        &conn->cm_id->route.addr.dst_addr)->sin_addr),
                        ntohs(((struct sockaddr_in *)
                        &conn->cm_id->route.addr.dst_addr)->sin_port));

		dapls_cr_callback(conn, IB_CME_DESTINATION_REJECT, 
				  NULL, conn->sp);
		break;
	}
	case RDMA_CM_EVENT_ESTABLISHED:
		dapl_dbg_log(DAPL_DBG_TYPE_CM, 
     		     " passive_cb: cm_id %p PORT %d CONNECTED from %s!\n",
     		     conn->cm_id,
		     ntohs(((struct sockaddr_in *)
			&conn->cm_id->route.addr.src_addr)->sin_port),
		     inet_ntoa(((struct sockaddr_in *)
                        &conn->cm_id->route.addr.dst_addr)->sin_addr));

		dapls_cr_callback(conn, IB_CME_CONNECTED, 
				  NULL, conn->sp);
		
		break;
	case RDMA_CM_EVENT_DISCONNECTED:
		rdma_disconnect(conn->cm_id); /* required for DREP */
		/* validate SP handle context */
		if (!DAPL_BAD_HANDLE(conn->sp, DAPL_MAGIC_PSP) || 
		    !DAPL_BAD_HANDLE(conn->sp, DAPL_MAGIC_RSP))
			dapls_cr_callback(conn, 
					  IB_CME_DISCONNECTED, 
					  NULL, 
					  conn->sp);
		break;
	default:
		dapl_dbg_log(DAPL_DBG_TYPE_ERR, " passive_cb: "
			     "Unexpected CM event %d on ID 0x%p\n",
			     event->event, conn->cm_id);
		break;
	}

	return;
}


/************************ DAPL provider entry points **********************/

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
DAT_RETURN dapls_ib_connect(IN DAT_EP_HANDLE ep_handle,
			    IN DAT_IA_ADDRESS_PTR r_addr,
			    IN DAT_CONN_QUAL r_qual,
			    IN DAT_COUNT p_size,
			    IN void *p_data)
{
	struct dapl_ep *ep_ptr = ep_handle;
	struct dapl_cm_id *conn;
			
	/* Sanity check */
	if (NULL == ep_ptr) 
		return DAT_SUCCESS;

	dapl_dbg_log(DAPL_DBG_TYPE_CM, " connect: rSID %d, pdata %p, ln %d\n", 
		     SID_TO_PORT(r_qual),p_data,p_size);
			
	/* rdma conn and cm_id pre-bound; reference via qp_handle */
	conn = ep_ptr->cm_handle = ep_ptr->qp_handle;

	/* Setup QP/CM parameters and private data in cm_id */
	(void)dapl_os_memzero(&conn->params, sizeof(conn->params));
	conn->params.responder_resources = 
			ep_ptr->param.ep_attr.max_rdma_read_in;
	conn->params.initiator_depth = 
			ep_ptr->param.ep_attr.max_rdma_read_out;
	conn->params.flow_control = 1;
	conn->params.rnr_retry_count = IB_RNR_RETRY_COUNT;
	conn->params.retry_count = IB_RC_RETRY_COUNT;
	if (p_size) {
		dapl_os_memcpy(conn->p_data, p_data, p_size);
		conn->params.private_data = conn->p_data;
		conn->params.private_data_len = p_size;
	}

	/* copy in remote address, need a copy for retry attempts */
	dapl_os_memcpy(&conn->r_addr, r_addr, sizeof(*r_addr));

	/* Resolve remote address, src already bound during QP create */
	((struct sockaddr_in*)&conn->r_addr)->sin_port = SID_TO_PORT(r_qual);
	((struct sockaddr_in*)&conn->r_addr)->sin_family = AF_INET;

	if (rdma_resolve_addr(conn->cm_id, NULL, 
			      (struct sockaddr *)&conn->r_addr, 
			      conn->arp_timeout)) {
                dapl_log(DAPL_DBG_TYPE_ERR,
                         " dapl_cma_connect: rdma_resolve_addr ERR %s\n",
                         strerror(errno));
		return dapl_convert_errno(errno,"ib_connect");
	}

	dapl_dbg_log(DAPL_DBG_TYPE_CM, 
		" connect: resolve_addr: cm_id %p -> %s port %d\n", 
		conn->cm_id, 
		inet_ntoa(((struct sockaddr_in *)&conn->r_addr)->sin_addr),
		ntohs(((struct sockaddr_in*)&conn->r_addr)->sin_port));

	return DAT_SUCCESS;
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
 *
 */
DAT_RETURN
dapls_ib_disconnect(IN DAPL_EP *ep_ptr,
		    IN DAT_CLOSE_FLAGS close_flags)
{
	ib_cm_handle_t conn = ep_ptr->cm_handle;
	int ret;
	
	dapl_dbg_log(DAPL_DBG_TYPE_CM,
		     " disconnect(ep %p, conn %p, id %d flags %x)\n",
		     ep_ptr,conn, (conn?conn->cm_id:0),close_flags);

	if ((conn == IB_INVALID_HANDLE) || (conn->cm_id == NULL))
		return DAT_SUCCESS;

	/* no graceful half-pipe disconnect option */
	ret = rdma_disconnect(conn->cm_id);
	if (ret)
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
			     " disconnect: ID %p ret %d\n", 
			     ep_ptr->cm_handle, ret);
	/* 
	 * DAT event notification occurs from the callback
	 * Don't wait for event, allow consumer option to
	 * to give up and destroy cm_id if event is delayed. 
	 * EP DISCONNECTED state protects against duplicate 
	 * events being queued.
	 */
	return DAT_SUCCESS;
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
dapls_ib_disconnect_clean(IN DAPL_EP *ep_ptr,
			  IN DAT_BOOLEAN active,
			  IN const ib_cm_events_t ib_cm_event)
{
	/* nothing to do */
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
dapls_ib_setup_conn_listener(IN DAPL_IA *ia_ptr,
			     IN DAT_UINT64 ServiceID,
			     IN DAPL_SP *sp_ptr )
{
	DAT_RETURN dat_status = DAT_SUCCESS;
	ib_cm_srvc_handle_t conn;
	DAT_SOCK_ADDR6	addr;	/* local binding address */

	/* Allocate CM and initialize lock */
	if ((conn = dapl_os_alloc(sizeof(*conn))) == NULL) 
		return DAT_INSUFFICIENT_RESOURCES;
	
	dapl_os_memzero(conn, sizeof(*conn));
	dapl_os_lock_init(&conn->lock);
		 
	/* create CM_ID, bind to local device, create QP */
	if (rdma_create_id(g_cm_events, &conn->cm_id, (void*)conn, RDMA_PS_TCP)) {
		dapl_os_free(conn, sizeof(*conn));
		return(dapl_convert_errno(errno,"setup_listener"));
	}
	
	/* open identifies the local device; per DAT specification */
	/* Get family and address then set port to consumer's ServiceID */
	dapl_os_memcpy(&addr, &ia_ptr->hca_ptr->hca_address, sizeof(addr));
	((struct sockaddr_in *)&addr)->sin_port = SID_TO_PORT(ServiceID);


	if (rdma_bind_addr(conn->cm_id,(struct sockaddr *)&addr)) {
		if ((errno == EBUSY) || (errno == EADDRINUSE))
			dat_status = DAT_CONN_QUAL_IN_USE;
		else
			dat_status = 
				dapl_convert_errno(errno,"setup_listener");
		goto bail;
	}

	dapl_dbg_log(DAPL_DBG_TYPE_CM,
		" listen(ia_ptr %p SID %d sp %p conn %p id %d)\n",
		ia_ptr, SID_TO_PORT(ServiceID), 
		sp_ptr, conn, conn->cm_id);

	sp_ptr->cm_srvc_handle = conn;
	conn->sp = sp_ptr;
	conn->hca = ia_ptr->hca_ptr;
	
	dapl_dbg_log(DAPL_DBG_TYPE_EP,
		     " listen(conn=%p cm_id=%d)\n",
		     sp_ptr->cm_srvc_handle,conn->cm_id);
	
	if (rdma_listen(conn->cm_id,0)) { /* max cma backlog */

		if ((errno == EBUSY) || (errno == EADDRINUSE))
			dat_status = DAT_CONN_QUAL_IN_USE;
		else
			dat_status = 
				dapl_convert_errno(errno,"setup_listener");
        	goto bail;
	}

	/* success */ 
	return DAT_SUCCESS;

bail:
	rdma_destroy_id(conn->cm_id);
	dapl_os_free(conn, sizeof(*conn));
	return dat_status;
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
dapls_ib_remove_conn_listener(IN DAPL_IA *ia_ptr, IN DAPL_SP *sp_ptr)
{
	ib_cm_srvc_handle_t conn = sp_ptr->cm_srvc_handle;

	dapl_dbg_log(DAPL_DBG_TYPE_CM,
		     " remove_listen(ia_ptr %p sp_ptr %p cm_ptr %p)\n",
		     ia_ptr, sp_ptr, conn );
	
	if (conn != IB_INVALID_HANDLE) { 
		sp_ptr->cm_srvc_handle = NULL;
        	dapli_destroy_conn(conn);
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
dapls_ib_accept_connection(IN DAT_CR_HANDLE cr_handle,
			   IN DAT_EP_HANDLE ep_handle,
			   IN DAT_COUNT p_size,
			   IN const DAT_PVOID p_data)
{
	DAPL_CR *cr_ptr = (DAPL_CR *)cr_handle;
	DAPL_EP *ep_ptr = (DAPL_EP *)ep_handle;
	DAPL_IA *ia_ptr = ep_ptr->header.owner_ia;
	struct dapl_cm_id *cr_conn = cr_ptr->ib_cm_handle;
	int ret;
	DAT_RETURN dat_status;
	
	dapl_dbg_log(DAPL_DBG_TYPE_CM,
		     " accept(cr %p conn %p, id %p, p_data %p, p_sz=%d)\n",
		     cr_ptr, cr_conn, cr_conn->cm_id, p_data, p_size );

	/* Obtain size of private data structure & contents */
	if (p_size > IB_MAX_REP_PDATA_SIZE) {
		dat_status = DAT_ERROR(DAT_LENGTH_ERROR, DAT_NO_SUBTYPE);
		goto bail;
	}

	if (ep_ptr->qp_state == DAPL_QP_STATE_UNATTACHED) {
		/* 
		 * If we are lazy attaching the QP then we may need to
		 * hook it up here. Typically, we run this code only for
		 * DAT_PSP_PROVIDER_FLAG
		 */
		dat_status = dapls_ib_qp_alloc(ia_ptr, ep_ptr, NULL);
		if (dat_status != DAT_SUCCESS) {
			dapl_log(DAPL_DBG_TYPE_ERR,
				 "dapl_cm_accept: ib_qp_alloc failed: 0x%x\n",
				 dat_status);
			goto bail;
		}
	}

	/* 
	 * Validate device and port in EP cm_id against inbound 
	 * CR cm_id. The pre-allocated EP cm_id is already bound to 
	 * a local device (cm_id and QP) when created. Move the QP
	 * to the new cm_id only if device and port numbers match.
	 */
	if (ep_ptr->qp_handle->cm_id->verbs == cr_conn->cm_id->verbs &&
	    ep_ptr->qp_handle->cm_id->port_num == cr_conn->cm_id->port_num) {
		/* move QP to new cr_conn, remove QP ref in EP cm_id */
		cr_conn->cm_id->qp = ep_ptr->qp_handle->cm_id->qp;
		ep_ptr->qp_handle->cm_id->qp = NULL;
		dapli_destroy_conn(ep_ptr->qp_handle);
	} else {
                dapl_log(DAPL_DBG_TYPE_ERR,
                        " dapl_cma_accept: ERR dev(%p!=%p) or"
                        " port mismatch(%d!=%d)\n",
                        ep_ptr->qp_handle->cm_id->verbs,cr_conn->cm_id->verbs,
                        ntohs(ep_ptr->qp_handle->cm_id->port_num),
                        ntohs(cr_conn->cm_id->port_num));
		dat_status = DAT_INTERNAL_ERROR;
		goto bail;
	}

   	cr_ptr->param.local_ep_handle = ep_handle;
	cr_conn->params.private_data = p_data;
	cr_conn->params.private_data_len = p_size;

	ret = rdma_accept(cr_conn->cm_id, &cr_conn->params);
	if (ret) {
                dapl_log(DAPL_DBG_TYPE_ERR," dapl_cma_accept: ERR %d %s\n",
                         ret, strerror(errno));
		dat_status = dapl_convert_errno(ret, "accept");
		goto bail;
	}

        /* save accepted conn and EP reference */
        ep_ptr->qp_handle = cr_conn;
        ep_ptr->cm_handle = cr_conn;
        cr_conn->ep = ep_ptr;

	/* setup local and remote ports for ep query */
	ep_ptr->param.remote_port_qual = 
		PORT_TO_SID(rdma_get_dst_port(cr_conn->cm_id));
	ep_ptr->param.local_port_qual = 
		PORT_TO_SID(rdma_get_src_port(cr_conn->cm_id));

	return DAT_SUCCESS;
bail:
	rdma_reject(cr_conn->cm_id, NULL, 0);
	dapli_destroy_conn(cr_conn);
	return dat_status; 
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
dapls_ib_reject_connection(IN ib_cm_handle_t cm_handle, IN int reason)
{
    	int ret;

	dapl_dbg_log(DAPL_DBG_TYPE_CM,
		     " reject(cm_handle %p reason %x)\n",
		     cm_handle, reason );

	if (cm_handle == IB_INVALID_HANDLE) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
			     " reject: invalid handle: reason %d\n",
			     reason);
		return DAT_SUCCESS;
	}

	ret = rdma_reject(cm_handle->cm_id, NULL, 0);

	dapli_destroy_conn(cm_handle);
	return dapl_convert_errno(ret, "reject");
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
dapls_ib_cm_remote_addr(IN DAT_HANDLE dat_handle, OUT DAT_SOCK_ADDR6 *raddr)
{
	DAPL_HEADER *header;
	ib_cm_handle_t ib_cm_handle;
	struct rdma_addr *ipaddr;
	
	dapl_dbg_log(DAPL_DBG_TYPE_EP,
		     " remote_addr(cm_handle=%p, r_addr=%p)\n",
		     dat_handle, raddr);

	header = (DAPL_HEADER *)dat_handle;

	if (header->magic == DAPL_MAGIC_EP) 
		ib_cm_handle = ((DAPL_EP *)dat_handle)->cm_handle;
	else if (header->magic == DAPL_MAGIC_CR) 
		ib_cm_handle = ((DAPL_CR *)dat_handle)->ib_cm_handle;
	else 
		return DAT_INVALID_HANDLE;

	/* get remote IP address from cm_id route */
	ipaddr = &ib_cm_handle->cm_id->route.addr;

	dapl_dbg_log(DAPL_DBG_TYPE_CM, 
		" remote_addr: conn %p id %p SRC %x DST %x PORT %d\n", 
		ib_cm_handle, ib_cm_handle->cm_id, 
		ntohl(((struct sockaddr_in *)
			&ipaddr->src_addr)->sin_addr.s_addr),
		ntohl(((struct sockaddr_in *)
			&ipaddr->dst_addr)->sin_addr.s_addr),
		ntohs(((struct sockaddr_in *)
			&ipaddr->dst_addr)->sin_port));

	dapl_os_memcpy(raddr,&ipaddr->dst_addr,sizeof(DAT_SOCK_ADDR));
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
int dapls_ib_private_data_size(IN DAPL_PRIVATE	*prd_ptr,
			       IN DAPL_PDATA_OP conn_op)
{
	int  size;

	switch(conn_op)	{

	case DAPL_PDATA_CONN_REQ:
		size = IB_MAX_REQ_PDATA_SIZE;
		break;
	case DAPL_PDATA_CONN_REP:
		size = IB_MAX_REP_PDATA_SIZE;
		break;
	case DAPL_PDATA_CONN_REJ:
		size = IB_MAX_REJ_PDATA_SIZE;
		break;
	case DAPL_PDATA_CONN_DREQ:
		size = IB_MAX_DREQ_PDATA_SIZE;
		break;
	case DAPL_PDATA_CONN_DREP:
		size = IB_MAX_DREP_PDATA_SIZE;
		break;
	default:
		size = 0;

	} /* end case */

	return size;
}

/*
 * Map all CMA event codes to the DAT equivelent.
 */
#define DAPL_IB_EVENT_CNT	13

static struct ib_cm_event_map
{
	const ib_cm_events_t ib_cm_event;
	DAT_EVENT_NUMBER dat_event_num;
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
	/* 05 */  { IB_CME_CONNECTION_REQUEST_ACKED,
				DAT_CONNECTION_REQUEST_EVENT},
	/* 06 */  { IB_CME_DESTINATION_REJECT,
				DAT_CONNECTION_EVENT_NON_PEER_REJECTED},
	/* 07 */  { IB_CME_DESTINATION_REJECT_PRIVATE_DATA,		
				DAT_CONNECTION_EVENT_PEER_REJECTED},
	/* 08 */  { IB_CME_DESTINATION_UNREACHABLE,	
				DAT_CONNECTION_EVENT_UNREACHABLE},
	/* 09 */  { IB_CME_TOO_MANY_CONNECTION_REQUESTS,
				DAT_CONNECTION_EVENT_NON_PEER_REJECTED},
	/* 10 */  { IB_CME_LOCAL_FAILURE,
				DAT_CONNECTION_EVENT_BROKEN},
	/* 11 */  { IB_CME_BROKEN,
				DAT_CONNECTION_EVENT_BROKEN},
	/* 12 */  { IB_CME_TIMEOUT,	
				DAT_CONNECTION_EVENT_TIMED_OUT},
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
dapls_ib_get_dat_event(IN const ib_cm_events_t ib_cm_event,
		       IN DAT_BOOLEAN active)
{
	DAT_EVENT_NUMBER dat_event_num;
	int i;
	
	active = active;

	dat_event_num = 0;
	for(i = 0; i < DAPL_IB_EVENT_CNT; i++) {
		if (ib_cm_event == ib_cm_event_map[i].ib_cm_event) {
			dat_event_num = ib_cm_event_map[i].dat_event_num;
			break;
		}
	}
	dapl_dbg_log(DAPL_DBG_TYPE_CALLBACK,
		"dapls_ib_get_dat_event: event(%s) ib=0x%x dat=0x%x\n",
		active ? "active" : "passive", ib_cm_event, dat_event_num);

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
dapls_ib_get_cm_event(IN DAT_EVENT_NUMBER dat_event_num)
{
	ib_cm_events_t ib_cm_event;
	int i;

	ib_cm_event = 0;
	for(i = 0; i < DAPL_IB_EVENT_CNT; i++) {
		if (dat_event_num == ib_cm_event_map[i].dat_event_num) {
			ib_cm_event = ib_cm_event_map[i].ib_cm_event;
			break;
		}
	}
	return ib_cm_event;
}


void dapli_cma_event_cb(void)
{
	struct rdma_cm_event *event;

	dapl_dbg_log(DAPL_DBG_TYPE_UTIL, " cm_event()\n");

	/* process one CM event, fairness */
	if(!rdma_get_cm_event(g_cm_events, &event)) {
		struct dapl_cm_id *conn;
				
		/* set proper conn from cm_id context*/
		if (event->event == RDMA_CM_EVENT_CONNECT_REQUEST)
			conn = (struct dapl_cm_id *)event->listen_id->context;
		else
			conn = (struct dapl_cm_id *)event->id->context;

		dapl_dbg_log(DAPL_DBG_TYPE_CM,
			     " cm_event: EVENT=%d ID=%p LID=%p CTX=%p\n",
			     event->event, event->id, event->listen_id, conn);

		switch (event->event) {
		case RDMA_CM_EVENT_ADDR_RESOLVED:
			dapli_addr_resolve(conn);
			break;

		case RDMA_CM_EVENT_ROUTE_RESOLVED:
			dapli_route_resolve(conn);
			break;

		case RDMA_CM_EVENT_ADDR_ERROR:
                        dapl_log(DAPL_DBG_TYPE_WARN,
                                 "dapl_cma_active: CM ADDR ERROR: ->"
                                 " DST %s retry (%d)..\n",
                                 inet_ntoa(((struct sockaddr_in *)
                                        &conn->r_addr)->sin_addr),
                                 conn->arp_retries);

			/* retry address resolution */
			if ((--conn->arp_retries) && 
				(event->status == -ETIMEDOUT)) {
				int ret;
				ret = rdma_resolve_addr(
					conn->cm_id, NULL, 
					(struct sockaddr *)&conn->r_addr, 
					conn->arp_timeout);
				if (!ret) 
					break;
				else { 
					dapl_dbg_log(
						DAPL_DBG_TYPE_WARN,
						" ERROR: rdma_resolve_addr = "
						"%d %s\n", 
						ret,strerror(errno));
				}
			} 
			/* retries exhausted or resolve_addr failed */
                        dapl_log(DAPL_DBG_TYPE_ERR,
                                "dapl_cma_active: ARP_ERR, retries(%d)"
                                " exhausted -> DST %s,%d\n",
                                IB_ARP_RETRY_COUNT,
                                inet_ntoa(((struct sockaddr_in *)
                                &conn->cm_id->route.addr.dst_addr)->sin_addr),
                                ntohs(((struct sockaddr_in *)
                                &conn->cm_id->route.addr.dst_addr)->sin_port));

			dapl_evd_connection_callback(
				conn, IB_CME_DESTINATION_UNREACHABLE, 
				NULL, conn->ep);
			break;


		case RDMA_CM_EVENT_ROUTE_ERROR:
                        dapl_log(DAPL_DBG_TYPE_WARN,
                                 "dapl_cma_active: CM ROUTE ERROR: ->"
                                 " DST %s retry (%d)..\n",
                                 inet_ntoa(((struct sockaddr_in *)
                                        &conn->r_addr)->sin_addr),
                                 conn->route_retries );

			/* retry route resolution */
			if ((--conn->route_retries) && 
				(event->status == -ETIMEDOUT))
				dapli_addr_resolve(conn);
			else {
                            dapl_log(DAPL_DBG_TYPE_ERR,
                               "dapl_cma_active: PATH_RECORD_ERR,"
                               " retries(%d) exhausted, DST %s,%d\n",
                               IB_ROUTE_RETRY_COUNT,
                               inet_ntoa(((struct sockaddr_in *)
                               &conn->cm_id->route.addr.dst_addr)->sin_addr),
                               ntohs(((struct sockaddr_in *)
                               &conn->cm_id->route.addr.dst_addr)->sin_port));

				dapl_evd_connection_callback( conn, 
					IB_CME_DESTINATION_UNREACHABLE, 
					NULL, conn->ep);
			}
			break;
		
		case RDMA_CM_EVENT_DEVICE_REMOVAL:
			dapl_evd_connection_callback(conn, 
						     IB_CME_LOCAL_FAILURE, 
						     NULL, conn->ep);
			break;
		case RDMA_CM_EVENT_CONNECT_REQUEST:
		case RDMA_CM_EVENT_CONNECT_ERROR:
		case RDMA_CM_EVENT_UNREACHABLE:
		case RDMA_CM_EVENT_REJECTED:
		case RDMA_CM_EVENT_ESTABLISHED:
		case RDMA_CM_EVENT_DISCONNECTED:
			/* passive or active */
			if (conn->sp) 
				dapli_cm_passive_cb(conn,event);
			else 
				dapli_cm_active_cb(conn,event);
			break;
		case RDMA_CM_EVENT_CONNECT_RESPONSE:
		default:
			dapl_dbg_log(DAPL_DBG_TYPE_WARN,
			     " cm_event: UNEXPECTED EVENT=%p ID=%p CTX=%p\n",
			     event->event, event->id, 
			     event->id->context);
			break;
		}
		/* ack event, unblocks destroy_cm_id in consumer threads */
		rdma_ack_cm_event(event);
	} 
}

/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 8
 * End:
 */
