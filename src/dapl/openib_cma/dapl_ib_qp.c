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

/**********************************************************************
 *
 * MODULE: dapl_det_qp.c
 *
 * PURPOSE: QP routines for access to DET Verbs
 *
 * $Id: $
 **********************************************************************/

#include "dapl.h"
#include "dapl_adapter_util.h"

extern struct rdma_event_channel *g_cm_events;

/*
 * dapl_ib_qp_alloc
 *
 * Alloc a QP
 *
 * Input:
 *	*ep_ptr		pointer to EP INFO
 *	ib_hca_handle	provider HCA handle
 *	ib_pd_handle	provider protection domain handle
 *	cq_recv		provider recv CQ handle
 *	cq_send		provider send CQ handle
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
DAT_RETURN dapls_ib_qp_alloc(IN DAPL_IA *ia_ptr,
			     IN DAPL_EP *ep_ptr,
			     IN DAPL_EP *ep_ctx_ptr)
{
   	DAT_EP_ATTR *attr;
	DAPL_EVD *rcv_evd, *req_evd;
	ib_cq_handle_t rcv_cq, req_cq;
	ib_pd_handle_t ib_pd_handle;
	struct ibv_qp_init_attr qp_create;
	ib_cm_handle_t conn;
	struct rdma_cm_id *cm_id;
			
	dapl_dbg_log(DAPL_DBG_TYPE_EP,
		     " qp_alloc: ia_ptr %p ep_ptr %p ep_ctx_ptr %p\n",
		     ia_ptr, ep_ptr, ep_ctx_ptr);

	attr = &ep_ptr->param.ep_attr;
	ib_pd_handle = ((DAPL_PZ *)ep_ptr->param.pz_handle)->pd_handle;
	rcv_evd	= (DAPL_EVD *) ep_ptr->param.recv_evd_handle;
	req_evd	= (DAPL_EVD *) ep_ptr->param.request_evd_handle;

	/* 
	 * DAT allows usage model of EP's with no EVD's but IB does not. 
	 * Create a CQ with zero entries under the covers to support and 
	 * catch any invalid posting. 
	 */
	if (rcv_evd != DAT_HANDLE_NULL) 
		rcv_cq = rcv_evd->ib_cq_handle;
	else if (!ia_ptr->hca_ptr->ib_trans.ib_cq_empty) 
		rcv_cq = ia_ptr->hca_ptr->ib_trans.ib_cq_empty;
	else {
		struct ibv_comp_channel *channel = 
					ia_ptr->hca_ptr->ib_trans.ib_cq;
#ifdef CQ_WAIT_OBJECT
		if (rcv_evd->cq_wait_obj_handle)
			channel = rcv_evd->cq_wait_obj_handle->events;
#endif
		/* Call IB verbs to create CQ */
		rcv_cq = ibv_create_cq(ia_ptr->hca_ptr->ib_hca_handle,
				       0, NULL, channel, 0);

		if (rcv_cq == IB_INVALID_HANDLE) 
			return(dapl_convert_errno(ENOMEM, "create_cq"));

		ia_ptr->hca_ptr->ib_trans.ib_cq_empty = rcv_cq;
	}
	if (req_evd != DAT_HANDLE_NULL) 
		req_cq = req_evd->ib_cq_handle;
	else 
		req_cq = ia_ptr->hca_ptr->ib_trans.ib_cq_empty;

	/* 
	 * IMPLEMENTATION NOTE:
	 * uDAPL allows consumers to post buffers on the EP after creation
	 * and before a connect request (outbound and inbound). This forces
	 * a binding to a device during the hca_open call and requires the
	 * consumer to predetermine which device to listen on or connect from.
	 * This restriction eliminates any option of listening or connecting 
	 * over multiple devices. uDAPL should add API's to resolve addresses 
	 * and bind to the device at the approriate time (before connect 
	 * and after CR arrives). Discovery should happen at connection time 
	 * based on addressing and not on static configuration during open.
	 */
	
	/* Allocate CM and initialize lock */
	if ((conn = dapl_os_alloc(sizeof(*conn))) == NULL) 
		return(dapl_convert_errno(ENOMEM, "create_cq"));
	
	dapl_os_memzero(conn, sizeof(*conn));
	dapl_os_lock_init(&conn->lock);

	/* create CM_ID, bind to local device, create QP */
	if (rdma_create_id(g_cm_events, &cm_id, (void*)conn, RDMA_PS_TCP)) {
		dapl_os_free(conn, sizeof(*conn));
		return(dapl_convert_errno(errno, "create_qp"));
	}

	/* open identifies the local device; per DAT specification */
	if (rdma_bind_addr(cm_id,
			   (struct sockaddr *)&ia_ptr->hca_ptr->hca_address))
		goto bail;
	
	/* Setup attributes and create qp */
	dapl_os_memzero((void*)&qp_create, sizeof(qp_create));
	qp_create.cap.max_send_wr = attr->max_request_dtos;
	qp_create.cap.max_send_sge = attr->max_request_iov;
	qp_create.cap.max_inline_data = 
		ia_ptr->hca_ptr->ib_trans.max_inline_send; 
	qp_create.send_cq = req_cq;

	/* ibv assumes rcv_cq is never NULL, set to req_cq */
	if (rcv_cq == NULL) {
		qp_create.recv_cq = req_cq;
		qp_create.cap.max_recv_wr = 0;
		qp_create.cap.max_recv_sge = 0;
	} else {
		qp_create.recv_cq = rcv_cq;
		qp_create.cap.max_recv_wr = attr->max_recv_dtos;
		qp_create.cap.max_recv_sge = attr->max_recv_iov;
	}
	qp_create.qp_type = IBV_QPT_RC;
	qp_create.qp_context = (void*)ep_ptr;

	/* Let uCMA transition QP states */
	if (rdma_create_qp(cm_id, ib_pd_handle, &qp_create))
		goto bail; 
		
	conn->cm_id = cm_id;
	conn->ep = ep_ptr;
	conn->hca = ia_ptr->hca_ptr;

	/* setup timers for address and route resolution */
	conn->arp_timeout = dapl_os_get_env_val("DAPL_CM_ARP_TIMEOUT_MS", 
						IB_ARP_TIMEOUT);
	conn->arp_retries = dapl_os_get_env_val("DAPL_CM_ARP_RETRY_COUNT", 
						IB_ARP_RETRY_COUNT);
	conn->route_timeout = dapl_os_get_env_val("DAPL_CM_ROUTE_TIMEOUT_MS", 
						    IB_ROUTE_TIMEOUT);
	conn->route_retries = dapl_os_get_env_val("DAPL_CM_ROUTE_RETRY_COUNT", 
						    IB_ROUTE_RETRY_COUNT);

	/* setup up ep->param to reference the bound local address and port */
	ep_ptr->param.local_ia_address_ptr = &cm_id->route.addr.src_addr;
	ep_ptr->param.local_port_qual = rdma_get_src_port(cm_id);
		
	ep_ptr->qp_handle = conn;
	ep_ptr->qp_state = IB_QP_STATE_INIT;
	
	dapl_dbg_log(DAPL_DBG_TYPE_EP,
		     " qp_alloc: qpn %p sq %d,%d rq %d,%d port=%d\n", 
		     ep_ptr->qp_handle->cm_id->qp->qp_num,
		     qp_create.cap.max_send_wr,qp_create.cap.max_send_sge,
		     qp_create.cap.max_recv_wr,qp_create.cap.max_recv_sge,
		     ep_ptr->param.local_port_qual);
	
	return DAT_SUCCESS;
bail:
	rdma_destroy_id(cm_id);
	dapl_os_free(conn, sizeof(*conn));
	return(dapl_convert_errno(errno, "create_qp"));
}

/*
 * dapl_ib_qp_free
 *
 * Free a QP
 *
 * Input:
 *	ia_handle	IA handle
 *	*ep_ptr		pointer to EP INFO
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *  dapl_convert_errno
 *
 */
DAT_RETURN dapls_ib_qp_free(IN DAPL_IA *ia_ptr, IN DAPL_EP *ep_ptr)
{
	dapl_dbg_log(DAPL_DBG_TYPE_EP, " qp_free:  ep_ptr %p qp %p\n",	
		     ep_ptr, ep_ptr->qp_handle);

	if (ep_ptr->qp_handle != IB_INVALID_HANDLE) {
		/* qp_handle is conn object with reference to cm_id and qp */
		dapli_destroy_conn(ep_ptr->qp_handle); 
		ep_ptr->qp_handle = IB_INVALID_HANDLE;
		ep_ptr->qp_state = IB_QP_STATE_ERROR;
	}
	return DAT_SUCCESS;
}

/*
 * dapl_ib_qp_modify
 *
 * Set the QP to the parameters specified in an EP_PARAM
 *
 * The EP_PARAM structure that is provided has been
 * sanitized such that only non-zero values are valid.
 *
 * Input:
 *	ib_hca_handle		HCA handle
 *	qp_handle		QP handle
 *	ep_attr		        Sanitized EP Params
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
DAT_RETURN dapls_ib_qp_modify(IN DAPL_IA *ia_ptr,
			      IN DAPL_EP *ep_ptr,
			      IN DAT_EP_ATTR *attr)
{
	struct ibv_qp_attr qp_attr;
	
	if (ep_ptr->qp_handle == IB_INVALID_HANDLE)
		return DAT_INVALID_PARAMETER;

	/*
	 * Check if we have the right qp_state to modify attributes
	 */
	if ((ep_ptr->qp_handle->cm_id->qp->state != IBV_QPS_RTR) && 
	    (ep_ptr->qp_handle->cm_id->qp->state != IBV_QPS_RTS)) 
		return DAT_INVALID_STATE;

	/* Adjust to current EP attributes */
	dapl_os_memzero((void*)&qp_attr, sizeof(qp_attr));
	qp_attr.cap.max_send_wr = attr->max_request_dtos;
	qp_attr.cap.max_recv_wr = attr->max_recv_dtos;
	qp_attr.cap.max_send_sge = attr->max_request_iov;
	qp_attr.cap.max_recv_sge = attr->max_recv_iov;

	dapl_dbg_log(DAPL_DBG_TYPE_EP,
		     "modify_qp: qp %p sq %d,%d, rq %d,%d\n", 
		     ep_ptr->qp_handle->cm_id->qp, 
		     qp_attr.cap.max_send_wr, qp_attr.cap.max_send_sge, 
		     qp_attr.cap.max_recv_wr, qp_attr.cap.max_recv_sge);

	if (ibv_modify_qp(ep_ptr->qp_handle->cm_id->qp, &qp_attr, IBV_QP_CAP)) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
			     "modify_qp: modify ep %p qp %p failed\n",
			     ep_ptr, ep_ptr->qp_handle->cm_id->qp);
		return(dapl_convert_errno(errno,"modify_qp_state"));
	}

	return DAT_SUCCESS;
}

/*
 * dapls_ib_reinit_ep
 *
 * Move the QP to INIT state again.
 *
 * Input:
 *	ep_ptr		DAPL_EP
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	void
 *
 */
void dapls_ib_reinit_ep(IN DAPL_EP *ep_ptr)
{
	/* uCMA does not allow reuse of CM_ID, destroy and create new one */
	if (ep_ptr->qp_handle != IB_INVALID_HANDLE) {
		
		/* destroy */
		dapli_destroy_conn(ep_ptr->qp_handle);

		/* create new CM_ID and QP */
		ep_ptr->qp_handle = IB_INVALID_HANDLE;
		dapls_ib_qp_alloc(ep_ptr->header.owner_ia, ep_ptr, ep_ptr);
	}
}


/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 8
 * End:
 */
