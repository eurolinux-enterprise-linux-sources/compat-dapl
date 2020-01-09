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
 * MODULE: dapl_ib_qp.c
 *
 * PURPOSE: QP routines for access to ofa rdma verbs 
 *
 * $Id: $
 **********************************************************************/

#include "dapl.h"
#include "dapl_adapter_util.h"

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
DAT_RETURN
dapls_ib_qp_alloc (
    IN  DAPL_IA		*ia_ptr,
    IN  DAPL_EP		*ep_ptr,
    IN  DAPL_EP		*ep_ctx_ptr )
{
   	DAT_EP_ATTR		*attr;
	DAPL_EVD		*rcv_evd, *req_evd;
	ib_cq_handle_t		rcv_cq, req_cq;
	ib_pd_handle_t		ib_pd_handle;
	struct ibv_qp_init_attr qp_create;
			
	dapl_dbg_log (DAPL_DBG_TYPE_EP,
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
	if ( rcv_evd != DAT_HANDLE_NULL ) 
		rcv_cq = rcv_evd->ib_cq_handle;
	else if (!ia_ptr->hca_ptr->ib_trans.ib_cq_empty) 
		rcv_cq = ia_ptr->hca_ptr->ib_trans.ib_cq_empty;
	else {
		struct ibv_comp_channel *channel = 
					ia_ptr->hca_ptr->ib_trans.ib_cq;
#ifdef CQ_WAIT_OBJECT
		if (rcv_evd->cq_wait_obj_handle)
			channel = rcv_evd->cq_wait_obj_handle;
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

	/* Setup attributes and create qp */
	dapl_os_memzero((void*)&qp_create, sizeof(qp_create));
	qp_create.send_cq = req_cq;
	qp_create.cap.max_send_wr = attr->max_request_dtos;
	qp_create.cap.max_send_sge = attr->max_request_iov;
	qp_create.cap.max_inline_data = ia_ptr->hca_ptr->ib_trans.max_inline_send; 
	qp_create.qp_type = IBV_QPT_RC;
	qp_create.qp_context = (void*)ep_ptr;

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

	ep_ptr->qp_handle = ibv_create_qp( ib_pd_handle, &qp_create);
	if (!ep_ptr->qp_handle) 
		return(dapl_convert_errno(ENOMEM, "create_qp"));
	
	dapl_dbg_log (	DAPL_DBG_TYPE_EP,
			" qp_alloc: qpn %p sq %d,%d rq %d,%d\n", 
			ep_ptr->qp_handle->qp_num,
			qp_create.cap.max_send_wr,qp_create.cap.max_send_sge,
			qp_create.cap.max_recv_wr,qp_create.cap.max_recv_sge );

	/* Setup QP attributes for INIT state on the way out */ 
	if (dapls_modify_qp_state(ep_ptr->qp_handle,
				  IBV_QPS_INIT,
				  NULL )  != DAT_SUCCESS ) {
		ibv_destroy_qp(ep_ptr->qp_handle);		
		ep_ptr->qp_handle = IB_INVALID_HANDLE;
		return DAT_INTERNAL_ERROR;
	}

	ep_ptr->qp_state = IB_QP_STATE_INIT;
	return DAT_SUCCESS;
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
DAT_RETURN
dapls_ib_qp_free (
    IN  DAPL_IA		*ia_ptr,
    IN  DAPL_EP		*ep_ptr )
{
	dapl_dbg_log (DAPL_DBG_TYPE_EP, " qp_free:  ep_ptr %p qp %p\n",	
		      ep_ptr, ep_ptr->qp_handle);

	if (ep_ptr->qp_handle != IB_INVALID_HANDLE) {
		/* force error state to flush queue, then destroy */
		dapls_modify_qp_state(ep_ptr->qp_handle, IBV_QPS_ERR, NULL);
		
		if (ibv_destroy_qp(ep_ptr->qp_handle)) 
			return(dapl_convert_errno(errno,"destroy_qp"));

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
DAT_RETURN
dapls_ib_qp_modify (
    IN  DAPL_IA		*ia_ptr,
    IN  DAPL_EP		*ep_ptr,
    IN  DAT_EP_ATTR	*attr )
{
	struct ibv_qp_attr	qp_attr;
	
	if (ep_ptr->qp_handle == IB_INVALID_HANDLE)
		return DAT_INVALID_PARAMETER;

	/* 
	 * EP state, qp_handle state should be an indication
	 * of current state but the only way to be sure is with
	 * a user mode ibv_query_qp call which is NOT available 
	 */
	
	/* move to error state if necessary */
	if ((ep_ptr->qp_state == IB_QP_STATE_ERROR) &&
	    (ep_ptr->qp_handle->state != IBV_QPS_ERR)) {
		ep_ptr->qp_state = IB_QP_STATE_ERROR;
		return (dapls_modify_qp_state(ep_ptr->qp_handle, 
					      IBV_QPS_ERR, NULL));
	}

	/*
	 * Check if we have the right qp_state to modify attributes
	 */
	if ((ep_ptr->qp_handle->state  != IBV_QPS_RTR ) && 
	    (ep_ptr->qp_handle->state  != IBV_QPS_RTS )) 
		return DAT_INVALID_STATE;

	/* Adjust to current EP attributes */
	dapl_os_memzero((void*)&qp_attr, sizeof(qp_attr));
	qp_attr.cap.max_send_wr = attr->max_request_dtos;
	qp_attr.cap.max_recv_wr = attr->max_recv_dtos;
	qp_attr.cap.max_send_sge = attr->max_request_iov;
	qp_attr.cap.max_recv_sge = attr->max_recv_iov;

	dapl_dbg_log (DAPL_DBG_TYPE_EP,
		      "modify_qp: qp %p sq %d,%d, rq %d,%d\n", 
		      ep_ptr->qp_handle, 
		      qp_attr.cap.max_send_wr, qp_attr.cap.max_send_sge, 
		      qp_attr.cap.max_recv_wr, qp_attr.cap.max_recv_sge );

	if (ibv_modify_qp(ep_ptr->qp_handle, &qp_attr, IBV_QP_CAP)) {
		dapl_dbg_log (DAPL_DBG_TYPE_ERR,
			      "modify_qp: modify ep %p qp %p failed\n",
			      ep_ptr, ep_ptr->qp_handle);
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
void
dapls_ib_reinit_ep (
	IN  DAPL_EP	*ep_ptr)
{
	if ( ep_ptr->qp_handle != IB_INVALID_HANDLE ) {
		/* move to RESET state and then to INIT */
		dapls_modify_qp_state(ep_ptr->qp_handle, IBV_QPS_RESET, 0);
		dapls_modify_qp_state(ep_ptr->qp_handle, IBV_QPS_INIT, 0);
		ep_ptr->qp_state = IB_QP_STATE_INIT;
	}
}

/* 
 * Generic QP modify for init, reset, error, RTS, RTR
 */
DAT_RETURN
dapls_modify_qp_state ( IN ib_qp_handle_t	qp_handle,
			IN ib_qp_state_t	qp_state,
			IN ib_qp_cm_t		*qp_cm )
{
	struct ibv_qp_attr 	qp_attr;
	enum ibv_qp_attr_mask	mask = IBV_QP_STATE;
	DAPL_EP			*ep_ptr = (DAPL_EP*)qp_handle->qp_context;
	DAPL_IA			*ia_ptr = ep_ptr->header.owner_ia;
			
	dapl_os_memzero((void*)&qp_attr, sizeof(qp_attr));
	qp_attr.qp_state = qp_state;

	switch (qp_state) {
		/* additional attributes with RTR and RTS */
		case IBV_QPS_RTR:
		{
			mask |= IBV_QP_AV                 |
				IBV_QP_PATH_MTU           |
				IBV_QP_DEST_QPN           |
				IBV_QP_RQ_PSN             |
				IBV_QP_MAX_DEST_RD_ATOMIC |
				IBV_QP_MIN_RNR_TIMER;

			qp_attr.qp_state = IBV_QPS_RTR;
			qp_attr.dest_qp_num = qp_cm->qpn;
			qp_attr.rq_psn = 1;
			qp_attr.path_mtu = 
				ia_ptr->hca_ptr->ib_trans.mtu;
			qp_attr.max_dest_rd_atomic = 
				ep_ptr->param.ep_attr.max_rdma_read_out;
			qp_attr.min_rnr_timer =
				ia_ptr->hca_ptr->ib_trans.rnr_timer;
			qp_attr.ah_attr.dlid = qp_cm->lid;
			/* global routing */
			if (ia_ptr->hca_ptr->ib_trans.global) {
				qp_attr.ah_attr.is_global = 1;
				qp_attr.ah_attr.grh.dgid = qp_cm->gid;
				qp_attr.ah_attr.grh.hop_limit = 
						ia_ptr->hca_ptr->ib_trans.hop_limit;
				qp_attr.ah_attr.grh.traffic_class = 
						ia_ptr->hca_ptr->ib_trans.tclass;
			}
			qp_attr.ah_attr.sl = 0;
			qp_attr.ah_attr.src_path_bits = 0;
			qp_attr.ah_attr.port_num = qp_cm->port;
			
			dapl_dbg_log (DAPL_DBG_TYPE_EP,
			      " modify_qp_rtr: qpn %x lid %x "
			      "port %x rd_atomic %d\n",
			      qp_cm->qpn, qp_cm->lid, qp_cm->port,
			      qp_attr.max_dest_rd_atomic );

			break;
		}		
		case IBV_QPS_RTS: 
		{
			mask |= IBV_QP_TIMEOUT            |
				IBV_QP_RETRY_CNT          |
				IBV_QP_RNR_RETRY          |
				IBV_QP_SQ_PSN             |
				IBV_QP_MAX_QP_RD_ATOMIC;

			qp_attr.qp_state	= IBV_QPS_RTS;
			qp_attr.timeout		= ia_ptr->hca_ptr->ib_trans.ack_timer;
			qp_attr.retry_cnt	= ia_ptr->hca_ptr->ib_trans.ack_retry;
			qp_attr.rnr_retry	= ia_ptr->hca_ptr->ib_trans.rnr_retry;
			qp_attr.sq_psn		= 1;
			qp_attr.max_rd_atomic	= 
				ep_ptr->param.ep_attr.max_rdma_read_out;

			dapl_dbg_log(DAPL_DBG_TYPE_EP,
				" modify_qp_rts: psn %x rd_atomic %d ack %d "
				" retry %d rnr_retry %d\n",
				qp_attr.sq_psn, qp_attr.max_rd_atomic, 
				qp_attr.timeout, qp_attr.retry_cnt, 
				qp_attr.rnr_retry );
			break;
		}
		case IBV_QPS_INIT: 
		{
			mask |= IBV_QP_PKEY_INDEX	|
				IBV_QP_PORT		|
				IBV_QP_ACCESS_FLAGS;

			qp_attr.pkey_index  = 0;
			qp_attr.port_num = ia_ptr->hca_ptr->port_num;
			qp_attr.qp_access_flags = 
					IBV_ACCESS_LOCAL_WRITE |
					IBV_ACCESS_REMOTE_WRITE |
					IBV_ACCESS_REMOTE_READ |
					IBV_ACCESS_REMOTE_ATOMIC |
					IBV_ACCESS_MW_BIND;
			
			dapl_dbg_log (DAPL_DBG_TYPE_EP,
				" modify_qp_init: pi %x port %x acc %x\n",
				qp_attr.pkey_index, qp_attr.port_num,
				qp_attr.qp_access_flags );
			break;
		}
		default:
			break;
		
	}

	if (ibv_modify_qp(qp_handle, &qp_attr, mask))
		return(dapl_convert_errno(errno,"modify_qp_state"));
	
	return DAT_SUCCESS;
}

/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 8
 * End:
 */
