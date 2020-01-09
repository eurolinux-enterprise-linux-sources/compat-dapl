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
 *   Filename:		 dapl_ib_dto.h
 *
 *   Author:		 Arlin Davis
 *
 *   Created:		 3/10/2005
 *
 *   Description: 
 *
 *   The uDAPL openib provider - DTO operations and CQE macros 
 *
 ****************************************************************************
 *		   Source Control System Information
 *
 *    $Id: $
 *
 *	Copyright (c) 2005 Intel Corporation.  All rights reserved.
 *
 **************************************************************************/
#ifndef _DAPL_IB_DTO_H_
#define _DAPL_IB_DTO_H_

#include "dapl_ib_util.h"

#define	DEFAULT_DS_ENTRIES	8

STATIC _INLINE_ int dapls_cqe_opcode(ib_work_completion_t *cqe_p);

/*
 * dapls_ib_post_recv
 *
 * Provider specific Post RECV function
 */
STATIC _INLINE_ DAT_RETURN 
dapls_ib_post_recv (
	IN  DAPL_EP		*ep_ptr,
	IN  DAPL_COOKIE		*cookie,
	IN  DAT_COUNT		segments,
	IN  DAT_LMR_TRIPLET	*local_iov )
{
	ib_data_segment_t ds_array[DEFAULT_DS_ENTRIES];
	ib_data_segment_t *ds_array_p, *ds_array_start_p = NULL;
	struct ibv_recv_wr wr;
	struct ibv_recv_wr *bad_wr;
	DAT_COUNT i, total_len;
	int ret;
	
	dapl_dbg_log(DAPL_DBG_TYPE_EP,
		     " post_rcv: ep %p cookie %p segs %d l_iov %p\n",
		     ep_ptr, cookie, segments, local_iov);

	if (segments <= DEFAULT_DS_ENTRIES) 
		ds_array_p = ds_array;
	else
		ds_array_start_p = ds_array_p = 
			dapl_os_alloc(segments * sizeof(ib_data_segment_t));

	if (NULL == ds_array_p)
		return (DAT_INSUFFICIENT_RESOURCES);
	
	/* setup work request */
	total_len = 0;
	wr.next = 0;
	wr.num_sge = 0;
	wr.wr_id = (uint64_t)(uintptr_t)cookie;
	wr.sg_list = ds_array_p;

	for (i = 0; i < segments; i++) {
		if (!local_iov[i].segment_length)
			continue;

		ds_array_p->addr = (uint64_t) local_iov[i].virtual_address;
		ds_array_p->length = local_iov[i].segment_length;
		ds_array_p->lkey = local_iov[i].lmr_context;
		
		dapl_dbg_log(DAPL_DBG_TYPE_EP, 
			     " post_rcv: l_key 0x%x va %p len %d\n",
			     ds_array_p->lkey, ds_array_p->addr, 
			     ds_array_p->length );

		total_len += ds_array_p->length;
		wr.num_sge++;
		ds_array_p++;
	}

	if (cookie != NULL) 
		cookie->val.dto.size = total_len;

	ret = ibv_post_recv(ep_ptr->qp_handle->cm_id->qp, &wr, &bad_wr);
	
	if (ds_array_start_p != NULL)
	    dapl_os_free(ds_array_start_p, segments * sizeof(ib_data_segment_t));

	if (ret)
		return( dapl_convert_errno(errno,"ibv_recv") );

	return DAT_SUCCESS;
}


/*
 * dapls_ib_post_send
 *
 * Provider specific Post SEND function
 */
STATIC _INLINE_ DAT_RETURN 
dapls_ib_post_send (
	IN  DAPL_EP			*ep_ptr,
	IN  ib_send_op_type_t		op_type,
	IN  DAPL_COOKIE			*cookie,
	IN  DAT_COUNT			segments,
	IN  DAT_LMR_TRIPLET		*local_iov,
	IN  const DAT_RMR_TRIPLET	*remote_iov,
	IN  DAT_COMPLETION_FLAGS	completion_flags)
{
	dapl_dbg_log(DAPL_DBG_TYPE_EP,
		     " post_snd: ep %p op %d ck %p sgs",
		     "%d l_iov %p r_iov %p f %d\n",
		     ep_ptr, op_type, cookie, segments, local_iov, 
		     remote_iov, completion_flags);

	ib_data_segment_t ds_array[DEFAULT_DS_ENTRIES];
	ib_data_segment_t *ds_array_p, *ds_array_start_p = NULL;
	struct ibv_send_wr wr;
	struct ibv_send_wr *bad_wr;
	ib_hca_transport_t *ibt_ptr = 
		&ep_ptr->header.owner_ia->hca_ptr->ib_trans;
	DAT_COUNT i, total_len;
	int ret;
	
	dapl_dbg_log(DAPL_DBG_TYPE_EP,
		     " post_snd: ep %p cookie %p segs %d l_iov %p\n",
		     ep_ptr, cookie, segments, local_iov);

	if(segments <= DEFAULT_DS_ENTRIES) 
		ds_array_p = ds_array;
	else
		ds_array_start_p = ds_array_p = 
			dapl_os_alloc(segments * sizeof(ib_data_segment_t));

	if (NULL == ds_array_p)
		return (DAT_INSUFFICIENT_RESOURCES);
	
	/* setup the work request */
	wr.next = 0;
	wr.opcode = op_type;
	wr.num_sge = 0;
	wr.send_flags = 0;
	wr.wr_id = (uint64_t)(uintptr_t)cookie;
	wr.sg_list = ds_array_p;
	total_len = 0;

	for (i = 0; i < segments; i++ ) {
		if ( !local_iov[i].segment_length )
			continue;

		ds_array_p->addr = (uint64_t) local_iov[i].virtual_address;
		ds_array_p->length = local_iov[i].segment_length;
		ds_array_p->lkey = local_iov[i].lmr_context;
		
		dapl_dbg_log(DAPL_DBG_TYPE_EP, 
			     " post_snd: lkey 0x%x va %p len %d\n",
			     ds_array_p->lkey, ds_array_p->addr, 
			     ds_array_p->length );

		total_len += ds_array_p->length;
		wr.num_sge++;
		ds_array_p++;
	}

	if (cookie != NULL) 
		cookie->val.dto.size = total_len;
	
	if (wr.num_sge &&
	    (op_type == OP_RDMA_WRITE || op_type == OP_RDMA_READ)) {
		wr.wr.rdma.remote_addr = remote_iov->target_address;
		wr.wr.rdma.rkey = remote_iov->rmr_context;
		dapl_dbg_log(DAPL_DBG_TYPE_EP, 
			     " post_snd_rdma: rkey 0x%x va %#016Lx\n",
			     wr.wr.rdma.rkey, wr.wr.rdma.remote_addr);
	}

	/* inline data for send or write ops */
	if ((total_len <= ibt_ptr->max_inline_send) && 
	   ((op_type == OP_SEND) || (op_type == OP_RDMA_WRITE))) 
		wr.send_flags |= IBV_SEND_INLINE;
	
	/* set completion flags in work request */
	wr.send_flags |= (DAT_COMPLETION_SUPPRESS_FLAG & 
				completion_flags) ? 0 : IBV_SEND_SIGNALED;
	wr.send_flags |= (DAT_COMPLETION_BARRIER_FENCE_FLAG & 
				completion_flags) ? IBV_SEND_FENCE : 0;
	wr.send_flags |= (DAT_COMPLETION_SOLICITED_WAIT_FLAG & 
				completion_flags) ? IBV_SEND_SOLICITED : 0;

	dapl_dbg_log(DAPL_DBG_TYPE_EP, 
		     " post_snd: op 0x%x flags 0x%x sglist %p, %d\n", 
		     wr.opcode, wr.send_flags, wr.sg_list, wr.num_sge);

	ret = ibv_post_send(ep_ptr->qp_handle->cm_id->qp, &wr, &bad_wr);

	if (ds_array_start_p != NULL)
	    dapl_os_free(ds_array_start_p, segments * sizeof(ib_data_segment_t));

	if (ret)
		return( dapl_convert_errno(errno,"ibv_send") );

	dapl_dbg_log(DAPL_DBG_TYPE_EP," post_snd: returned\n");
	return DAT_SUCCESS;
}

STATIC _INLINE_ DAT_RETURN 
dapls_ib_optional_prv_dat(
	IN  DAPL_CR		*cr_ptr,
	IN  const void		*event_data,
	OUT   DAPL_CR		**cr_pp)
{
    return DAT_SUCCESS;
}

STATIC _INLINE_ int dapls_cqe_opcode(ib_work_completion_t *cqe_p)
{
	switch (cqe_p->opcode) {
	case IBV_WC_SEND:
		return (OP_SEND);
	case IBV_WC_RDMA_WRITE:
		return (OP_RDMA_WRITE);
	case IBV_WC_RDMA_READ:
		return (OP_RDMA_READ);
	case IBV_WC_COMP_SWAP:
		return (OP_COMP_AND_SWAP);
	case IBV_WC_FETCH_ADD:
		return (OP_FETCH_AND_ADD);
	case IBV_WC_BIND_MW:
		return (OP_BIND_MW);
	case IBV_WC_RECV:
		return (OP_RECEIVE);
	case IBV_WC_RECV_RDMA_WITH_IMM:
		return (OP_RECEIVE_IMM);
	default:
		return (OP_INVALID);
	}
}

#define DAPL_GET_CQE_OPTYPE(cqe_p) dapls_cqe_opcode(cqe_p)
#define DAPL_GET_CQE_WRID(cqe_p) ((ib_work_completion_t*)cqe_p)->wr_id
#define DAPL_GET_CQE_STATUS(cqe_p) ((ib_work_completion_t*)cqe_p)->status
#define DAPL_GET_CQE_VENDOR_ERR(cqe_p) ((ib_work_completion_t*)cqe_p)->vendor_err
#define DAPL_GET_CQE_BYTESNUM(cqe_p) ((ib_work_completion_t*)cqe_p)->byte_len
#define DAPL_GET_CQE_IMMED_DATA(cqe_p) ((ib_work_completion_t*)cqe_p)->imm_data

STATIC _INLINE_ char * dapls_dto_op_str(int op)
{
    static char *optable[] =
    {
        "OP_RDMA_WRITE",
        "OP_RDMA_WRITE_IMM",
        "OP_SEND",
        "OP_SEND_IMM",
        "OP_RDMA_READ",
        "OP_COMP_AND_SWAP",
        "OP_FETCH_AND_ADD",
        "OP_RECEIVE",
        "OP_RECEIVE_IMM",
        "OP_BIND_MW"
    };
    return ((op < 0 || op > 9) ? "Invalid CQE OP?" : optable[op]);
}

static _INLINE_ char *
dapls_cqe_op_str(IN ib_work_completion_t *cqe_ptr)
{
    return dapls_dto_op_str(DAPL_GET_CQE_OPTYPE(cqe_ptr));
}

#define DAPL_GET_CQE_OP_STR(cqe) dapls_cqe_op_str(cqe)

#endif	/*  _DAPL_IB_DTO_H_ */
