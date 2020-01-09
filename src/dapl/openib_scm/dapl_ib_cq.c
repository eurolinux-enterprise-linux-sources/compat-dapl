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
 *   Filename:		 dapl_ib_cq.c
 *
 *   Author:		 Arlin Davis
 *
 *   Created:		 3/10/2005
 *
 *   Description: 
 *
 *   The uDAPL openib provider - completion queue
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
#include "dapl_lmr_util.h"
#include "dapl_evd_util.h"
#include "dapl_ring_buffer_util.h"
#include <sys/poll.h>
#include <signal.h>

int dapli_cq_thread_init(struct dapl_hca *hca_ptr)
{
        DAT_RETURN dat_status;

        dapl_dbg_log(DAPL_DBG_TYPE_UTIL," cq_thread_init(%p)\n", hca_ptr);

        /* create thread to process inbound connect request */
	hca_ptr->ib_trans.cq_state = IB_THREAD_INIT;
        dat_status = dapl_os_thread_create(cq_thread, (void*)hca_ptr, &hca_ptr->ib_trans.cq_thread);
        if (dat_status != DAT_SUCCESS)
        {
                dapl_dbg_log(DAPL_DBG_TYPE_ERR,
                             " cq_thread_init: failed to create thread\n");
                return 1;
        }
	
	/* wait for thread to start */
	while (hca_ptr->ib_trans.cq_state != IB_THREAD_RUN) {
                struct timespec sleep, remain;
                sleep.tv_sec = 0;
                sleep.tv_nsec = 20000000; /* 20 ms */
                dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
                             " cq_thread_init: waiting for cq_thread\n");
                nanosleep (&sleep, &remain);
        }
	dapl_dbg_log(DAPL_DBG_TYPE_UTIL," cq_thread_init(%d) exit\n",getpid());
        return 0;
}

void dapli_cq_thread_destroy(struct dapl_hca *hca_ptr)
{
        dapl_dbg_log(DAPL_DBG_TYPE_UTIL," cq_thread_destroy(%p)\n", hca_ptr);

	if (hca_ptr->ib_trans.cq_state != IB_THREAD_RUN)
		return;

        /* destroy cr_thread and lock */
        hca_ptr->ib_trans.cq_state = IB_THREAD_CANCEL;
        pthread_kill(hca_ptr->ib_trans.cq_thread, SIGUSR1);
        dapl_dbg_log(DAPL_DBG_TYPE_CM," cq_thread_destroy(%p) cancel\n",hca_ptr);
        while (hca_ptr->ib_trans.cq_state != IB_THREAD_EXIT) {
                struct timespec sleep, remain;
                sleep.tv_sec = 0;
                sleep.tv_nsec = 2000000; /* 2 ms */
                dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
                             " cq_thread_destroy: waiting for cq_thread\n");
                nanosleep (&sleep, &remain);
        }
        dapl_dbg_log(DAPL_DBG_TYPE_UTIL," cq_thread_destroy(%d) exit\n",getpid());
}

/* catch the signal */
static void ib_cq_handler(int signum)
{
        return;
}

void cq_thread( void *arg )
{
        struct dapl_hca *hca_ptr = arg;
        struct dapl_evd *evd_ptr;
        struct ibv_cq   *ibv_cq = NULL;
	sigset_t	sigset;

	sigemptyset(&sigset);
        sigaddset(&sigset,SIGUSR1);
        pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);
        signal(SIGUSR1, ib_cq_handler);

	hca_ptr->ib_trans.cq_state = IB_THREAD_RUN;
	
	dapl_dbg_log(DAPL_DBG_TYPE_UTIL," cq_thread: ENTER hca %p\n",hca_ptr);
	
        /* wait on DTO event, or signal to abort */
        while (hca_ptr->ib_trans.cq_state == IB_THREAD_RUN) {
                struct pollfd cq_fd = {
                        .fd      = hca_ptr->ib_trans.ib_cq->fd,
                        .events  = POLLIN,
                        .revents = 0
                };
		if ((poll(&cq_fd, 1, -1) == 1) &&
			(!ibv_get_cq_event(hca_ptr->ib_trans.ib_cq,  
				   &ibv_cq, (void*)&evd_ptr))) {

			if (DAPL_BAD_HANDLE(evd_ptr, DAPL_MAGIC_EVD)) {
				ibv_ack_cq_events(ibv_cq, 1);
				return;
			}

			/* process DTO event via callback */
			dapl_evd_dto_callback ( hca_ptr->ib_hca_handle,
						evd_ptr->ib_cq_handle,
						(void*)evd_ptr );

			ibv_ack_cq_events(ibv_cq, 1);
		} 
        }
        hca_ptr->ib_trans.cq_state = IB_THREAD_EXIT;
        dapl_dbg_log(DAPL_DBG_TYPE_UTIL," cq_thread: EXIT: hca %p \n", hca_ptr);
}


/*
 * Map all verbs DTO completion codes to the DAT equivelent.
 *
 * Not returned by verbs:     DAT_DTO_ERR_PARTIAL_PACKET
 */
static struct ib_status_map
{
    int				ib_status;
    DAT_DTO_COMPLETION_STATUS	dat_status;
} ib_status_map[] = {
	/* 00 */  { IBV_WC_SUCCESS,		DAT_DTO_SUCCESS},
	/* 01 */  { IBV_WC_LOC_LEN_ERR,		DAT_DTO_ERR_LOCAL_LENGTH},
	/* 02 */  { IBV_WC_LOC_QP_OP_ERR,	DAT_DTO_ERR_LOCAL_EP},
	/* 03 */  { IBV_WC_LOC_EEC_OP_ERR,	DAT_DTO_ERR_TRANSPORT},
	/* 04 */  { IBV_WC_LOC_PROT_ERR,	DAT_DTO_ERR_LOCAL_PROTECTION},
	/* 05 */  { IBV_WC_WR_FLUSH_ERR,	DAT_DTO_ERR_FLUSHED},
	/* 06 */  { IBV_WC_MW_BIND_ERR,		DAT_RMR_OPERATION_FAILED},
	/* 07 */  { IBV_WC_BAD_RESP_ERR,	DAT_DTO_ERR_BAD_RESPONSE},
	/* 08 */  { IBV_WC_LOC_ACCESS_ERR,	DAT_DTO_ERR_LOCAL_PROTECTION},
	/* 09 */  { IBV_WC_REM_INV_REQ_ERR,	DAT_DTO_ERR_REMOTE_RESPONDER},
	/* 10 */  { IBV_WC_REM_ACCESS_ERR,	DAT_DTO_ERR_REMOTE_ACCESS},
	/* 11 */  { IBV_WC_REM_OP_ERR,		DAT_DTO_ERR_REMOTE_RESPONDER},
	/* 12 */  { IBV_WC_RETRY_EXC_ERR,	DAT_DTO_ERR_TRANSPORT},
	/* 13 */  { IBV_WC_RNR_RETRY_EXC_ERR,	DAT_DTO_ERR_RECEIVER_NOT_READY},
	/* 14 */  { IBV_WC_LOC_RDD_VIOL_ERR,	DAT_DTO_ERR_LOCAL_PROTECTION},
	/* 15 */  { IBV_WC_REM_INV_RD_REQ_ERR,	DAT_DTO_ERR_REMOTE_RESPONDER},
	/* 16 */  { IBV_WC_REM_ABORT_ERR,	DAT_DTO_ERR_REMOTE_RESPONDER},
	/* 17 */  { IBV_WC_INV_EECN_ERR,	DAT_DTO_ERR_TRANSPORT},
	/* 18 */  { IBV_WC_INV_EEC_STATE_ERR,	DAT_DTO_ERR_TRANSPORT},
	/* 19 */  { IBV_WC_FATAL_ERR,		DAT_DTO_ERR_TRANSPORT},
	/* 20 */  { IBV_WC_RESP_TIMEOUT_ERR,	DAT_DTO_ERR_RECEIVER_NOT_READY},
	/* 21 */  { IBV_WC_GENERAL_ERR,		DAT_DTO_ERR_TRANSPORT},
};

/*
 * dapls_ib_get_dto_status
 *
 * Return the DAT status of a DTO operation
 *
 * Input:
 *	cqe_ptr		pointer to completion queue entry
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	Value from ib_status_map table above
 */

DAT_DTO_COMPLETION_STATUS
dapls_ib_get_dto_status (
	IN ib_work_completion_t		*cqe_ptr)
{
	uint32_t	ib_status;
	int		i;

	ib_status = DAPL_GET_CQE_STATUS (cqe_ptr);

	/*
	* Due to the implementation of verbs completion code, we need to
	* search the table for the correct value rather than assuming
	* linear distribution.
	*/
	for (i = 0; i <= IBV_WC_GENERAL_ERR; i++) {
		if (ib_status == ib_status_map[i].ib_status) {
			if ( ib_status != IBV_WC_SUCCESS ) {
				dapl_dbg_log (DAPL_DBG_TYPE_DTO_COMP_ERR,
	    			" DTO completion ERROR: %d: op %#x\n", 
				ib_status, DAPL_GET_CQE_OPTYPE (cqe_ptr));
			}
			return ib_status_map[i].dat_status;
		}
	}

	dapl_dbg_log (DAPL_DBG_TYPE_DTO_COMP_ERR,
	    		" DTO completion ERROR: %d: op %#x\n", 
			ib_status,
			DAPL_GET_CQE_OPTYPE (cqe_ptr));

	return DAT_DTO_FAILURE;
}
    
DAT_RETURN dapls_ib_get_async_event (
	IN  ib_error_record_t		*err_record,
	OUT DAT_EVENT_NUMBER		*async_event)
{
    DAT_RETURN	dat_status = DAT_SUCCESS;
    int	err_code = err_record->event_type;
    
    switch (err_code) {
	/* OVERFLOW error */
	case IBV_EVENT_CQ_ERR:
	    *async_event = DAT_ASYNC_ERROR_EVD_OVERFLOW;
	    break;
	/* INTERNAL errors */
	case IBV_EVENT_DEVICE_FATAL:
	    *async_event = DAT_ASYNC_ERROR_PROVIDER_INTERNAL_ERROR;
	    break;
	/* CATASTROPHIC errors */
	case IBV_EVENT_PORT_ERR:
	    *async_event = DAT_ASYNC_ERROR_IA_CATASTROPHIC;
	    break;
	/* BROKEN QP error */
	case IBV_EVENT_SQ_DRAINED:
	case IBV_EVENT_QP_FATAL:
	case IBV_EVENT_QP_REQ_ERR:
	case IBV_EVENT_QP_ACCESS_ERR:
	    *async_event = DAT_ASYNC_ERROR_EP_BROKEN;
	    break;

	/* connection completion */
	case IBV_EVENT_COMM_EST:
	    *async_event = DAT_CONNECTION_EVENT_ESTABLISHED;
	    break;

	/* TODO: process HW state changes */
	case IBV_EVENT_PATH_MIG:
	case IBV_EVENT_PATH_MIG_ERR:
	case IBV_EVENT_PORT_ACTIVE:
	case IBV_EVENT_LID_CHANGE:
	case IBV_EVENT_PKEY_CHANGE:
	case IBV_EVENT_SM_CHANGE:
	default:
	    dat_status = DAT_ERROR (DAT_NOT_IMPLEMENTED, 0);
    }
    return dat_status;
}

/*
 * dapl_ib_cq_alloc
 *
 * Alloc a CQ
 *
 * Input:
 *	ia_handle		IA handle
 *	evd_ptr			pointer to EVD struct
 *	cqlen			minimum QLen
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_ib_cq_alloc (
	IN  DAPL_IA		*ia_ptr,
	IN  DAPL_EVD		*evd_ptr,
	IN  DAT_COUNT		*cqlen )
{
	dapl_dbg_log ( DAPL_DBG_TYPE_UTIL, 
		"dapls_ib_cq_alloc: evd %p cqlen=%d \n", evd_ptr, *cqlen );

	struct ibv_comp_channel *channel = ia_ptr->hca_ptr->ib_trans.ib_cq;

#ifdef CQ_WAIT_OBJECT
	if (evd_ptr->cq_wait_obj_handle)
		channel = evd_ptr->cq_wait_obj_handle;
#endif

	/* Call IB verbs to create CQ */
	evd_ptr->ib_cq_handle = ibv_create_cq(ia_ptr->hca_ptr->ib_hca_handle,
					      *cqlen,
					      evd_ptr,
					      channel, 0);
	
	if (evd_ptr->ib_cq_handle == IB_INVALID_HANDLE) 
		return	DAT_INSUFFICIENT_RESOURCES;

	/* arm cq for events */
	dapls_set_cq_notify(ia_ptr, evd_ptr);
	
        /* update with returned cq entry size */
	*cqlen = evd_ptr->ib_cq_handle->cqe;

	dapl_dbg_log ( DAPL_DBG_TYPE_UTIL, 
		"dapls_ib_cq_alloc: new_cq %p cqlen=%d \n", 
		evd_ptr->ib_cq_handle, *cqlen );

	return DAT_SUCCESS;
}


/*
 * dapl_ib_cq_resize
 *
 * Alloc a CQ
 *
 * Input:
 *	ia_handle		IA handle
 *	evd_ptr			pointer to EVD struct
 *	cqlen			minimum QLen
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INVALID_PARAMETER
 *
 */
DAT_RETURN
dapls_ib_cq_resize (
	IN  DAPL_IA	*ia_ptr,
	IN  DAPL_EVD	*evd_ptr,
	IN  DAT_COUNT	*cqlen )
{
	ib_cq_handle_t	new_cq;
	struct ibv_comp_channel *channel = ia_ptr->hca_ptr->ib_trans.ib_cq;

	/* IB verbs doe not support resize. Try to re-create CQ
	 * with new size. Can only be done if QP is not attached. 
	 * destroy EBUSY == QP still attached.
	 */

#ifdef CQ_WAIT_OBJECT
	if (evd_ptr->cq_wait_obj_handle)
		channel = evd_ptr->cq_wait_obj_handle;
#endif

	/* Call IB verbs to create CQ */
	new_cq = ibv_create_cq(ia_ptr->hca_ptr->ib_hca_handle, *cqlen,
			       evd_ptr, channel, 0);

	if (new_cq == IB_INVALID_HANDLE) 
		return	DAT_INSUFFICIENT_RESOURCES;
	
	/* destroy the original and replace if successful */
	if (ibv_destroy_cq(evd_ptr->ib_cq_handle)) {
		ibv_destroy_cq(new_cq);
		return(dapl_convert_errno(errno,"resize_cq"));
	}
		
	/* update EVD with new cq handle and size */
	evd_ptr->ib_cq_handle = new_cq;
	*cqlen = new_cq->cqe;

	/* arm cq for events */
	dapls_set_cq_notify (ia_ptr, evd_ptr);

	return DAT_SUCCESS;
}

/*
 * dapls_ib_cq_free
 *
 * destroy a CQ
 *
 * Input:
 *	ia_handle		IA handle
 *	evd_ptr			pointer to EVD struct
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	DAT_INVALID_PARAMETER
 *
 */
DAT_RETURN dapls_ib_cq_free (
	IN  DAPL_IA		*ia_ptr,
	IN  DAPL_EVD		*evd_ptr)
{
	DAT_EVENT event;
	ib_work_completion_t wc;	

	if (evd_ptr->ib_cq_handle != IB_INVALID_HANDLE) {
		/* pull off CQ and EVD entries and toss */	
        	while (ibv_poll_cq(evd_ptr->ib_cq_handle, 1, &wc) == 1);
		while (dapl_evd_dequeue(evd_ptr, &event) == DAT_SUCCESS);
		if (ibv_destroy_cq(evd_ptr->ib_cq_handle)) 
			return(dapl_convert_errno(errno,"ibv_destroy_cq"));
		evd_ptr->ib_cq_handle = IB_INVALID_HANDLE;
	}
	return DAT_SUCCESS;
}

/*
 * dapls_set_cq_notify
 *
 * Set the CQ notification for next
 *
 * Input:
 *	hca_handl		hca handle
 *	DAPL_EVD		evd handle
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	dapl_convert_errno 
 */
DAT_RETURN dapls_set_cq_notify (
	IN  DAPL_IA	    *ia_ptr,
	IN  DAPL_EVD	    *evd_ptr)
{
	if (ibv_req_notify_cq( evd_ptr->ib_cq_handle, 0 ))
		return(dapl_convert_errno(errno,"notify_cq"));
	else
		return DAT_SUCCESS;
}

/*
 * dapls_ib_completion_notify
 *
 * Set the CQ notification type
 *
 * Input:
 *	hca_handl		hca handle
 *	evd_ptr			evd handle
 *	type			notification type
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 *	dapl_convert_errno
 */
DAT_RETURN dapls_ib_completion_notify (
	IN  ib_hca_handle_t		hca_handle,
	IN  DAPL_EVD			*evd_ptr,
	IN  ib_notification_type_t	type)
{
	if (ibv_req_notify_cq( evd_ptr->ib_cq_handle, type ))
		return(dapl_convert_errno(errno,"notify_cq_type"));
	else
		return DAT_SUCCESS;
}

/*
 * dapls_ib_completion_poll
 *
 * CQ poll for completions
 *
 * Input:
 *	hca_handl		hca handle
 *	evd_ptr			evd handle
 *	wc_ptr			work completion
 *
 * Output:
 * 	none
 *
 * Returns: 
 * 	DAT_SUCCESS
 *	DAT_QUEUE_EMPTY
 *	
 */
DAT_RETURN dapls_ib_completion_poll (
	IN  DAPL_HCA			*hca_ptr,
	IN  DAPL_EVD			*evd_ptr,
	IN  ib_work_completion_t	*wc_ptr)
{
	int	ret;

    	ret = ibv_poll_cq(evd_ptr->ib_cq_handle, 1, wc_ptr);
	if (ret == 1) 
		return	DAT_SUCCESS;
	
	return	DAT_QUEUE_EMPTY;
}

#ifdef CQ_WAIT_OBJECT

/* NEW common wait objects for providers with direct CQ wait objects */
DAT_RETURN
dapls_ib_wait_object_create ( 
		IN DAPL_EVD		*evd_ptr,
		IN ib_wait_obj_handle_t	*p_cq_wait_obj_handle )
{
	dapl_dbg_log (	DAPL_DBG_TYPE_CM, 
			" cq_object_create: (%p,%p)\n", 
			evd_ptr, p_cq_wait_obj_handle );

	/* set cq_wait object to evd_ptr */
	*p_cq_wait_obj_handle = 
		ibv_create_comp_channel(evd_ptr->header.owner_ia->hca_ptr->ib_hca_handle);	
		
	return DAT_SUCCESS;
}

DAT_RETURN
dapls_ib_wait_object_destroy (
	IN ib_wait_obj_handle_t	    p_cq_wait_obj_handle)
{
	dapl_dbg_log (  DAPL_DBG_TYPE_UTIL, 
			" cq_object_destroy: wait_obj=%p\n", 
			p_cq_wait_obj_handle );
	
	ibv_destroy_comp_channel(p_cq_wait_obj_handle);
	
	return DAT_SUCCESS;
}

DAT_RETURN
dapls_ib_wait_object_wakeup (
	IN ib_wait_obj_handle_t		p_cq_wait_obj_handle)
{
	dapl_dbg_log (  DAPL_DBG_TYPE_UTIL, 
			" cq_object_wakeup: wait_obj=%p\n", 
			p_cq_wait_obj_handle );

        /* no wake up mechanism */
	return DAT_SUCCESS;
}

DAT_RETURN
dapls_ib_wait_object_wait (
	IN ib_wait_obj_handle_t	    p_cq_wait_obj_handle,
	IN u_int32_t 		    timeout)
{
	struct dapl_evd	*evd_ptr;
	struct ibv_cq	*ibv_cq = NULL;
	int		status = 0; 
	int		timeout_ms = -1;
	struct pollfd cq_fd = {
			.fd      = p_cq_wait_obj_handle->fd,
			.events  = POLLIN,
			.revents = 0
		};

	dapl_dbg_log ( DAPL_DBG_TYPE_CM, 
			" cq_object_wait: CQ channel %p time %d\n", 
			p_cq_wait_obj_handle, timeout );
	
	/* uDAPL timeout values in usecs */
	if (timeout != DAT_TIMEOUT_INFINITE)
		timeout_ms = timeout/1000;

	status = poll(&cq_fd, 1, timeout_ms);

	/* returned event */
	if (status > 0) {
		if (!ibv_get_cq_event(p_cq_wait_obj_handle, 
				      &ibv_cq, (void*)&evd_ptr)) {
			ibv_ack_cq_events(ibv_cq, 1);
		}
		status = 0;

	/* timeout */
	} else if (status == 0) 
		status = ETIMEDOUT;
	
	dapl_dbg_log (DAPL_DBG_TYPE_CM, 
		      " cq_object_wait: RET evd %p ibv_cq %p %s\n",
		      evd_ptr, ibv_cq,strerror(errno));
	
	return(dapl_convert_errno(status,"cq_wait_object_wait"));
	
}
#endif

/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 8
 * End:
 */

