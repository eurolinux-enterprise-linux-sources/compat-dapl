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
 *   Filename:		 dapl_ib_util.h
 *
 *   Author:		 Arlin Davis
 *
 *   Created:		 3/10/2005
 *
 *   Description: 
 *
 *   The uDAPL openib provider - definitions, prototypes,
 *
 ****************************************************************************
 *		   Source Control System Information
 *
 *    $Id: $
 *
 *	Copyright (c) 2005 Intel Corporation.  All rights reserved.
 *
 **************************************************************************/

#ifndef _DAPL_IB_UTIL_H_
#define _DAPL_IB_UTIL_H_

#include <infiniband/verbs.h>
#include <byteswap.h>
#include <rdma/rdma_cma.h>

/* Typedefs to map common DAPL provider types to IB verbs */
typedef	struct dapl_cm_id	*ib_qp_handle_t;
typedef	struct ibv_cq		*ib_cq_handle_t;
typedef	struct ibv_pd		*ib_pd_handle_t;
typedef	struct ibv_mr		*ib_mr_handle_t;
typedef	struct ibv_mw		*ib_mw_handle_t;
typedef	struct ibv_wc		ib_work_completion_t;

/* HCA context type maps to IB verbs  */
typedef	struct ibv_context	*ib_hca_handle_t;
typedef ib_hca_handle_t		dapl_ibal_ca_t;

#define IB_RC_RETRY_COUNT      7
#define IB_RNR_RETRY_COUNT     7
#define IB_CM_RESPONSE_TIMEOUT  23	/* 16 sec */
#define IB_CM_RETRIES           15	/* 240 sec total default */
#define IB_ARP_TIMEOUT		4000	/* 4 sec */
#define IB_ARP_RETRY_COUNT	15	/* 60 sec total */
#define IB_ROUTE_TIMEOUT	4000	/* 4 sec */
#define IB_ROUTE_RETRY_COUNT	15	/* 60 sec total */
#define IB_MAX_AT_RETRY		3

typedef enum {
	IB_CME_CONNECTED,
	IB_CME_DISCONNECTED,
	IB_CME_DISCONNECTED_ON_LINK_DOWN,
	IB_CME_CONNECTION_REQUEST_PENDING,
	IB_CME_CONNECTION_REQUEST_PENDING_PRIVATE_DATA,
	IB_CME_CONNECTION_REQUEST_ACKED,
	IB_CME_DESTINATION_REJECT,
	IB_CME_DESTINATION_REJECT_PRIVATE_DATA,
	IB_CME_DESTINATION_UNREACHABLE,
	IB_CME_TOO_MANY_CONNECTION_REQUESTS,
	IB_CME_LOCAL_FAILURE,
	IB_CME_BROKEN,
	IB_CME_TIMEOUT
} ib_cm_events_t;

/* CQ notifications */
typedef enum
{
	IB_NOTIFY_ON_NEXT_COMP,
	IB_NOTIFY_ON_SOLIC_COMP

} ib_notification_type_t;

/* other mappings */
typedef int			ib_bool_t;
typedef union ibv_gid		GID;
typedef char			*IB_HCA_NAME;
typedef uint16_t		ib_hca_port_t;
typedef uint32_t		ib_comp_handle_t;

#ifdef CQ_WAIT_OBJECT

/* CQ event channel, plus pipe to enable consumer wakeup */
typedef struct _ib_wait_obj_handle
{ 
	struct ibv_comp_channel *events;
	int			pipe[2];

} *ib_wait_obj_handle_t;

#endif

/* Definitions */
#define IB_INVALID_HANDLE	NULL

/* inline send rdma threshold */
#define	INLINE_SEND_IWARP_DEFAULT	64
#define	INLINE_SEND_IB_DEFAULT		200

/* CM private data areas */
#define	IB_MAX_REQ_PDATA_SIZE	48
#define	IB_MAX_REP_PDATA_SIZE	196
#define	IB_MAX_REJ_PDATA_SIZE	148
#define	IB_MAX_DREQ_PDATA_SIZE	220
#define	IB_MAX_DREP_PDATA_SIZE	224

/* DTO OPs, ordered for DAPL ENUM definitions */
#define OP_RDMA_WRITE           IBV_WR_RDMA_WRITE
#define OP_RDMA_WRITE_IMM       IBV_WR_RDMA_WRITE_WITH_IMM
#define OP_SEND                 IBV_WR_SEND
#define OP_SEND_IMM             IBV_WR_SEND_WITH_IMM
#define OP_RDMA_READ            IBV_WR_RDMA_READ
#define OP_COMP_AND_SWAP        IBV_WR_ATOMIC_CMP_AND_SWP
#define OP_FETCH_AND_ADD        IBV_WR_ATOMIC_FETCH_AND_ADD
#define OP_RECEIVE              7   /* internal op */
#define OP_RECEIVE_IMM		8   /* internel op */
#define OP_BIND_MW              9   /* internal op */
#define OP_INVALID		0xff

/* Definitions to map QP state */
#define IB_QP_STATE_RESET	IBV_QPS_RESET
#define IB_QP_STATE_INIT	IBV_QPS_INIT
#define IB_QP_STATE_RTR		IBV_QPS_RTR
#define IB_QP_STATE_RTS		IBV_QPS_RTS
#define IB_QP_STATE_SQD		IBV_QPS_SQD
#define IB_QP_STATE_SQE		IBV_QPS_SQE
#define IB_QP_STATE_ERROR	IBV_QPS_ERR

typedef enum
{
	IB_THREAD_INIT,
	IB_THREAD_CREATE,
	IB_THREAD_RUN,
	IB_THREAD_CANCEL,
	IB_THREAD_EXIT

} ib_thread_state_t;

struct dapl_cm_id {
	DAPL_OS_LOCK			lock;
	int				destroy;
	int				arp_retries;
	int				arp_timeout;
	int				route_retries;
	int				route_timeout;
	int				in_callback;
	struct rdma_cm_id		*cm_id;
	struct dapl_hca			*hca;
	struct dapl_sp			*sp;
	struct dapl_ep			*ep;
	struct rdma_conn_param		params;
	DAT_SOCK_ADDR6			r_addr;
	int				p_len;
	unsigned char			p_data[IB_MAX_DREP_PDATA_SIZE];
};

typedef struct dapl_cm_id	*ib_cm_handle_t;
typedef struct dapl_cm_id	*ib_cm_srvc_handle_t;

/* Operation and state mappings */
typedef enum	ibv_send_flags	ib_send_op_type_t;
typedef	struct	ibv_sge		ib_data_segment_t;
typedef enum	ibv_qp_state	ib_qp_state_t;
typedef	enum	ibv_event_type	ib_async_event_type;
typedef struct	ibv_async_event	ib_error_record_t;

/* Definitions for ibverbs/mthca return codes, should be defined in verbs.h */
/* some are errno and some are -n values */

/**
 * ibv_get_device_name - Return kernel device name
 * ibv_get_device_guid - Return device's node GUID
 * ibv_open_device - Return ibv_context or NULL
 * ibv_close_device - Return 0, (errno?)
 * ibv_get_async_event - Return 0, -1 
 * ibv_alloc_pd - Return ibv_pd, NULL
 * ibv_dealloc_pd - Return 0, errno 
 * ibv_reg_mr - Return ibv_mr, NULL
 * ibv_dereg_mr - Return 0, errno
 * ibv_create_cq - Return ibv_cq, NULL
 * ibv_destroy_cq - Return 0, errno
 * ibv_get_cq_event - Return 0 & ibv_cq/context, int
 * ibv_poll_cq - Return n & ibv_wc, 0 ok, -1 empty, -2 error 
 * ibv_req_notify_cq - Return 0 (void?)
 * ibv_create_qp - Return ibv_qp, NULL
 * ibv_modify_qp - Return 0, errno
 * ibv_destroy_qp - Return 0, errno
 * ibv_post_send - Return 0, -1 & bad_wr
 * ibv_post_recv - Return 0, -1 & bad_wr 
 */

/* async handlers for DTO, CQ, QP, and unafiliated */
typedef void (*ib_async_dto_handler_t)(
    IN    ib_hca_handle_t    ib_hca_handle,
    IN    ib_error_record_t  *err_code,
    IN    void               *context);

typedef void (*ib_async_cq_handler_t)(
    IN    ib_hca_handle_t    ib_hca_handle,
    IN    ib_cq_handle_t     ib_cq_handle,
    IN    ib_error_record_t  *err_code,
    IN    void               *context);

typedef void (*ib_async_qp_handler_t)(
    IN    ib_hca_handle_t    ib_hca_handle,
    IN    ib_qp_handle_t     ib_qp_handle,
    IN    ib_error_record_t  *err_code,
    IN    void               *context);

typedef void (*ib_async_handler_t)(
    IN    ib_hca_handle_t    ib_hca_handle,
    IN    ib_error_record_t  *err_code,
    IN    void               *context);


/* ib_hca_transport_t, specific to this implementation */
typedef struct _ib_hca_transport
{ 
	struct dapl_llist_entry	entry;
	int			destroy;
	struct dapl_hca		*d_hca;
	struct rdma_cm_id 	*cm_id;
	struct ibv_comp_channel *ib_cq;
	ib_cq_handle_t		ib_cq_empty;
	int			max_inline_send;
	ib_async_handler_t	async_unafiliated;
	void			*async_un_ctx;
	ib_async_cq_handler_t	async_cq_error;
	ib_async_dto_handler_t	async_cq;
	ib_async_qp_handler_t	async_qp_error;
	uint8_t			max_cm_timeout;
	uint8_t			max_cm_retries;
	/* device attributes */
	int			max_rdma_rd_in;
	int			max_rdma_rd_out;

} ib_hca_transport_t;

/* provider specfic fields for shared memory support */
typedef uint32_t ib_shm_transport_t;

/* prototypes */
int32_t	dapls_ib_init (void);
int32_t	dapls_ib_release (void);
void dapli_thread(void *arg);
DAT_RETURN  dapli_ib_thread_init(void);
void dapli_ib_thread_destroy(void);
void dapli_cma_event_cb(void);
void dapli_cq_event_cb(struct _ib_hca_transport *hca);
void dapli_async_event_cb(struct _ib_hca_transport *hca);
void dapli_destroy_conn(struct dapl_cm_id *conn);

DAT_RETURN
dapls_modify_qp_state ( IN ib_qp_handle_t	qp_handle,
			IN ib_qp_state_t	qp_state,
			IN struct dapl_cm_id	*conn );

/* inline functions */
STATIC _INLINE_ IB_HCA_NAME dapl_ib_convert_name (IN char *name)
{
	/* use ascii; name of local device */
	return dapl_os_strdup(name);
}

STATIC _INLINE_ void dapl_ib_release_name (IN IB_HCA_NAME name)
{
	return;
}

/*
 *  Convert errno to DAT_RETURN values
 */
STATIC _INLINE_ DAT_RETURN 
dapl_convert_errno( IN int err, IN const char *str )
{
    if (!err)	return DAT_SUCCESS;
    	
    if ((err != EAGAIN) && (err != ETIME) && 
	(err != ETIMEDOUT) && (err != EINTR))
	dapl_log (DAPL_DBG_TYPE_ERR," %s %s\n", str, strerror(err));

    switch( err )
    {
	case EOVERFLOW	: return DAT_LENGTH_ERROR;
	case EACCES	: return DAT_PRIVILEGES_VIOLATION;
	case ENXIO	: 
	case ERANGE	: 
	case EPERM	: return DAT_PROTECTION_VIOLATION;		  
	case EINVAL	:
        case EBADF	: 
	case ENOENT	:
	case ENOTSOCK	: return DAT_INVALID_HANDLE;
    	case EISCONN	: return DAT_INVALID_STATE | DAT_INVALID_STATE_EP_CONNECTED;
    	case ECONNREFUSED : return DAT_INVALID_STATE | DAT_INVALID_STATE_EP_NOTREADY;
	case ETIME	:	    
	case ETIMEDOUT	: return DAT_TIMEOUT_EXPIRED;
    	case ENETUNREACH: return DAT_INVALID_ADDRESS | DAT_INVALID_ADDRESS_UNREACHABLE;
	case EBUSY	: return DAT_PROVIDER_IN_USE;
	case EADDRINUSE	: return DAT_CONN_QUAL_IN_USE;
    	case EALREADY	: return DAT_INVALID_STATE | DAT_INVALID_STATE_EP_ACTCONNPENDING;
        case ENOSPC	: 
	case ENOMEM	:
        case E2BIG	:
        case EDQUOT	: return DAT_INSUFFICIENT_RESOURCES;
        case EAGAIN	: return DAT_QUEUE_EMPTY;
	case EINTR	: return DAT_INTERRUPTED_CALL;
    	case EAFNOSUPPORT : return DAT_INVALID_ADDRESS | DAT_INVALID_ADDRESS_MALFORMED;
    	case EFAULT	: 
	default		: return DAT_INTERNAL_ERROR;
    }
 }

#endif /*  _DAPL_IB_UTIL_H_ */
