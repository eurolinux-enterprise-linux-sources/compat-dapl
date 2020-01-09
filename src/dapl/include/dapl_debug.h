/*
 * Copyright (c) 2002-2003, Network Appliance, Inc. All rights reserved.
 *
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
 * MODULE: dapl_debug.h
 *
 * PURPOSE: defines common deuggging flags & data for the DAPL reference
 * implemenation
 *
 * Description:
 *
 *
 * $Id:$
 **********************************************************************/

#ifndef _DAPL_DEBUG_H_
#define _DAPL_DEBUG_H_

/*
 * Debug level switches
 *
 * Use these bits to enable various tracing/debug options. Each bit
 * represents debugging in a particular subsystem or area of the code.
 *
 * The ERR bit should always be on unless someone disables it for a
 * reason: The ERR flag is used sparingly and will print useful
 * information if it fires.
 */
typedef enum
{
    DAPL_DBG_TYPE_ERR		= 0x0001,
    DAPL_DBG_TYPE_WARN	  	= 0x0002,
    DAPL_DBG_TYPE_EVD	  	= 0x0004,
    DAPL_DBG_TYPE_CM		= 0x0008,
    DAPL_DBG_TYPE_EP		= 0x0010,
    DAPL_DBG_TYPE_UTIL	  	= 0x0020,
    DAPL_DBG_TYPE_CALLBACK	= 0x0040,
    DAPL_DBG_TYPE_DTO_COMP_ERR	= 0x0080,
    DAPL_DBG_TYPE_API	  	= 0x0100,
    DAPL_DBG_TYPE_RTN	  	= 0x0200,
    DAPL_DBG_TYPE_EXCEPTION	= 0x0400,
    DAPL_DBG_TYPE_SRQ		= 0x0800,
    DAPL_DBG_TYPE_CNTR  	= 0x1000

} DAPL_DBG_TYPE;

typedef enum
{
    DAPL_DBG_DEST_STDOUT  	= 0x0001,
    DAPL_DBG_DEST_SYSLOG  	= 0x0002,
} DAPL_DBG_DEST;

extern DAPL_DBG_TYPE    g_dapl_dbg_type;
extern DAPL_DBG_DEST    g_dapl_dbg_dest;

extern void dapl_internal_dbg_log(DAPL_DBG_TYPE type,  const char *fmt,  ...);

#define dapl_log g_dapl_dbg_type==0 ? (void) 1 : dapl_internal_dbg_log

#if defined(DAPL_DBG)

#define dapl_dbg_log g_dapl_dbg_type==0 ? (void) 1 : dapl_internal_dbg_log

#else  /* !DAPL_DBG */

#define dapl_dbg_log(...)

#endif /* !DAPL_DBG */

/*
 * Counters
 */
#define DCNT_EP_CREATE			0
#define DCNT_EP_FREE			1
#define DCNT_EP_CONNECT			2
#define DCNT_EP_DISCONNECT		3
#define DCNT_POST_SEND			4
#define DCNT_POST_RECV			5
#define DCNT_POST_RDMA_WRITE		6
#define DCNT_POST_RDMA_READ		7
#define DCNT_EVD_CREATE			8
#define DCNT_EVD_FREE			9
#define DCNT_EVD_WAIT			10
#define DCNT_EVD_WAIT_BLOCKED		11
#define DCNT_EVD_WAIT_CMP_NTFY		12
#define DCNT_EVD_DTO_CALLBACK		13
#define DCNT_EVD_CONN_CALLBACK		14
#define DCNT_EVD_DEQUEUE		15
#define DCNT_EVD_DEQUEUE_POLL		16
#define DCNT_EVD_DEQUEUE_FOUND		17
#define DCNT_EVD_DEQUEUE_NOT_FOUND	18
#define DCNT_TIMER_SET			19
#define DCNT_TIMER_CANCEL		20
#define DCNT_NUM_COUNTERS		21
#define DCNT_ALL_COUNTERS               DCNT_NUM_COUNTERS

#if defined(DAPL_COUNTERS)

extern void dapl_dump_cntr( int cntr );
extern int dapl_dbg_counters[];

#define DAPL_CNTR(cntr)         dapl_os_atomic_inc (&dapl_dbg_counters[cntr]);
#define DAPL_DUMP_CNTR(cntr)    dapl_dump_cntr( cntr );
#define DAPL_COUNTERS_INIT()

#else

#define DAPL_CNTR(cntr)
#define DAPL_DUMP_CNTR(cntr) 
#define DAPL_COUNTERS_INIT()

#endif /* DAPL_COUNTERS */


#endif /* _DAPL_DEBUG_H_ */
