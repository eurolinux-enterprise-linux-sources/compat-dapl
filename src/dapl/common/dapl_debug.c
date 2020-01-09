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

#include "dapl_debug.h"
#include "dapl.h"
#if !defined(__KDAPL__)
#include <stdarg.h>
#include <stdlib.h>
#endif /* __KDAPL__ */

DAPL_DBG_TYPE g_dapl_dbg_type;		/* initialized in dapl_init.c */
DAPL_DBG_DEST g_dapl_dbg_dest;		/* initialized in dapl_init.c */

static char *_ptr_host_ = NULL;
static char _hostname_[128];

void dapl_internal_dbg_log ( DAPL_DBG_TYPE type, const char *fmt, ...)
{
    va_list args;

    if ( _ptr_host_ == NULL )
    {
       gethostname(_hostname_, sizeof(_hostname_));
       _ptr_host_ = _hostname_;
    }

    if ( type & g_dapl_dbg_type )
    {
	if ( DAPL_DBG_DEST_STDOUT & g_dapl_dbg_dest )
	{
	    va_start (args, fmt);
            fprintf(stdout, "%s:%d: ", _ptr_host_, getpid());
	    dapl_os_vprintf (fmt, args);
	    va_end (args);
	}

	if ( DAPL_DBG_DEST_SYSLOG & g_dapl_dbg_dest )
	{
	    va_start (args, fmt);
	    dapl_os_syslog(fmt, args);
	    va_end (args);
	}
    }
}

#if defined(DAPL_COUNTERS)
int dapl_dbg_counters[DCNT_NUM_COUNTERS] = { 0 };

/*
 * The order of this list must match exactly with the #defines
 * in dapl_debug.h
 */
char  *dapl_dbg_counter_names[] = {
	"dapl_ep_create",
	"dapl_ep_free",
	"dapl_ep_connect",
	"dapl_ep_disconnect",
	"dapl_ep_post_send",
	"dapl_ep_post_recv",
	"dapl_ep_post_rdma_write",
	"dapl_ep_post_rdma_read",
	"dapl_evd_create",
	"dapl_evd_free",
	"dapl_evd_wait",
	"dapl_evd_blocked",
	"dapl_evd_completion_notify",
	"dapl_evd_dto_callback",
	"dapl_evd_connection_callback",
	"dapl_evd_dequeue",
	"dapl_evd_poll",
	"dapl_evd_found",
	"dapl_evd_not_found",
	"dapls_timer_set",
	"dapls_timer_cancel",
};

void dapl_dump_cntr( int cntr )
{
    int i;

    for ( i = 0; i < DCNT_NUM_COUNTERS; i++ )
    {
        if (( cntr == i ) || ( cntr == DCNT_ALL_COUNTERS ))
        {
            dapl_dbg_log (  DAPL_DBG_TYPE_CNTR,
                            "DAPL Counter: %s = %lu \n",
                            dapl_dbg_counter_names[i],
                            dapl_dbg_counters[i] );
        }
    }
}

#endif /* DAPL_COUNTERS */

