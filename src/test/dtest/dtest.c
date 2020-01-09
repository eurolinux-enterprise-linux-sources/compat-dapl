/*
 * Copyright (c) 2005 Intel Corporation.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * $Id: $
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <getopt.h>
#include <inttypes.h>
#include <unistd.h>

#ifndef DAPL_PROVIDER
#define DAPL_PROVIDER "OpenIB-cma"
#endif

#define F64x "%"PRIx64""
#define MAX_POLLING_CNT 50000
#define MAX_RDMA_RD    4
#define MAX_PROCS      1000

/* Header files needed for DAT/uDAPL */
#include    "dat/udat.h"

/* definitions */
#define SERVER_CONN_QUAL  45248
#define DTO_TIMEOUT       (1000*1000*5)
#define DTO_FLUSH_TIMEOUT (1000*1000*2)
#define CONN_TIMEOUT      (1000*1000*10)
#define SERVER_TIMEOUT    (1000*1000*20)
#define RDMA_BUFFER_SIZE  (64)

/* Global DAT vars */
static DAT_IA_HANDLE      h_ia = DAT_HANDLE_NULL;
static DAT_PZ_HANDLE      h_pz = DAT_HANDLE_NULL;
static DAT_EP_HANDLE      h_ep = DAT_HANDLE_NULL;
static DAT_PSP_HANDLE     h_psp = DAT_HANDLE_NULL;
static DAT_CR_HANDLE      h_cr = DAT_HANDLE_NULL;

static DAT_EVD_HANDLE     h_async_evd = DAT_HANDLE_NULL;
static DAT_EVD_HANDLE     h_dto_req_evd = DAT_HANDLE_NULL;
static DAT_EVD_HANDLE     h_dto_rcv_evd = DAT_HANDLE_NULL;
static DAT_EVD_HANDLE     h_cr_evd = DAT_HANDLE_NULL;
static DAT_EVD_HANDLE     h_conn_evd = DAT_HANDLE_NULL;
static DAT_CNO_HANDLE     h_dto_cno = DAT_HANDLE_NULL;

/* RDMA buffers */
static DAT_LMR_HANDLE     h_lmr_send = DAT_HANDLE_NULL;
static DAT_LMR_HANDLE     h_lmr_recv = DAT_HANDLE_NULL;
static DAT_LMR_CONTEXT    lmr_context_send;
static DAT_LMR_CONTEXT    lmr_context_recv;
static DAT_RMR_CONTEXT    rmr_context_send;
static DAT_RMR_CONTEXT    rmr_context_recv;
static DAT_VLEN           registered_size_send;
static DAT_VLEN           registered_size_recv;
static DAT_VADDR          registered_addr_send;
static DAT_VADDR          registered_addr_recv;

/* Initial msg receive buf, RMR exchange, and Rdma-write notification */
#define MSG_BUF_COUNT     3
#define MSG_IOV_COUNT     2
static DAT_RMR_TRIPLET    rmr_recv_msg[MSG_BUF_COUNT];
static DAT_LMR_HANDLE     h_lmr_recv_msg = DAT_HANDLE_NULL;
static DAT_LMR_CONTEXT    lmr_context_recv_msg;
static DAT_RMR_CONTEXT    rmr_context_recv_msg;
static DAT_VLEN           registered_size_recv_msg;
static DAT_VADDR          registered_addr_recv_msg;

/* message send buffer */
static DAT_RMR_TRIPLET    rmr_send_msg;
static DAT_LMR_HANDLE     h_lmr_send_msg = DAT_HANDLE_NULL;
static DAT_LMR_CONTEXT    lmr_context_send_msg;
static DAT_RMR_CONTEXT    rmr_context_send_msg;
static DAT_VLEN           registered_size_send_msg;
static DAT_VADDR          registered_addr_send_msg;
static DAT_EP_ATTR        ep_attr;
static DAT_EP_PARAM       ep_param;
char                      hostname[256] = {0};
char                      provider[256] = DAPL_PROVIDER;
char			  addr_str[INET_ADDRSTRLEN];

/* rdma pointers */
char   *rbuf = NULL;
char   *sbuf = NULL;
int     status;

/* timers */
double start,stop,total_us,total_sec;
struct {
    double  total;
    double  open;
    double  reg;
    double  unreg;
    double  pzc;
    double  pzf;
    double  evdc;
    double  evdf;
    double  cnoc;
    double  cnof;
    double  epc;
    double  epf;
    double  rdma_wr;
    double  rdma_rd[MAX_RDMA_RD];
    double  rdma_rd_total;
    double  rtt;
    double  close;
} time;

/* defaults */
static int  connected=0;
static int  burst=10;
static int  server=1;
static int  verbose=0;
static int  polling=0;
static int  poll_count=0;
static int  rdma_wr_poll_count=0;
static int  rdma_rd_poll_count[MAX_RDMA_RD]={0};
static int  delay=0;
static int  buf_len=RDMA_BUFFER_SIZE;
static int  use_cno=0;
static int  recv_msg_index=0;
static int  burst_msg_posted=0;
static int  burst_msg_index=0;

/* forward prototypes */
const char * DT_RetToString (DAT_RETURN ret_value);
const char * DT_EventToSTr (DAT_EVENT_NUMBER event_code);
void       print_usage();
double     get_time();
void       init_data();

DAT_RETURN     send_msg(   void                    *data,
                           DAT_COUNT               size,
                           DAT_LMR_CONTEXT         context,
                           DAT_DTO_COOKIE          cookie,
                           DAT_COMPLETION_FLAGS    flags );

DAT_RETURN     connect_ep( char *hostname, int conn_id );
void           disconnect_ep( void );
DAT_RETURN     register_rdma_memory( void );
DAT_RETURN     unregister_rdma_memory( void );
DAT_RETURN     create_events( void );
DAT_RETURN     destroy_events(void);
DAT_RETURN     do_rdma_write_with_msg( void );
DAT_RETURN     do_rdma_read_with_msg( void );
DAT_RETURN     do_ping_pong_msg( void );

#define LOGPRINTF(_format, _aa...) \
       if (verbose)               \
           printf(_format, ##_aa)
int
main(int argc, char **argv)
{
       int i,c;
       DAT_RETURN  ret;

       /* parse arguments */
       while ((c = getopt(argc, argv, "scvpb:d:B:h:P:")) != -1)
       {
               switch(c)
               {
                       case 's':
                               server = 1;
                               fflush(stdout);
                               break;
                       case 'c':
                               use_cno = 1;
                               printf("%d Creating CNO for DTO EVD's\n",getpid());
                               fflush(stdout);
                               break;
                       case 'v':
                               verbose = 1;
                               printf("%d Verbose\n",getpid());
                               fflush(stdout);
                               break;
                       case 'p':
                               polling = 1;
                               printf("%d Polling\n",getpid());
                               fflush(stdout);
                               break;
                       case 'B':
                               burst = atoi(optarg);
                               break;
                       case 'd':
                               delay = atoi(optarg);
                               break;
                       case 'b':
                               buf_len = atoi(optarg);
                               break;
                       case 'h':
                               server = 0;
                               strcpy (hostname, optarg);
                               break;
                       case 'P':
                               strcpy (provider, optarg);
                               break;
                       default:
                               print_usage();
                               exit(-12);
               }
       }

       if (!server) {
               printf("%d Running as client - %s\n",getpid(),provider); fflush(stdout);
       } else {
               printf("%d Running as server - %s\n",getpid(),provider); fflush(stdout);
       }

       /* allocate send and receive buffers */
       if (((rbuf = malloc(buf_len*burst)) == NULL) ||
           ((sbuf = malloc(buf_len*burst)) == NULL)) {
               perror("malloc");
               exit(1);
       }
       memset( &time, 0, sizeof(time) );
       LOGPRINTF("%d Allocated RDMA buffers (r:%p,s:%p) len %d \n",
                       getpid(), rbuf, sbuf, buf_len);

       /* dat_ia_open, dat_pz_create */
       h_async_evd = DAT_HANDLE_NULL;
       start = get_time();
       ret = dat_ia_open( provider, 8, &h_async_evd, &h_ia );
       stop = get_time();
       time.open += ((stop - start)*1.0e6);
       if(ret != DAT_SUCCESS) {
               fprintf(stderr, "%d: Error Adaptor open: %s\n",
                       getpid(),DT_RetToString(ret));
               exit(1);
       } else
               LOGPRINTF("%d Opened Interface Adaptor\n",getpid());

       /* Create Protection Zone */
       start = get_time();
       LOGPRINTF("%d Create Protection Zone\n",getpid());
       ret = dat_pz_create(h_ia, &h_pz);
       stop = get_time();
       time.pzc += ((stop - start)*1.0e6);
       if(ret != DAT_SUCCESS) {
               fprintf(stderr,
                       "%d Error creating Protection Zone: %s\n",
                       getpid(),DT_RetToString(ret));
               exit(1);
       } else
               LOGPRINTF("%d Created Protection Zone\n",getpid());

       /* Register memory */
       LOGPRINTF("%d Register RDMA memory\n", getpid());
       ret = register_rdma_memory();
       if(ret != DAT_SUCCESS) {
               fprintf(stderr, "%d Error creating events: %s\n",
                               getpid(),DT_RetToString(ret));
               goto cleanup;
       } else
               LOGPRINTF("%d Register RDMA memory done\n", getpid());

       LOGPRINTF("%d Create events\n", getpid());
       ret = create_events();
       if(ret != DAT_SUCCESS) {
               fprintf(stderr, "%d Error creating events: %s\n",
                       getpid(),DT_RetToString(ret));
               goto cleanup;
       } else {
               LOGPRINTF("%d Create events done\n", getpid());
       }

       /* create EP */
       memset( &ep_attr, 0, sizeof(ep_attr) );
       ep_attr.service_type                = DAT_SERVICE_TYPE_RC;
       ep_attr.max_rdma_size               = 0x10000;
       ep_attr.qos                         = 0;
       ep_attr.recv_completion_flags       = 0;
       ep_attr.max_recv_dtos               = MSG_BUF_COUNT + (burst*3);
       ep_attr.max_request_dtos            = MSG_BUF_COUNT + (burst*3) + MAX_RDMA_RD; 
       ep_attr.max_recv_iov                = MSG_IOV_COUNT;
       ep_attr.max_request_iov             = MSG_IOV_COUNT;
       ep_attr.max_rdma_read_in            = MAX_RDMA_RD;
       ep_attr.max_rdma_read_out           = MAX_RDMA_RD;
       ep_attr.request_completion_flags    = DAT_COMPLETION_DEFAULT_FLAG;
       ep_attr.ep_transport_specific_count = 0;
       ep_attr.ep_transport_specific       = NULL;
       ep_attr.ep_provider_specific_count  = 0;
       ep_attr.ep_provider_specific        = NULL;

       start = get_time();
       ret = dat_ep_create( h_ia, h_pz, h_dto_rcv_evd, 
			    h_dto_req_evd, h_conn_evd, &ep_attr, &h_ep );
       stop = get_time();
       time.epc += ((stop - start)*1.0e6);
       time.total += time.epc;
       if(ret != DAT_SUCCESS) {
               fprintf(stderr, "%d Error dat_ep_create: %s\n",
                       getpid(),DT_RetToString(ret));
               goto cleanup;
       } else
               LOGPRINTF("%d EP created %p \n", getpid(), h_ep);

       /*
        * register message buffers, establish connection, and
        * exchange DMA RMR information info via messages
        */
       ret = connect_ep( hostname, SERVER_CONN_QUAL );
       if(ret != DAT_SUCCESS) {
               fprintf(stderr, "%d Error connect_ep: %s\n",
                               getpid(),DT_RetToString(ret));
               goto cleanup;
       } else
               LOGPRINTF("%d connect_ep complete\n", getpid());

        /* query EP for local and remote address information, print */
	ret = dat_ep_query( h_ep, DAT_EP_FIELD_ALL, &ep_param );
	if(ret != DAT_SUCCESS) {
               fprintf(stderr, "%d Error dat_ep_query: %s\n",
                       getpid(),DT_RetToString(ret));
               goto cleanup;
       } else
               LOGPRINTF("%d EP queried %p \n", getpid(), h_ep);

       inet_ntop(AF_INET, 
	         &((struct sockaddr_in *)ep_param.local_ia_address_ptr)->sin_addr, 
		 addr_str, sizeof(addr_str));
       printf("\n%d Query EP: LOCAL addr %s port "F64x"\n", getpid(), 
	       addr_str, ep_param.local_port_qual);
       inet_ntop(AF_INET, 
	         &((struct sockaddr_in *)ep_param.remote_ia_address_ptr)->sin_addr, 
		 addr_str, sizeof(addr_str));
       printf("%d Query EP: REMOTE addr %s port "F64x"\n", getpid(), 
	       addr_str, ep_param.remote_port_qual);
       fflush(stdout);

       /*********** RDMA write data *************/
       ret = do_rdma_write_with_msg();
       if(ret != DAT_SUCCESS) {
               fprintf(stderr, "%d Error do_rdma_write_with_msg: %s\n",
                               getpid(),DT_RetToString(ret));
               goto cleanup;
       } else
               LOGPRINTF("%d do_rdma_write_with_msg complete\n", getpid());

       /*********** RDMA read data *************/
       ret = do_rdma_read_with_msg();
       if(ret != DAT_SUCCESS) {
               fprintf(stderr, "%d Error do_rdma_read_with_msg: %s\n",
                               getpid(),DT_RetToString(ret));
               goto cleanup;
       } else
               LOGPRINTF("%d do_rdma_read_with_msg complete\n", getpid());

       /*********** PING PING messages ************/
       ret = do_ping_pong_msg();
       if(ret != DAT_SUCCESS) {
               fprintf(stderr, "%d Error do_ping_pong_msg: %s\n",
                               getpid(),DT_RetToString(ret));
               goto cleanup;
       } else
               LOGPRINTF("%d do_ping_pong_msg complete\n", getpid());

cleanup:
       /* disconnect and free EP resources */
       if ( h_ep != DAT_HANDLE_NULL ) {
               /* unregister message buffers and tear down connection */
               LOGPRINTF("%d Disconnect and Free EP %p \n",getpid(),h_ep);
               disconnect_ep();
       }

       /* free EP */
       LOGPRINTF("%d Free EP %p \n",getpid(),h_ep);
       start = get_time();
       ret = dat_ep_free( h_ep );
       stop = get_time();
       time.epf += ((stop - start)*1.0e6);
       time.total += time.epf;
       if(ret != DAT_SUCCESS) {
               fprintf(stderr, "%d Error freeing EP: %s\n",
                       getpid(), DT_RetToString(ret));
       } else {
               LOGPRINTF("%d Freed EP\n",getpid());
               h_ep = DAT_HANDLE_NULL;
       }

       /* free EVDs */
       LOGPRINTF("%d destroy events\n", getpid());
       ret = destroy_events();
       if(ret != DAT_SUCCESS)
               fprintf(stderr, "%d Error destroy_events: %s\n",
                       getpid(),DT_RetToString(ret));
       else
               LOGPRINTF("%d destroy events done\n", getpid());


       ret = unregister_rdma_memory();
       LOGPRINTF("%d unregister_rdma_memory \n", getpid());
       if(ret != DAT_SUCCESS)
               fprintf(stderr, "%d Error unregister_rdma_memory: %s\n",
                       getpid(),DT_RetToString(ret));
       else
               LOGPRINTF("%d unregister_rdma_memory done\n", getpid());

       /* Free protection domain */
       LOGPRINTF("%d Freeing pz\n",getpid());
       start = get_time();
       ret = dat_pz_free( h_pz );
       stop = get_time();
       time.pzf += ((stop - start)*1.0e6);
       if (ret != DAT_SUCCESS) {
               fprintf(stderr, "%d Error freeing PZ: %s\n",
               getpid(), DT_RetToString(ret));
       } else {
               LOGPRINTF("%d Freed pz\n",getpid());
               h_pz = NULL;
       }

       /* close the device */
       LOGPRINTF("%d Closing Interface Adaptor\n",getpid());
       start = get_time();
       ret = dat_ia_close( h_ia, DAT_CLOSE_ABRUPT_FLAG );
       stop = get_time();
       time.close += ((stop - start)*1.0e6);
       if(ret != DAT_SUCCESS) {
               fprintf(stderr, "%d: Error Adaptor close: %s\n",
                       getpid(),DT_RetToString(ret));
               exit(1);
       } else
               LOGPRINTF("%d Closed Interface Adaptor\n",getpid());

        printf( "\n%d: DAPL Test Complete.\n\n",getpid());
	printf( "%d: Message RTT: Total=%10.2lf usec, %d bursts, itime=%10.2lf usec, pc=%d\n", 
		getpid(), time.rtt, burst, time.rtt/burst, poll_count );
	printf( "%d: RDMA write:  Total=%10.2lf usec, %d bursts, itime=%10.2lf usec, pc=%d\n", 
		getpid(), time.rdma_wr, burst, 
		time.rdma_wr/burst, rdma_wr_poll_count );
	for(i=0;i<MAX_RDMA_RD;i++) {
	    printf( "%d: RDMA read:   Total=%10.2lf usec,   %d bursts, itime=%10.2lf usec, pc=%d\n", 
	           getpid(),time.rdma_rd_total,MAX_RDMA_RD,
		   time.rdma_rd[i],rdma_rd_poll_count[i] );
	}
        printf( "%d: open:      %10.2lf usec\n", getpid(), time.open  );
        printf( "%d: close:     %10.2lf usec\n", getpid(), time.close );
        printf( "%d: PZ create: %10.2lf usec\n", getpid(), time.pzc );
        printf( "%d: PZ free:   %10.2lf usec\n", getpid(), time.pzf );
        printf( "%d: LMR create:%10.2lf usec\n", getpid(), time.reg );
        printf( "%d: LMR free:  %10.2lf usec\n", getpid(), time.unreg );
        printf( "%d: EVD create:%10.2lf usec\n", getpid(), time.evdc );
        printf( "%d: EVD free:  %10.2lf usec\n", getpid(), time.evdf );
        if (use_cno) {
           printf( "%d: CNO create:  %10.2lf usec\n", getpid(), time.cnoc );
           printf( "%d: CNO free:    %10.2lf usec\n", getpid(), time.cnof );
        }
        printf( "%d: EP create: %10.2lf usec\n",getpid(), time.epc );
        printf( "%d: EP free:   %10.2lf usec\n",getpid(), time.epf );
        printf( "%d: TOTAL:     %10.2lf usec\n",getpid(), time.total );

       /* free rdma buffers */
       free(rbuf);
       free(sbuf);
       return(0);
}


double get_time()
{
       struct timeval tp;

       gettimeofday(&tp, NULL);
       return ((double) tp.tv_sec + (double) tp.tv_usec * 1e-6);
}

void init_data()
{
       memset(rbuf, 'a', buf_len);
       memset(sbuf, 'b', buf_len);
}


DAT_RETURN
send_msg(  void                   *data,
           DAT_COUNT               size,
           DAT_LMR_CONTEXT         context,
           DAT_DTO_COOKIE          cookie,
           DAT_COMPLETION_FLAGS    flags )
{
    DAT_LMR_TRIPLET    iov;
    DAT_EVENT          event;
    DAT_COUNT          nmore;
    DAT_RETURN         ret;

    iov.lmr_context     = context;
    iov.pad             = 0;
    iov.virtual_address = (DAT_VADDR)(unsigned long)data;
    iov.segment_length  = size;
    
    LOGPRINTF("%d calling post_send\n", getpid());
    cookie.as_64 = 0xaaaa;
    ret = dat_ep_post_send( h_ep,
                           1,
                           &iov,
                           cookie,
                           flags );

    if (ret != DAT_SUCCESS) {
        fprintf(stderr, "%d: ERROR: dat_ep_post_send() %s\n",
                           getpid(),DT_RetToString(ret));
        return ret;
    }

    if (!(flags & DAT_COMPLETION_SUPPRESS_FLAG)) {
       if ( polling ) {
           printf("%d Polling post send completion...\n",getpid());
           while (  dat_evd_dequeue( h_dto_req_evd, &event ) == DAT_QUEUE_EMPTY );
       }
       else {
           LOGPRINTF("%d waiting for post_send completion event\n", getpid());
           if (use_cno) {
               DAT_EVD_HANDLE evd = DAT_HANDLE_NULL;
               ret = dat_cno_wait( h_dto_cno, DTO_TIMEOUT, &evd );
               LOGPRINTF("%d cno wait return evd_handle=%p\n", getpid(),evd);
               if ( evd != h_dto_req_evd ) {
                   fprintf(stderr,
                       "%d Error waiting on h_dto_cno: evd != h_dto_req_evd\n",
                       getpid());
                   return( DAT_ABORT );
               }
           }
           /* use wait to dequeue */
           ret = dat_evd_wait( h_dto_req_evd, DTO_TIMEOUT, 1, &event, &nmore );
           if (ret != DAT_SUCCESS) {
               fprintf(stderr, "%d: ERROR: DTO dat_evd_wait() %s\n",
                       getpid(),DT_RetToString(ret));
               return ret;
           }
       }

       /* validate event number, len, cookie, and status */
       if ( event.event_number != DAT_DTO_COMPLETION_EVENT ) {
           fprintf(stderr, "%d: ERROR: DTO event number %s\n",
                   getpid(),DT_EventToSTr(event.event_number));
           return( DAT_ABORT );
       }

       if ((event.event_data.dto_completion_event_data.transfered_length != size ) ||
           (event.event_data.dto_completion_event_data.user_cookie.as_64 != 0xaaaa )) {
           fprintf(stderr, "%d: ERROR: DTO len "F64x" or cookie "F64x"\n",
               getpid(),
               event.event_data.dto_completion_event_data.transfered_length,
               event.event_data.dto_completion_event_data.user_cookie.as_64 );
           return( DAT_ABORT );

       }
       if (event.event_data.dto_completion_event_data.status != DAT_SUCCESS) {
           fprintf(stderr, "%d: ERROR: DTO event status %s\n",
                   getpid(),DT_RetToString(ret));
           return( DAT_ABORT );
       }
    }

    return DAT_SUCCESS;
}


DAT_RETURN
connect_ep( char *hostname, int conn_id )
{
       DAT_SOCK_ADDR           remote_addr;
       DAT_RETURN              ret;
       DAT_REGION_DESCRIPTION  region;
       DAT_EVENT               event;
       DAT_COUNT               nmore;
       DAT_LMR_TRIPLET         l_iov;
       DAT_RMR_TRIPLET         r_iov;
       DAT_DTO_COOKIE          cookie;
       int                     i;

     /* Register send message buffer */
    LOGPRINTF("%d Registering send Message Buffer %p, len %d\n",
               getpid(), &rmr_send_msg, (int)sizeof(DAT_RMR_TRIPLET));
    region.for_va = &rmr_send_msg;
    ret = dat_lmr_create(   h_ia,
                           DAT_MEM_TYPE_VIRTUAL,
                           region,
                           sizeof(DAT_RMR_TRIPLET),
                           h_pz,
                           DAT_MEM_PRIV_LOCAL_WRITE_FLAG,
                           &h_lmr_send_msg,
                           &lmr_context_send_msg,
                           &rmr_context_send_msg,
                           &registered_size_send_msg,
                           &registered_addr_send_msg );

    if (ret != DAT_SUCCESS) {
       fprintf(stderr, "%d Error registering send msg buffer: %s\n",
               getpid(),DT_RetToString(ret));
       return(ret);
    }
    else
       LOGPRINTF("%d Registered send Message Buffer %p \n",
               getpid(),region.for_va );

    /* Register Receive buffers */
    LOGPRINTF("%d Registering Receive Message Buffer %p\n",
               getpid(), rmr_recv_msg );
    region.for_va = rmr_recv_msg;
    ret = dat_lmr_create(  h_ia,
                           DAT_MEM_TYPE_VIRTUAL,
                           region,
                           sizeof(DAT_RMR_TRIPLET)*MSG_BUF_COUNT,
                           h_pz,
                           DAT_MEM_PRIV_LOCAL_WRITE_FLAG,
                           &h_lmr_recv_msg,
                           &lmr_context_recv_msg,
                           &rmr_context_recv_msg,
                           &registered_size_recv_msg,
                           &registered_addr_recv_msg );
    if(ret != DAT_SUCCESS) {
       fprintf(stderr, "%d Error registering recv msg buffer: %s\n",
               getpid(),DT_RetToString(ret));
       return(ret);
    }
    else
       LOGPRINTF("%d Registered Receive Message Buffer %p\n",
               getpid(),region.for_va);

    for ( i = 0; i < MSG_BUF_COUNT; i++ ) {
       cookie.as_64          = i;
       l_iov.lmr_context     = lmr_context_recv_msg;
       l_iov.pad             = 0;
       l_iov.virtual_address = (DAT_VADDR)(unsigned long)&rmr_recv_msg[ i ];
       l_iov.segment_length  = sizeof(DAT_RMR_TRIPLET);

       LOGPRINTF("%d Posting Receive Message Buffer %p\n",
                   getpid(), &rmr_recv_msg[ i ]);
       ret = dat_ep_post_recv( h_ep,
                               1,
                               &l_iov,
                               cookie,
                               DAT_COMPLETION_DEFAULT_FLAG );

        if(ret != DAT_SUCCESS) {
           fprintf(stderr, "%d Error registering recv msg buffer: %s\n",
                           getpid(),DT_RetToString(ret));
           return(ret);
        }
       else
           LOGPRINTF("%d Registered Receive Message Buffer %p\n",
                                   getpid(),region.for_va);

    }

    /* setup receive rdma buffer to initial string to be overwritten */
    strcpy( (char*)rbuf, "blah, blah, blah\n" );

    if ( server ) {  /* SERVER */

        /* create the service point for server listen */
        LOGPRINTF("%d Creating service point for listen\n",getpid());
       ret = dat_psp_create(   h_ia,
                               conn_id,
                               h_cr_evd,
                               DAT_PSP_CONSUMER_FLAG,
                               &h_psp );
       if(ret != DAT_SUCCESS) {
           fprintf(stderr, "%d Error dat_psp_create: %s\n",
                           getpid(),DT_RetToString(ret));
           return(ret);
       }
       else
           LOGPRINTF("%d dat_psp_created for server listen\n", getpid());

        printf("%d Server waiting for connect request..\n", getpid());
       ret = dat_evd_wait( h_cr_evd, SERVER_TIMEOUT, 1, &event, &nmore );
       if(ret != DAT_SUCCESS) {
           fprintf(stderr, "%d Error dat_evd_wait: %s\n",
                           getpid(),DT_RetToString(ret));
           return(ret);
       }
       else
           LOGPRINTF("%d dat_evd_wait for cr_evd completed\n", getpid());

       if ( event.event_number != DAT_CONNECTION_REQUEST_EVENT ) {
            fprintf(stderr, "%d Error unexpected cr event : %s\n",
                                   getpid(),DT_EventToSTr(event.event_number));
                       return( DAT_ABORT );
       }
       if ( (event.event_data.cr_arrival_event_data.conn_qual != SERVER_CONN_QUAL) ||
            (event.event_data.cr_arrival_event_data.sp_handle.psp_handle != h_psp) ) {
            fprintf(stderr, "%d Error wrong cr event data : %s\n",
                   getpid(),DT_EventToSTr(event.event_number));
           return( DAT_ABORT );
       }

       if (delay) sleep(delay); /* use to test rdma_cma timeout logic */

        /* accept connect request from client */
       h_cr = event.event_data.cr_arrival_event_data.cr_handle;
        LOGPRINTF("%d Accepting connect request from client\n",getpid());
       ret = dat_cr_accept( h_cr, h_ep, 0, (DAT_PVOID)0 );
        if(ret != DAT_SUCCESS) {
           fprintf(stderr, "%d Error dat_cr_accept: %s\n",
                   getpid(),DT_RetToString(ret));
           return(ret);
       }
       else
           LOGPRINTF("%d dat_cr_accept completed\n", getpid());
    }
    else {  /* CLIENT */
       struct addrinfo *target;

       if (getaddrinfo (hostname, NULL, NULL, &target) != 0) {
           printf("\n remote name resolution failed!\n");
           exit ( 1 );
       }

       printf ("%d Server Name: %s \n", getpid(), hostname);
       printf ("%d Server Net Address: %s\n", getpid(),
           inet_ntoa(((struct sockaddr_in *)target->ai_addr)->sin_addr));

       remote_addr = *((DAT_IA_ADDRESS_PTR)target->ai_addr);
       freeaddrinfo(target);

       LOGPRINTF("%d Connecting to server\n",getpid());
       ret = dat_ep_connect(   h_ep,
                               &remote_addr,
                               conn_id,
                               CONN_TIMEOUT,
                               0,
                               (DAT_PVOID)0,
                               0,
                               DAT_CONNECT_DEFAULT_FLAG  );
       if(ret != DAT_SUCCESS) {
           fprintf(stderr, "%d Error dat_ep_connect: %s\n",
                               getpid(), DT_RetToString(ret));
           return(ret);
       }
       else
           LOGPRINTF("%d dat_ep_connect completed\n", getpid());
    }

    printf("%d Waiting for connect response\n",getpid());

    ret = dat_evd_wait( h_conn_evd, DAT_TIMEOUT_INFINITE, 1, &event, &nmore );
    if(ret != DAT_SUCCESS) {
           fprintf(stderr, "%d Error dat_evd_wait: %s\n",
                           getpid(),DT_RetToString(ret));
           return(ret);
    }
    else
           LOGPRINTF("%d dat_evd_wait for h_conn_evd completed\n", getpid());

    if ( event.event_number != DAT_CONNECTION_EVENT_ESTABLISHED ) {
           fprintf(stderr, "%d Error unexpected conn event : %s\n",
                               getpid(),DT_EventToSTr(event.event_number));
           return( DAT_ABORT );
    }
    printf("\n%d CONNECTED!\n\n",getpid());
    connected = 1;

    /*
     *  Setup our remote memory and tell the other side about it
     */
    rmr_send_msg.rmr_context    = rmr_context_recv;
    rmr_send_msg.pad            = 0;
    rmr_send_msg.target_address = (DAT_VADDR)(unsigned long)rbuf;
    rmr_send_msg.segment_length = RDMA_BUFFER_SIZE;

    printf("%d Send RMR to remote: snd_msg: r_key_ctx=%x,pad=%x, "
	   "va="F64x",len="F64x"\n",
           getpid(), rmr_send_msg.rmr_context, rmr_send_msg.pad,
           rmr_send_msg.target_address, rmr_send_msg.segment_length );

    ret = send_msg( &rmr_send_msg,
                   sizeof( DAT_RMR_TRIPLET ),
                   lmr_context_send_msg,
                   cookie,
                   DAT_COMPLETION_SUPPRESS_FLAG );

    if(ret != DAT_SUCCESS) {
        fprintf(stderr, "%d Error send_msg: %s\n",
               getpid(),DT_RetToString(ret));
       return(ret);
    }
    else
       LOGPRINTF("%d send_msg completed\n", getpid());

    /*
     *  Wait for remote RMR information for RDMA
     */
    if ( polling ) {
       printf("%d Polling for remote to send RMR data\n",getpid());
       while (  dat_evd_dequeue( h_dto_rcv_evd, &event ) == DAT_QUEUE_EMPTY );
    }
    else  {
       printf("%d Waiting for remote to send RMR data\n",getpid());
       if (use_cno)
       {
           DAT_EVD_HANDLE evd = DAT_HANDLE_NULL;
           ret = dat_cno_wait( h_dto_cno, DTO_TIMEOUT, &evd );
           LOGPRINTF("%d cno wait return evd_handle=%p\n", getpid(),evd);
           if ( evd != h_dto_rcv_evd ) {
               fprintf(stderr,
                       "%d Error waiting on h_dto_cno: evd != h_dto_rcv_evd\n",
                       getpid());
               return( DAT_ABORT );
           }
       }
       /* use wait to dequeue */
       ret = dat_evd_wait( h_dto_rcv_evd, DTO_TIMEOUT, 1, &event, &nmore );
       if(ret != DAT_SUCCESS) {
           fprintf(stderr, "%d Error waiting on h_dto_rcv_evd: %s\n",
                   getpid(),DT_RetToString(ret));
           return(ret);
       }
       else {
           LOGPRINTF("%d dat_evd_wait h_dto_rcv_evd completed\n", getpid());
       }
    }

    printf("%d remote RMR data arrived!\n",getpid());

    if ( event.event_number != DAT_DTO_COMPLETION_EVENT ) {
        fprintf(stderr, "%d Error unexpected DTO event : %s\n",
               getpid(),DT_EventToSTr(event.event_number));
        return( DAT_ABORT );
    }
    if ((event.event_data.dto_completion_event_data.transfered_length !=
               sizeof( DAT_RMR_TRIPLET )) ||
       (event.event_data.dto_completion_event_data.user_cookie.as_64 !=
               recv_msg_index) ) {
       fprintf(stderr,"ERR recv event: len=%d cookie="F64x" expected %d/%d\n",
           (int)event.event_data.dto_completion_event_data.transfered_length,
           event.event_data.dto_completion_event_data.user_cookie.as_64,
           (int)sizeof(DAT_RMR_TRIPLET), recv_msg_index );
       return( DAT_ABORT );
    }

    r_iov = rmr_recv_msg[ recv_msg_index ];

    printf("%d Received RMR from remote: r_iov: r_key_ctx=%x,pad=%x "
	   ",va="F64x",len="F64x"\n",
           getpid(), r_iov.rmr_context, r_iov.pad,
           r_iov.target_address, r_iov.segment_length );

    recv_msg_index++;

    return ( DAT_SUCCESS );
}


void
disconnect_ep()
{
    DAT_RETURN ret;
    DAT_EVENT  event;
    DAT_COUNT  nmore;

    if (connected) {

       /* 
        * Only the client needs to call disconnect. The server _should_ be able to
        * just wait on the EVD associated with connection events for a disconnect
        * request and exit then.
        */
       if ( !server ) {
           LOGPRINTF("%d dat_ep_disconnect\n", getpid());
           ret = dat_ep_disconnect( h_ep, DAT_CLOSE_DEFAULT );
           if(ret != DAT_SUCCESS)  {
                   fprintf(stderr, "%d Error dat_ep_disconnect: %s\n",
                                   getpid(),DT_RetToString(ret));
           }
           else {
               LOGPRINTF("%d dat_ep_disconnect completed\n", getpid());
           }
       }

    	ret = dat_evd_wait( h_conn_evd, DAT_TIMEOUT_INFINITE, 1, &event, &nmore );
    	if(ret != DAT_SUCCESS) {
           	fprintf(stderr, "%d Error dat_evd_wait: %s\n",
                           	getpid(),DT_RetToString(ret));
    	}
    	else {
           	LOGPRINTF("%d dat_evd_wait for h_conn_evd completed\n", getpid());
    	}
    }

    /* destroy service point */
    if (( server ) && ( h_psp != DAT_HANDLE_NULL )) {
       ret = dat_psp_free( h_psp );
        if(ret != DAT_SUCCESS) {
           fprintf(stderr, "%d Error dat_psp_free: %s\n",
                   getpid(),DT_RetToString(ret));
       }
       else {
           LOGPRINTF("%d dat_psp_free completed\n", getpid());
       }
    }

    /* Unregister Send message Buffer */
    if ( h_lmr_send_msg != DAT_HANDLE_NULL ) {
       LOGPRINTF("%d Unregister send message h_lmr %p \n",getpid(),h_lmr_send_msg);
       ret = dat_lmr_free(h_lmr_send_msg);
        if(ret != DAT_SUCCESS) {
           fprintf(stderr, "%d Error deregistering send msg mr: %s\n",
           getpid(), DT_RetToString(ret));
       } else {
           LOGPRINTF("%d Unregistered send message Buffer\n",getpid());
           h_lmr_send_msg = NULL;
       }
    }

    /* Unregister recv message Buffer */
    if ( h_lmr_recv_msg != DAT_HANDLE_NULL ) {
       LOGPRINTF("%d Unregister recv message h_lmr %p \n",getpid(),h_lmr_recv_msg);
       ret = dat_lmr_free(h_lmr_recv_msg);
        if(ret != DAT_SUCCESS) {
           fprintf(stderr, "%d Error deregistering recv msg mr: %s\n",
                           getpid(), DT_RetToString(ret));
       } else {
           LOGPRINTF("%d Unregistered recv message Buffer\n",getpid());
           h_lmr_recv_msg = NULL;
       }
    }
    return;
}


DAT_RETURN
do_rdma_write_with_msg( )
{
       DAT_EVENT               event;
       DAT_COUNT               nmore;
       DAT_LMR_TRIPLET         l_iov[MSG_IOV_COUNT];
       DAT_RMR_TRIPLET         r_iov;
       DAT_DTO_COOKIE          cookie;
       DAT_RETURN              ret;
       int                     i;

       printf("\n %d RDMA WRITE DATA with SEND MSG\n\n",getpid());

       cookie.as_64 = 0x5555;

       if ( recv_msg_index >= MSG_BUF_COUNT )
               return( DAT_ABORT );

       /* get RMR information from previously received message */
       r_iov = rmr_recv_msg[ recv_msg_index-1 ];

       if ( server )
           strcpy( (char*)sbuf, "server RDMA write data..." );
       else
           strcpy( (char*)sbuf, "client RDMA write data..." );

       for (i=0;i<MSG_IOV_COUNT;i++) {
	   l_iov[i].lmr_context     = lmr_context_send;
	   l_iov[i].pad             = 0;
	   l_iov[i].segment_length  = buf_len/MSG_IOV_COUNT;
	   l_iov[i].virtual_address = (DAT_VADDR)(unsigned long)
					(&sbuf[l_iov[i].segment_length*i]);

	   LOGPRINTF("%d rdma_write iov[%d] buf=%p,len="F64x"\n", 
			getpid(), i, &sbuf[l_iov[i].segment_length*i],
			l_iov[i].segment_length);
       }

       start = get_time();
       for (i=0;i<burst;i++) {
           cookie.as_64 = 0x9999;
           ret = dat_ep_post_rdma_write(   h_ep,               // ep_handle
                                           MSG_IOV_COUNT,      // num_segments
                                           l_iov,              // LMR
                                           cookie,             // user_cookie
                                           &r_iov,             // RMR
                                           DAT_COMPLETION_SUPPRESS_FLAG );
           if (ret != DAT_SUCCESS) {
               fprintf(stderr, "%d: ERROR: dat_ep_post_rdma_write() %s\n",
                                       getpid(),DT_RetToString(ret));
               return( DAT_ABORT );
           }
           LOGPRINTF("%d rdma_write # %d completed\n", getpid(),i+1);
       }

       /*
        *  Send RMR information a 2nd time to indicate completion
        */
       rmr_send_msg.rmr_context    = rmr_context_recv;
       rmr_send_msg.pad            = 0;
       rmr_send_msg.target_address = (DAT_VADDR)(unsigned long)rbuf;
       rmr_send_msg.segment_length = RDMA_BUFFER_SIZE;

       printf("%d Sending completion message\n",getpid());

       ret = send_msg( &rmr_send_msg,
                       sizeof( DAT_RMR_TRIPLET ),
                       lmr_context_send_msg,
                       cookie,
                       DAT_COMPLETION_SUPPRESS_FLAG );

       if(ret != DAT_SUCCESS) {
               fprintf(stderr, "%d Error send_msg: %s\n",
                               getpid(),DT_RetToString(ret));
               return(ret);
       } else {
               LOGPRINTF("%d send_msg completed\n", getpid());
       }

       /*
        *  Collect first event, write completion or the inbound recv with immed
        */
       if ( polling ) {
           while (  dat_evd_dequeue( h_dto_rcv_evd, &event ) == DAT_QUEUE_EMPTY )
               rdma_wr_poll_count++;
       }
       else {
           LOGPRINTF("%d waiting for message receive event\n", getpid());
           if (use_cno)  {
                   DAT_EVD_HANDLE evd = DAT_HANDLE_NULL;
                   ret = dat_cno_wait( h_dto_cno, DTO_TIMEOUT, &evd );
                   LOGPRINTF("%d cno wait return evd_handle=%p\n", getpid(),evd);
                   if ( evd != h_dto_rcv_evd ) {
                           fprintf(stderr, 
				   "%d Error waiting on h_dto_cno: evd != h_dto_rcv_evd\n",
                                   getpid());
                           return( ret );
                   }
           }
           /* use wait to dequeue */
           ret = dat_evd_wait( h_dto_rcv_evd, DTO_TIMEOUT, 1, &event, &nmore );
           if (ret != DAT_SUCCESS) {
                   fprintf(stderr, "%d: ERROR: DTO dat_evd_wait() %s\n",
                                           getpid(),DT_RetToString(ret));
                   return( ret );
           }
       }
       stop = get_time();
       time.rdma_wr = ((stop - start)*1.0e6);

       /* validate event number and status */
       printf("%d inbound rdma_write; send message arrived!\n",getpid());
       if ( event.event_number != DAT_DTO_COMPLETION_EVENT ) {
           fprintf(stderr, "%d Error unexpected DTO event : %s\n",
                               getpid(),DT_EventToSTr(event.event_number));
           return( DAT_ABORT );
       }

       if ( (event.event_data.dto_completion_event_data.transfered_length != sizeof( DAT_RMR_TRIPLET )) ||
            (event.event_data.dto_completion_event_data.user_cookie.as_64 != recv_msg_index) ) { +
           fprintf(stderr,"unexpected event data for receive: len=%d cookie="F64x" exp %d/%d\n",
               (int)event.event_data.dto_completion_event_data.transfered_length,
               event.event_data.dto_completion_event_data.user_cookie.as_64,
               (int)sizeof(DAT_RMR_TRIPLET), recv_msg_index );

           return( DAT_ABORT );
       }

       r_iov = rmr_recv_msg[ recv_msg_index ];

       printf("%d Received RMR from remote: r_iov: ctx=%x,pad=%x,va=%p,len="F64x"\n",
                   getpid(), r_iov.rmr_context,
            r_iov.pad,
            (void*)(unsigned long)r_iov.target_address,
                   r_iov.segment_length );

       LOGPRINTF("%d inbound rdma_write; send msg event SUCCESS!!!\n", getpid());

       printf("%d %s RDMA write buffer contains: %s\n",
                       getpid(),
                       server ? "SERVER:" : "CLIENT:",
                       rbuf );

       recv_msg_index++;

       return ( DAT_SUCCESS );
}

DAT_RETURN
do_rdma_read_with_msg( )
{
       DAT_EVENT               event;
       DAT_COUNT               nmore;
       DAT_LMR_TRIPLET         l_iov;
       DAT_RMR_TRIPLET         r_iov;
       DAT_DTO_COOKIE          cookie;
       DAT_RETURN              ret;
       int                     i;

       printf("\n %d RDMA READ DATA with SEND MSG\n\n",getpid());

       if ( recv_msg_index >= MSG_BUF_COUNT )
               return( DAT_ABORT );

       /* get RMR information from previously received message */
       r_iov = rmr_recv_msg[ recv_msg_index-1 ];

       /* setup rdma read buffer to initial string to be overwritten */
       strcpy( (char*)sbuf, "blah, blah, blah\n" );

       if ( server )
           strcpy( (char*)rbuf, "server RDMA read data..." );
       else
           strcpy( (char*)rbuf, "client RDMA read data..." );

       l_iov.lmr_context     = lmr_context_send;
       l_iov.pad             = 0;
       l_iov.virtual_address = (DAT_VADDR)(unsigned long)sbuf;
       l_iov.segment_length  = buf_len;
 	
       for (i=0;i<MAX_RDMA_RD;i++) {
	    cookie.as_64 = 0x9999;
	    start = get_time();
	    ret = dat_ep_post_rdma_read(    h_ep,		// ep_handle
					    1,			// num_segments
					    &l_iov,		// LMR
					    cookie,		// user_cookie
					    &r_iov,		// RMR
					    DAT_COMPLETION_DEFAULT_FLAG );
	    if (ret != DAT_SUCCESS) {
		fprintf(stderr, "%d: ERROR: dat_ep_post_rdma_read() %s\n", 
					getpid(),DT_RetToString(ret));
		return( DAT_ABORT );
	    }
	    
	    if (polling) {
		while (dat_evd_dequeue(h_dto_req_evd, &event) == DAT_QUEUE_EMPTY)
			rdma_rd_poll_count[i]++;
	    } 
	    else {
		LOGPRINTF("%d waiting for rdma_read completion event\n", getpid());
		if (use_cno) {
			DAT_EVD_HANDLE evd = DAT_HANDLE_NULL;
			ret = dat_cno_wait( h_dto_cno, DTO_TIMEOUT, &evd );
			LOGPRINTF("%d cno wait return evd_handle=%p\n", getpid(),evd);
			if ( evd != h_dto_req_evd ) {
	    			fprintf(stderr, 
				"%d Error waiting on h_dto_cno: evd != h_dto_req_evd\n", 
				getpid());
				return( DAT_ABORT );
			}
		}
		/* use wait to dequeue */
		ret = dat_evd_wait( h_dto_req_evd, DTO_TIMEOUT, 1, &event, &nmore );
		if (ret != DAT_SUCCESS) {
			fprintf(stderr, "%d: ERROR: DTO dat_evd_wait() %s\n", 
				getpid(),DT_RetToString(ret));
			return ret;
		}
	    }
	    /* validate event number, len, cookie, and status */
	    if (event.event_number != DAT_DTO_COMPLETION_EVENT) {
		fprintf(stderr, "%d: ERROR: DTO event number %s\n", 
			getpid(),DT_EventToSTr(event.event_number));
		return( DAT_ABORT );
	    }
	    if ((event.event_data.dto_completion_event_data.transfered_length != buf_len ) ||
		(event.event_data.dto_completion_event_data.user_cookie.as_64 != 0x9999 )) {
		fprintf(stderr, "%d: ERROR: DTO len %d or cookie "F64x"\n", 
			getpid(),
			(int)event.event_data.dto_completion_event_data.transfered_length,
			event.event_data.dto_completion_event_data.user_cookie.as_64 );
		return( DAT_ABORT );
	    }
	    if (event.event_data.dto_completion_event_data.status != DAT_SUCCESS) {
		fprintf(stderr, "%d: ERROR: DTO event status %s\n", 
			getpid(),DT_RetToString(ret));
		return( DAT_ABORT );
	    }
	    stop = get_time();
	    time.rdma_rd[i] = ((stop - start)*1.0e6);
	    time.rdma_rd_total += time.rdma_rd[i];

	    LOGPRINTF("%d rdma_read # %d completed\n", getpid(),i+1);
       }

       /*
        *  Send RMR information a 2nd time to indicate completion
        */
       rmr_send_msg.rmr_context    = rmr_context_recv;
       rmr_send_msg.pad            = 0;
       rmr_send_msg.target_address = (DAT_VADDR)(unsigned long)rbuf;
       rmr_send_msg.segment_length = RDMA_BUFFER_SIZE;

       printf("%d Sending completion message\n",getpid());

       ret = send_msg( &rmr_send_msg,
                       sizeof( DAT_RMR_TRIPLET ),
                       lmr_context_send_msg,
                       cookie,
                       DAT_COMPLETION_SUPPRESS_FLAG );

       if(ret != DAT_SUCCESS) {
               fprintf(stderr, "%d Error send_msg: %s\n",
                               getpid(),DT_RetToString(ret));
               return(ret);
       } else {
               LOGPRINTF("%d send_msg completed\n", getpid());
       }

       /*
        *  Collect first event, write completion or the inbound recv with immed
        */
       printf("%d Waiting for inbound message....\n",getpid());
       if ( polling ) {
           while (  dat_evd_dequeue( h_dto_rcv_evd, &event ) == DAT_QUEUE_EMPTY );
       }
       else {
           LOGPRINTF("%d waiting for message receive event\n", getpid());
           if (use_cno) {
                   DAT_EVD_HANDLE evd = DAT_HANDLE_NULL;
                   ret = dat_cno_wait( h_dto_cno, DTO_TIMEOUT, &evd );
                   LOGPRINTF("%d cno wait return evd_handle=%p\n", getpid(),evd);
                   if ( evd != h_dto_rcv_evd ) {
                           fprintf(stderr, 
				   "%d Error waiting on h_dto_cno: evd != h_dto_rcv_evd\n",
                                   getpid());
                           return( ret );
                   }
           }
           /* use wait to dequeue */
           ret = dat_evd_wait( h_dto_rcv_evd, DTO_TIMEOUT, 1, &event, &nmore );
           if (ret != DAT_SUCCESS) {
                   fprintf(stderr, "%d: ERROR: DTO dat_evd_wait() %s\n",
                                           getpid(),DT_RetToString(ret));
                   return( ret );
           }
       }

       /* validate event number and status */
       printf("%d inbound rdma_read; send message arrived!\n",getpid());
       if ( event.event_number != DAT_DTO_COMPLETION_EVENT ) {
           fprintf(stderr, "%d Error unexpected DTO event : %s\n",
                               getpid(),DT_EventToSTr(event.event_number));
           return( DAT_ABORT );
       }

       if ( (event.event_data.dto_completion_event_data.transfered_length != sizeof( DAT_RMR_TRIPLET )) ||
            (event.event_data.dto_completion_event_data.user_cookie.as_64 != recv_msg_index) ) {

           fprintf(stderr,"unexpected event data for receive: len=%d cookie="F64x" exp %d/%d\n",
               (int)event.event_data.dto_completion_event_data.transfered_length,
               event.event_data.dto_completion_event_data.user_cookie.as_64,
               (int)sizeof(DAT_RMR_TRIPLET), recv_msg_index );

           return( DAT_ABORT );
       }

       r_iov = rmr_recv_msg[ recv_msg_index ];

       printf("%d Received RMR from remote: r_iov: ctx=%x,pad=%x,va=%p,len="F64x"\n",
               getpid(), r_iov.rmr_context, r_iov.pad,
               (void*)(unsigned long)r_iov.target_address, r_iov.segment_length );

       LOGPRINTF("%d inbound rdma_write; send msg event SUCCESS!!!\n", getpid());

       printf("%d %s RCV RDMA read buffer contains: %s\n",
                       getpid(),
                       server ? "SERVER:" : "CLIENT:",
                       sbuf );

       recv_msg_index++;

       return ( DAT_SUCCESS );
}


DAT_RETURN
do_ping_pong_msg( )
{
    DAT_EVENT          event;
    DAT_COUNT          nmore;
    DAT_DTO_COOKIE     cookie;
    DAT_LMR_TRIPLET    l_iov;
    DAT_RETURN         ret;
    int                i;
    char               *snd_buf;
    char               *rcv_buf;

    printf("\n %d PING DATA with SEND MSG\n\n",getpid());

    snd_buf = sbuf;
    rcv_buf = rbuf;

    /* pre-post all buffers */
    for ( i=0; i < burst; i++ ) {
       burst_msg_posted++;
       cookie.as_64          = i;
       l_iov.lmr_context     = lmr_context_recv;
       l_iov.pad             = 0;
       l_iov.virtual_address = (DAT_VADDR)(unsigned long)rcv_buf;
       l_iov.segment_length  = buf_len;

       LOGPRINTF("%d Pre-posting Receive Message Buffers %p\n",
                   getpid(), rcv_buf );

       ret = dat_ep_post_recv( h_ep,
                               1,
                               &l_iov,
                               cookie,
                               DAT_COMPLETION_DEFAULT_FLAG );

        if(ret != DAT_SUCCESS) {
           fprintf(stderr, "%d Error posting recv msg buffer: %s\n",
                           getpid(),DT_RetToString(ret));
           return(ret);
        }
       else {
           LOGPRINTF("%d Posted Receive Message Buffer %p\n",
                                   getpid(),rcv_buf);
        }

       /* next buffer */
       rcv_buf += buf_len;
    }
    sleep(1);

    /* Initialize recv_buf and index to beginning */
    rcv_buf = rbuf;
    burst_msg_index=0;

    /* client ping 0x55, server pong 0xAA in first byte */
    start = get_time();
    for ( i=0;i<burst;i++ ) {
       /* walk the send and recv buffers */
       if ( !server ) {
           *snd_buf = 0x55;

           LOGPRINTF("%d %s SND buffer %p contains: 0x%x len=%d\n",
                   getpid(), server ? "SERVER:" : "CLIENT:",
                   snd_buf, *snd_buf, buf_len );

           ret = send_msg( snd_buf,
                           buf_len,
                           lmr_context_send,
                           cookie,
                           DAT_COMPLETION_SUPPRESS_FLAG );

           if(ret != DAT_SUCCESS) {
               fprintf(stderr, "%d Error send_msg: %s\n",
                                   getpid(),DT_RetToString(ret));
               return(ret);
           }
           else {
               LOGPRINTF("%d send_msg completed\n", getpid());
           }
       }

       /* Wait for recv message */
       if ( polling ) {
           poll_count=0;
           LOGPRINTF("%d Polling for message receive event\n", getpid());
           while (  dat_evd_dequeue( h_dto_rcv_evd, &event ) == DAT_QUEUE_EMPTY )
               poll_count++;
       }
       else {
           LOGPRINTF("%d waiting for message receive event\n", getpid());
           if (use_cno) {
               DAT_EVD_HANDLE evd = DAT_HANDLE_NULL;
               ret = dat_cno_wait( h_dto_cno, DTO_TIMEOUT, &evd );
               LOGPRINTF("%d cno wait return evd_handle=%p\n", getpid(),evd);
               if ( evd != h_dto_rcv_evd )
               {
                   fprintf(stderr, 
			   "%d Error waiting on h_dto_cno: evd != h_dto_rcv_evd\n",
                           getpid());
                   return( ret );
               }
           }
           /* use wait to dequeue */
           ret = dat_evd_wait( h_dto_rcv_evd, DTO_TIMEOUT, 1, &event, &nmore );
           if (ret != DAT_SUCCESS) {
               fprintf(stderr, "%d: ERROR: DTO dat_evd_wait() %s\n",
                                       getpid(),DT_RetToString(ret));
               return( ret );
           }
       }
       /* start timer after first message arrives on server */
       if ( i == 0) {
           start = get_time();
       }
       /* validate event number and status */
       LOGPRINTF("%d inbound message; message arrived!\n",getpid());
       if ( event.event_number != DAT_DTO_COMPLETION_EVENT ) {
           fprintf(stderr, "%d Error unexpected DTO event : %s\n",
                   getpid(),DT_EventToSTr(event.event_number));
           return( DAT_ABORT );
       }
       if ((event.event_data.dto_completion_event_data.transfered_length
           != buf_len) ||
           (event.event_data.dto_completion_event_data.user_cookie.as_64
           != burst_msg_index) )  {
           fprintf(stderr,"ERR: recv event: len=%d cookie="F64x" exp %d/%d\n",
               (int)event.event_data.dto_completion_event_data.transfered_length,
               event.event_data.dto_completion_event_data.user_cookie.as_64,
               buf_len, burst_msg_index );

           return( DAT_ABORT );
       }

       LOGPRINTF("%d %s RCV buffer %p contains: 0x%x len=%d\n",
                   getpid(), server ? "SERVER:" : "CLIENT:",
                   rcv_buf, *rcv_buf, buf_len );

       burst_msg_index++;

       /* If server, change data and send it back to client */
       if ( server ) {
           *snd_buf = 0xaa;

           LOGPRINTF("%d %s SND buffer %p contains: 0x%x len=%d\n",
                   getpid(), server ? "SERVER:" : "CLIENT:",
                   snd_buf, *snd_buf, buf_len );

           ret = send_msg( snd_buf,
                           buf_len,
                           lmr_context_send,
                           cookie,
                           DAT_COMPLETION_SUPPRESS_FLAG );

           if(ret != DAT_SUCCESS) {
               fprintf(stderr, "%d Error send_msg: %s\n",
                                   getpid(),DT_RetToString(ret));
               return(ret);
           }
           else {
               LOGPRINTF("%d send_msg completed\n", getpid());
           }
       }

       /* next buffers */
       rcv_buf += buf_len;
       snd_buf += buf_len;
    }
    stop = get_time();
    time.rtt = ((stop - start)*1.0e6);

    return ( DAT_SUCCESS );
}

/* Register RDMA Receive buffer */
DAT_RETURN
register_rdma_memory(void)
{
    DAT_RETURN                         ret;
    DAT_REGION_DESCRIPTION region;

    region.for_va = rbuf;
    start = get_time();
    ret = dat_lmr_create(      h_ia,
                           DAT_MEM_TYPE_VIRTUAL,
                           region,
                           buf_len*burst,
                           h_pz,
                           DAT_MEM_PRIV_ALL_FLAG,
                           &h_lmr_recv,
                           &lmr_context_recv,
                           &rmr_context_recv,
                           &registered_size_recv,
                           &registered_addr_recv );
    stop = get_time();
    time.reg += ((stop - start)*1.0e6);
    time.total += time.reg;

    if(ret != DAT_SUCCESS) {
       fprintf(stderr, "%d Error registering recv buffer: %s\n",
               getpid(),DT_RetToString(ret));
       return (ret);
    } else {
           LOGPRINTF("%d Registered Receive RDMA Buffer %p\n",
                       getpid(),region.for_va);
    }

    /* Register RDMA Send buffer */
    region.for_va = sbuf;
    ret = dat_lmr_create(   h_ia,
                           DAT_MEM_TYPE_VIRTUAL,
                           region,
                           buf_len*burst,
                           h_pz,
                           DAT_MEM_PRIV_ALL_FLAG,
                           &h_lmr_send,
                           &lmr_context_send,
                           &rmr_context_send,
                           &registered_size_send,
                           &registered_addr_send );
    if(ret != DAT_SUCCESS) {
           fprintf(stderr, "%d Error registering send RDMA buffer: %s\n",
                           getpid(),DT_RetToString(ret));
           return (ret);
    } else {
           LOGPRINTF("%d Registered Send RDMA Buffer %p\n",
                   getpid(),region.for_va);
    }

    return DAT_SUCCESS;
}

/*
 * Unregister RDMA memory
 */
DAT_RETURN
unregister_rdma_memory(void)
{
    DAT_RETURN ret;

    /* Unregister Recv Buffer */
    if ( h_lmr_recv != DAT_HANDLE_NULL ) {
       LOGPRINTF("%d Unregister h_lmr %p \n",getpid(),h_lmr_recv);
        start = get_time();
       ret = dat_lmr_free(h_lmr_recv);
        stop = get_time();
       time.unreg += ((stop - start)*1.0e6);
       time.total += time.unreg;
       if(ret != DAT_SUCCESS) {
           fprintf(stderr, "%d Error deregistering recv mr: %s\n",
                       getpid(), DT_RetToString(ret));
           return (ret);
       }
       else {
           LOGPRINTF("%d Unregistered Recv Buffer\n",getpid());
           h_lmr_recv = NULL;
       }
    }

    /* Unregister Send Buffer */
    if ( h_lmr_send != DAT_HANDLE_NULL ) {
       LOGPRINTF("%d Unregister h_lmr %p \n",getpid(),h_lmr_send);
       ret = dat_lmr_free(h_lmr_send);
        if(ret != DAT_SUCCESS) {
           fprintf(stderr, "%d Error deregistering send mr: %s\n",
                           getpid(), DT_RetToString(ret));
           return (ret);
       }
       else {
           LOGPRINTF("%d Unregistered send Buffer\n",getpid());
           h_lmr_send = NULL;
       }
    }
    return DAT_SUCCESS;
}

 /*
  * Create CNO, CR, CONN, and DTO events
  */
DAT_RETURN
create_events(void)
{
    DAT_RETURN ret;

    /* create CNO */
    if (use_cno) {
        start = get_time();
        ret = dat_cno_create( h_ia, DAT_OS_WAIT_PROXY_AGENT_NULL, &h_dto_cno  );
        stop = get_time();
       time.cnoc += ((stop - start)*1.0e6);
       time.total += time.cnoc;
       if(ret != DAT_SUCCESS) {
           fprintf(stderr, "%d Error dat_cno_create: %s\n",
                               getpid(),DT_RetToString(ret));
           return (ret);
       }
       else {
           LOGPRINTF("%d cr_evd created, %p\n", getpid(), h_dto_cno);
       }
    }

    /* create cr EVD */
    start = get_time();
    ret = dat_evd_create( h_ia, 10, DAT_HANDLE_NULL, DAT_EVD_CR_FLAG, &h_cr_evd  );
    stop = get_time();
    time.evdc += ((stop - start)*1.0e6);
    time.total += time.evdc;
    if(ret != DAT_SUCCESS) {
        fprintf(stderr, "%d Error dat_evd_create: %s\n",
                           getpid(),DT_RetToString(ret));
        return (ret);
    }
    else {
        LOGPRINTF("%d cr_evd created %p\n", getpid(),h_cr_evd);
    }

    /* create conn EVD */
    ret = dat_evd_create( h_ia, 10, DAT_HANDLE_NULL, DAT_EVD_CONNECTION_FLAG, &h_conn_evd  );
    if(ret != DAT_SUCCESS) {
        fprintf(stderr, "%d Error dat_evd_create: %s\n",
                           getpid(),DT_RetToString(ret));
        return (ret);
    }
    else {
        LOGPRINTF("%d con_evd created %p\n", getpid(),h_conn_evd);
    }

    /* create dto SND EVD, with CNO if use_cno was set */
    ret = dat_evd_create( h_ia,
                         MSG_BUF_COUNT+MAX_RDMA_RD+burst*2,
                         h_dto_cno,
                         DAT_EVD_DTO_FLAG,
                         &h_dto_req_evd  );
    if(ret != DAT_SUCCESS) {
        fprintf(stderr, "%d Error dat_evd_create REQ: %s\n",
                           getpid(),DT_RetToString(ret));
        return (ret);
    }
    else {
        LOGPRINTF("%d dto_req_evd created %p\n", getpid(), h_dto_req_evd );
    }

    /* create dto RCV EVD, with CNO if use_cno was set */
    ret = dat_evd_create( h_ia,
                         MSG_BUF_COUNT,
                         h_dto_cno,
                         DAT_EVD_DTO_FLAG,
                         &h_dto_rcv_evd  );
    if(ret != DAT_SUCCESS) {
        fprintf(stderr, "%d Error dat_evd_create RCV: %s\n",
                           getpid(),DT_RetToString(ret));
        return (ret);
    }
    else {
        LOGPRINTF("%d dto_rcv_evd created %p\n", getpid(), h_dto_rcv_evd );
    }

    return DAT_SUCCESS;
}

/*
 * Destroy CR, CONN, CNO, and DTO events
 */
DAT_RETURN
destroy_events(void)
{
       DAT_RETURN      ret;

       /* free cr EVD */
    if ( h_cr_evd != DAT_HANDLE_NULL ) {
        LOGPRINTF("%d Free cr EVD %p \n",getpid(),h_cr_evd);
        ret = dat_evd_free( h_cr_evd );
        if(ret != DAT_SUCCESS) {
                   fprintf(stderr, "%d Error freeing cr EVD: %s\n",
                           getpid(), DT_RetToString(ret));
                       return (ret);
           } else {
                   LOGPRINTF("%d Freed cr EVD\n",getpid());
            h_cr_evd = DAT_HANDLE_NULL;
           }
    }

    /* free conn EVD */
    if ( h_conn_evd != DAT_HANDLE_NULL ) {
        LOGPRINTF("%d Free conn EVD %p \n",getpid(),h_conn_evd);
        ret = dat_evd_free( h_conn_evd );
        if(ret != DAT_SUCCESS) {
           fprintf(stderr, "%d Error freeing conn EVD: %s\n",
                       getpid(), DT_RetToString(ret));
           return (ret);
       }
       else {
           LOGPRINTF("%d Freed conn EVD\n",getpid());
           h_conn_evd = DAT_HANDLE_NULL;
       }
    }

    /* free RCV dto EVD */
    if ( h_dto_rcv_evd != DAT_HANDLE_NULL ) {
        LOGPRINTF("%d Free RCV dto EVD %p \n",getpid(),h_dto_rcv_evd);
        start = get_time();
       ret = dat_evd_free( h_dto_rcv_evd );
        stop = get_time();
       time.evdf += ((stop - start)*1.0e6);
       time.total += time.evdf;
        if(ret != DAT_SUCCESS) {
           fprintf(stderr, "%d Error freeing dto EVD: %s\n",
                           getpid(), DT_RetToString(ret));
           return (ret);
       }
       else {
           LOGPRINTF("%d Freed dto EVD\n",getpid());
            h_dto_rcv_evd = DAT_HANDLE_NULL;
       }
    }

    /* free REQ dto EVD */
    if ( h_dto_req_evd != DAT_HANDLE_NULL ) {
        LOGPRINTF("%d Free REQ dto EVD %p \n",getpid(),h_dto_req_evd);
        ret = dat_evd_free( h_dto_req_evd );
        if(ret != DAT_SUCCESS) {
           fprintf(stderr, "%d Error freeing dto EVD: %s\n",
                           getpid(), DT_RetToString(ret));
           return (ret);
       }
       else {
           LOGPRINTF("%d Freed dto EVD\n",getpid());
            h_dto_req_evd = DAT_HANDLE_NULL;
       }
    }

    /* free CNO */
    if ( h_dto_cno != DAT_HANDLE_NULL ) {
        LOGPRINTF("%d Free dto CNO %p \n",getpid(),h_dto_cno);
        start = get_time();
        ret = dat_cno_free( h_dto_cno );
        stop = get_time();
        time.cnof += ((stop - start)*1.0e6);
        time.total += time.cnof;
        if(ret != DAT_SUCCESS) {
           fprintf(stderr, "%d Error freeing dto CNO: %s\n",
                   getpid(), DT_RetToString(ret));
           return (ret);
       }
       else {
           LOGPRINTF("%d Freed dto CNO\n",getpid());
            h_dto_cno = DAT_HANDLE_NULL;
       }
    }
    return DAT_SUCCESS;
}

/*
 * Map DAT_RETURN values to readable strings,
 * but don't assume the values are zero-based or contiguous.
 */
char    errmsg[512] = {0};
const char *
DT_RetToString (DAT_RETURN ret_value)
{
    const char *major_msg, *minor_msg;

    dat_strerror (ret_value, &major_msg, &minor_msg);

    strcpy(errmsg, major_msg);
    strcat(errmsg, " ");
    strcat(errmsg, minor_msg);

    return errmsg;
}

/*
 * Map DAT_EVENT_CODE values to readable strings
 */
const char *
DT_EventToSTr (DAT_EVENT_NUMBER event_code)
{
    unsigned int i;
    static struct {
           const char  *name;
           DAT_RETURN  value;
    }
    dat_events[] =
    {
           #   define DATxx(x) { # x, x }
           DATxx (DAT_DTO_COMPLETION_EVENT),
           DATxx (DAT_RMR_BIND_COMPLETION_EVENT),
           DATxx (DAT_CONNECTION_REQUEST_EVENT),
           DATxx (DAT_CONNECTION_EVENT_ESTABLISHED),
           DATxx (DAT_CONNECTION_EVENT_PEER_REJECTED),
           DATxx (DAT_CONNECTION_EVENT_NON_PEER_REJECTED),
           DATxx (DAT_CONNECTION_EVENT_ACCEPT_COMPLETION_ERROR),
           DATxx (DAT_CONNECTION_EVENT_DISCONNECTED),
           DATxx (DAT_CONNECTION_EVENT_BROKEN),
           DATxx (DAT_CONNECTION_EVENT_TIMED_OUT),
           DATxx (DAT_CONNECTION_EVENT_UNREACHABLE),
           DATxx (DAT_ASYNC_ERROR_EVD_OVERFLOW),
           DATxx (DAT_ASYNC_ERROR_IA_CATASTROPHIC),
           DATxx (DAT_ASYNC_ERROR_EP_BROKEN),
           DATxx (DAT_ASYNC_ERROR_TIMED_OUT),
           DATxx (DAT_ASYNC_ERROR_PROVIDER_INTERNAL_ERROR),
           DATxx (DAT_SOFTWARE_EVENT)
           #   undef DATxx
    };
    #   define NUM_EVENTS (sizeof(dat_events)/sizeof(dat_events[0]))

    for (i = 0;  i < NUM_EVENTS;  i++) {
           if (dat_events[i].value == event_code)
           {
               return ( dat_events[i].name );
           }
    }

    return ( "Invalid_DAT_EVENT_NUMBER" );
}


void print_usage()
{
    printf("\n DAPL USAGE \n\n");
    printf("s: server\n");
    printf("c: use cno\n");
    printf("v: verbose\n");
    printf("p: polling\n");
    printf("d: delay before accept\n");
    printf("b: buf length to allocate\n");
    printf("B: burst count, rdma and msgs \n");
    printf("h: hostname\n");
    printf("P: provider (default=OpenIB-cma)\n");
    printf("\n");
}

