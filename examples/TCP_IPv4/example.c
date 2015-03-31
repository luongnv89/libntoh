/********************************************************************************
 * Copyright (c) 2011, Chema Garcia                                             *
 * All rights reserved.                                                         *
 *                                                                              *
 * Redistribution and use in source and binary forms, with or                   *
 * without modification, are permitted provided that the following              *
 * conditions are met:                                                          *
 *                                                                              *
 *    * Redistributions of source code must retain the above                    *
 *      copyright notice, this list of conditions and the following             *
 *      disclaimer.                                                             *
 *                                                                              *
 *    * Redistributions in binary form must reproduce the above                 *
 *      copyright notice, this list of conditions and the following             *
 *      disclaimer in the documentation and/or other materials provided         *
 *      with the distribution.                                                  *
 *                                                                              *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"  *
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE    *
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE   *
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE    *
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR          *
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF         *
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS     *
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN      *
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)      *
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE   *
 * POSSIBILITY OF SUCH DAMAGE.                                                  *
 ********************************************************************************/

/*
 * This example save the data sent by each peer in a separated file called: [src_ip]:[src_port]-[dst_ip]:[dst_port]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <errno.h>

#ifndef __FAVOR_BSD
# define __FAVOR_BSD
#endif

#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <pcap.h>
#include <libntoh.h>

typedef struct
{
	unsigned char *data;
	size_t data_len;
	char *path;
} peer_info_t , *ppeer_info_t;

#define RECV_CLIENT	1
#define RECV_SERVER	2

/* capture handle */
pcap_t 					*handle = 0;
pntoh_tcp_session_t		tcp_session = 0;
pntoh_ipv4_session_t	ipv4_session = 0;
unsigned short			receive = 0;

/**
 * @brief Exit function (closes the capture handle and releases all resource from libntoh)
 */
void shandler ( int sign )
{
	if ( sign != 0 )
		signal ( sign , &shandler );

	pcap_close( handle );

	ntoh_exit();

	fprintf( stderr, "\n\n[+] Capture finished!\n" );
	exit( sign );
}

/**
 * @brief Returns a struct which stores some peer information
 */
ppeer_info_t get_peer_info ( unsigned char *payload , size_t payload_len , pntoh_tcp_tuple5_t tuple )
{
	ppeer_info_t ret = 0;
	size_t len = 0;
	char path[1024] = {0};

	/* gets peer information */
	ret = (ppeer_info_t) calloc ( 1 , sizeof ( peer_info_t ) );
	ret->data_len = payload_len;
	ret->data = (unsigned char*) calloc ( ret->data_len , sizeof ( unsigned char ) );
	memcpy ( ret->data , payload , ret->data_len );

	snprintf ( path , sizeof(path) , "%s:%d-" , inet_ntoa ( *(struct in_addr*)&(tuple->source) ) , ntohs(tuple->sport) );
	len = strlen(path);
	snprintf ( &path[len] , sizeof(path) - len, "%s:%d" , inet_ntoa ( *(struct in_addr*)&(tuple->destination) ) , ntohs(tuple->dport) );

	ret->path = strndup ( path , sizeof(path) );

	return ret;
}

/**
 * @brief Frees the ppeer_info_t struct
 */
void free_peer_info ( ppeer_info_t pinfo )
{
	/* free peer info data */
	if ( ! pinfo )
		return;

	free ( pinfo->data );
	free ( pinfo->path );
	free ( pinfo );

	return;
}

/**
 * @brief Returns the name of a protocol
 */
inline char *get_proto_description ( unsigned short proto )
{
	switch ( proto )
	{
		case IPPROTO_ICMP:
			return "ICMP";

		case IPPROTO_TCP:
			return "TCP";

		case IPPROTO_UDP:
			return "UDP";

		case IPPROTO_IGMP:
			return "IGMP";

		case IPPROTO_IPV6:
			return "IPv6";

		case IPPROTO_FRAGMENT:
			return "IPv6 Fragment";

		default:
			return "Undefined";
	}
}

/**
 * @brief Writes the ppeer_info_t data field to disk
 */
void write_data ( ppeer_info_t info )
{
	int fd = 0;

	if ( !info )
		return;

	if ( (fd = open ( info->path , O_CREAT | O_WRONLY | O_APPEND | O_NOFOLLOW , S_IRWXU | S_IRWXG | S_IRWXO )) < 0 )
	{
		fprintf ( stderr , "\n[e] Error %d writting data to \"%s\": %s" , errno , info->path , strerror( errno ) );
		return;
	}

	write ( fd , info->data , info->data_len );
	close ( fd );

	return;
}

/**
 * @brief Send a TCP segment to libntoh
 */
void send_tcp_segment ( struct ip *iphdr , pntoh_tcp_callback_t callback )
{
	ppeer_info_t		pinfo;
	ntoh_tcp_tuple5_t	tcpt5;
	pntoh_tcp_stream_t	stream;
	struct tcphdr 		*tcp;
	size_t 				size_ip;
	size_t				total_len;
	size_t				size_tcp;
	size_t				size_payload;
	unsigned char		*payload;
	int					ret;
	unsigned int		error;
	// ip header
	size_ip = iphdr->ip_hl * 4;
	total_len = ntohs( iphdr->ip_len );
	// tcp header
	tcp = (struct tcphdr*)((unsigned char*)iphdr + size_ip);
	if ( (size_tcp = tcp->th_off * 4) < sizeof(struct tcphdr) )
		return;
	// data payload
	payload = (unsigned char *)iphdr + size_ip + size_tcp;
	size_payload = total_len - ( size_ip + size_tcp );
	/**
	 * @brief Get the tuple5
	 * @details Get the tuple5 of a tcp segment
	 * 
	 * @param iphdr IPv4 header
	 * @param tcp tcp header
	 * @param tcpt5 pointer to the output tuple5 struct
	 * @return 
	 * 
    NTOH_ERROR_PARAMS
    NTOH_OK

	 */
	ntoh_tcp_get_tuple5 ( iphdr , tcp , &tcpt5 );

	/* Find a stream */
	if ( !( stream = ntoh_tcp_find_stream( tcp_session , &tcpt5 ) ) )
		/**
		 * pntoh_tcp_stream_t ntoh_tcp_new_stream ( pntoh_tcp_session_t session , pntoh_tcp_tuple5_t tuple5 , pntoh_tcp_callback_t function ,void *udata , unsigned int *error, unsigned short enable_check_timeout, unsigned short enable_check_nowindow )
		 * @brief Create a new tcp stream
		 * @details Create a new tcp stream
		 * 
		 * @param tcp_session	TCP session
		 * @param tuple5	identifying the new stream
		 * @param callback	function callback after creating new stream
		 * @param 0	User-data linked to the new stream
		 * @param error	Returned error code:
		 * value of error code:
		 * 
		    NTOH_ERROR_PARAMS
		    NTOH_ERROR_NOKEY
		    NTOH_ERROR_NOFUNCTION
		    NTOH_ERROR_INVALID_TUPLE5
		    NTOH_ERROR_NOSPACE
		    NTOH_ERROR_NOMEM

		 * @param enable_check_timeout	Enable check timeout
		 * @param enable_check_nowindow	Enable check no window
		 * @return NULL or a pointer to the new stream
		 */
		if ( ! ( stream = ntoh_tcp_new_stream( tcp_session , &tcpt5, callback , 0 , &error , 1 , 1 ) ) )
		{
			fprintf ( stderr , "\n[e] Error %d creating new stream: %s" , error , ntoh_get_errdesc ( error ) );
			return;
		}
	// size_payload: size of data
	if ( size_payload > 0 )
		// data segment
		pinfo = get_peer_info ( payload , size_payload , &tcpt5 );
	else
		// ack
		pinfo = 0;

	/** Add a tcp segment to a stream 
	 * @brief [brief description]
	 * @details [long description]
	 * 
	 * @param tcp_session TCP Session
	 * @param stream TCP stream where the new segment will be added
	 * @param iphdr  IPv4 header
	 * @param total_len Total length (IPv4 header + payload)
	 * @param (void*)pinfo  User-defined data to be linked with the new segment
	 * @return 
	 * 
	    NTOH_OK: No error
	    NTOH_ERROR_PARAMS
	    NTOH_SYNCHRONIZING: Not an error, but no segment was created (data acknowledged)
	    NTOH_INCORRECT_IPHEADER
	    NTOH_INCORRECT_LENGTH
	    NTOH_INCORRECT_IP_HEADER_LENGTH
	    NTOH_NO_ENOUGH_DATA
	    NTOH_NOT_IPV4
	    NTOH_IP_ADDRESSES_MISMATCH
	    NTOH_NOT_TCP
	    NTOH_INCORRECT_TCP_HEADER_LENGTH
	    NTOH_INVALID_FLAGS
	    NTOH_TCP_PORTS_MISMATCH
	    NTOH_PAWS_FAILED
	    NTOH_TOO_LOW_SEQ_NUMBER
	    NTOH_TOO_LOW_ACK_NUMBER
	    NTOH_HANDSHAKE_FAILED
	    NTOH_MAX_SYN_RETRIES_REACHED
	    NTOH_MAX_SYNACK_RETRIES_REACHED
	    NTOH_NO_WINDOW_SPACE_LEFT

	 */
	switch ( ( ret = ntoh_tcp_add_segment( tcp_session , stream, iphdr, total_len, (void*)pinfo ) ) )
	{
		case NTOH_OK:
			break;

		case NTOH_SYNCHRONIZING:
			free_peer_info ( pinfo );
			break;

		default:
			fprintf( stderr, "\n[e] Error %d adding segment: %s", ret, ntoh_get_retval_desc( ret ) );
			free_peer_info ( pinfo );
			break;
	}

	return;
}

/**
 * @brief Sends a IPv4 fragment to libntoh
 */
void send_ipv4_fragment ( struct ip *iphdr , pipv4_dfcallback_t callback )
{
	ntoh_ipv4_tuple4_t 	ipt4;
	pntoh_ipv4_flow_t 	flow;
	size_t			total_len;
	int 			ret;
	unsigned int		error;

	// Get total length - ip header
	total_len = ntohs( iphdr->ip_len );
	/**
	 * @brief Get the tuple4
	 * @details Get the tuple4 - identification of a flow
	 * 
	 * @param r ip header
	 * @param t4 tuple4 pointer to store result
	 * 
	 * @return NTOH_ERROR_PARAMS
	 * NTOH_OK
	 */
	ntoh_ipv4_get_tuple4 ( iphdr , &ipt4 );
	// Find an IPv4 flow: (pntoh_ipv4_session_t session, pntoh_ipv4_tuple4_t tuple4)
	if ( !( flow = ntoh_ipv4_find_flow( ipv4_session , &ipt4 ) ) )
		// create a new flow: (pntoh_ipv4_session_t session,pntoh_ipv4_tuple4_t tuple4, pipv4_dfcallback_t function, void *udata, usigned int *error)
		if ( ! (flow = ntoh_ipv4_new_flow( ipv4_session , &ipt4, callback, 0 , &error )) )
		{
			fprintf ( stderr , "\n[e] Error %d creating new IPv4 flow: %s" , error , ntoh_get_errdesc ( error ) );
			return;
		}
	/** 
	* Add a fragment to a given IPv4 flow: (pntoh_ipv4_session_t session, pntoh_ipv4_flow_t flow, struct ip *iphdr, size_t len)
	* len: total length = IPv4 header + payload
	* return: 
	* 	- NTOH_OK: on success
	* 	
	* 	If failure:
	* 	 	NTOH_IP_INCORRECT_FLOW
			NTOH_INCORRECT_IPHEADER
			NTOH_INCORRECT_LENGTH
			NTOH_INCORRECT_IP_HEADER_LENGTH
			NTOH_NO_ENOUGH_DATA
			NTOH_NOT_IPV4
			NTOH_IP_ADDRESSES_MISMATCH
			NTOH_NOT_AN_IP_FRAGMENT
			NTOH_TOO_LOW_IP_FRAGMENT_LENGTH
			NTOH_IP_FRAGMENT_OVERRUN
	*/
	if ( ( ret = ntoh_ipv4_add_fragment( ipv4_session , flow, iphdr, total_len ) ) )
		fprintf( stderr, "\n[e] Error %d adding IPv4: %s", ret, ntoh_get_retval_desc( ret ) );

	return;
}

/**
 * typedef void(*pntoh_tcp_callback_t) ( pntoh_tcp_stream_t stream , pntoh_tcp_peer_t origin, pntoh_tcp_peer_t destination, pntoh_tcp_segment_t segment, int reason, int extra );
 * @brief TCP callback
 * @details [long description]
 * 
 * @param stream TCP Stream
 * @param orig Sender of this segment
 * @param dest Receiver of this segment
 * @param seg Reassembled segment
 * @param reason  Why the segment is sent?
 * 
    NTOH_REASON_DATA: We got a new segment
    NTOH_REASON_SYNC: Not a segment but synchronization

 * @param extra Why the datagram is sent? (extra information) depends on "reason"
 * 

    Reason: NTOH_REASON_DATA
        NTOH_REASON_OOO
        NTOH_REASON_NOWINDOW
        NTOH_REASON_EXIT
        NTOH_REASON_CLOSED
        NTOH_REASON_TIMEDOUT

    Reason: NTOH_REASON_SYNC
        NTOH_REASON_MAX_SYN_RETRIES_REACHED
        NTOH_REASON_MAX_SYNACK_RETRIES_REACHED
        NTOH_REASON_HSFAILED
        NTOH_REASON_EXIT
        NTOH_REASON_TIMEDOUT
        NTOH_REASON_CLOSED
        NTOH_REASON_ESTABLISHED
        NTOH_REASON_SYNC

 * 
 */
void tcp_callback ( pntoh_tcp_stream_t stream , pntoh_tcp_peer_t orig , pntoh_tcp_peer_t dest , pntoh_tcp_segment_t seg , int reason , int extra )
{
	/* receive data only from the peer given by the user */
	if ( receive == RECV_CLIENT && stream->server.receive )
	{
		stream->server.receive = 0;
		return;
	}else if ( receive == RECV_SERVER && stream->client.receive )
	{
		stream->client.receive = 0;
		return;
	}

	/*
	ntoh_tcp_get_status
	enum _ntoh_tcp_status_
	{
	    NTOH_STATUS_CLOSED = 0,
	    NTOH_STATUS_LISTEN,
	    NTOH_STATUS_SYNSENT,
	    NTOH_STATUS_SYNRCV,
	    NTOH_STATUS_ESTABLISHED,
	    NTOH_STATUS_CLOSING,
	    NTOH_STATUS_CLOSEWAIT,
	    NTOH_STATUS_FINWAIT1,
	    NTOH_STATUS_FINWAIT2,
	    NTOH_STATUS_LASTACK,
	    NTOH_STATUS_TIMEWAIT
	};
	*/
	fprintf ( stderr , "\n[%s] %s:%d (%s | Window: %lu) ---> " , ntoh_tcp_get_status ( stream->status ) , inet_ntoa( *(struct in_addr*) &orig->addr ) , ntohs(orig->port) , ntoh_tcp_get_status ( orig->status ) , orig->totalwin );
	fprintf ( stderr , "%s:%d (%s | Window: %lu)\n\t" , inet_ntoa( *(struct in_addr*) &dest->addr ) , ntohs(dest->port) , ntoh_tcp_get_status ( dest->status ) , dest->totalwin );

	if ( seg != 0 )
		fprintf ( stderr , "SEQ: %lu ACK: %lu Next SEQ: %lu" , seg->seq , seg->ack , orig->next_seq );

	switch ( reason )
	{
		case NTOH_REASON_SYNC:
	        switch ( extra )
	        {
	            case NTOH_REASON_MAX_SYN_RETRIES_REACHED:
	            case NTOH_REASON_MAX_SYNACK_RETRIES_REACHED:
	            case NTOH_REASON_HSFAILED:
	            case NTOH_REASON_EXIT:
	            case NTOH_REASON_TIMEDOUT:
	            case NTOH_REASON_CLOSED:
	                if ( extra == NTOH_REASON_CLOSED )
	                    fprintf ( stderr , "\n\t+ Connection closed by %s (%s)" , stream->closedby == NTOH_CLOSEDBY_CLIENT ? "Client" : "Server" , inet_ntoa( *(struct in_addr*) &(stream->client.addr) ) );
	                else
	                    fprintf ( stderr , "\n\t+ %s/%s - %s" , ntoh_get_reason ( reason ) , ntoh_get_reason ( extra ) , ntoh_tcp_get_status ( stream->status ) );

	                break;
	        }

	        break;

		/* Data segment */
		case NTOH_REASON_DATA:
			fprintf ( stderr , " | Data segment | Bytes: %i" , seg->payload_len );

			/* write data */
			write_data( (ppeer_info_t) seg->user_data );

			if ( extra != 0 )
					fprintf ( stderr , "- %s" , ntoh_get_reason ( extra ) );

			break;
	}

	if ( seg != 0 )
		free_peer_info ( (ppeer_info_t) seg->user_data );

	fprintf ( stderr , "\n" );

	return;
}

/**
 * @brief IPv4 callback
 * @details be called each time new flow is created
 * 
 * @param flow Ipv4 flow where the defragmented datagrams of the sent datagram where stored
 * @param tuple tuple4 identifying the flow
 * @param char defragmented datagram
 * @param len total length of the defragmented datagram (IPv4 header + payload)
 * @param short reason why the datagram is sent
 * value of reason: NTOH_REASON_DEFRAGMENTED_DATAGRAM or NTOH_REASON_TIMEDOUT_FRAGMENTS
 */
void ipv4_callback ( pntoh_ipv4_flow_t flow , pntoh_ipv4_tuple4_t tuple , unsigned char *data , size_t len , unsigned short reason )
{
	unsigned int i = 0;

	fprintf( stderr, "\n\n[i] Got an IPv4 datagram! (%s) %s --> ", ntoh_get_reason(reason) , inet_ntoa( *(struct in_addr*) &tuple->source ) );
	fprintf( stderr, "%s | %i/%i bytes - Key: %04x - ID: %02x - Proto: %d (%s)\n\n", inet_ntoa( *(struct in_addr*) &tuple->destination ), len, flow->total , flow->key, ntohs( tuple->id ), tuple->protocol, get_proto_description( tuple->protocol ) );

	if ( tuple->protocol == IPPROTO_TCP )
		send_tcp_segment ( (struct ip*) data , &tcp_callback );
	else
		for ( i = 0; i < flow->total ; i++ )
			fprintf( stderr, "%02x ", data[i] );

	fprintf( stderr, "\n" );

	return;
}

int main ( int argc , char *argv[] )
{
	/* parameters parsing */
	int c;

	/* pcap */
	char 				errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program 	fp;
	char 				filter_exp[] = "ip";
	char 				*source = 0;
	char 				*filter = filter_exp;
	const unsigned char *packet = 0;
	struct pcap_pkthdr 	header;

	/* packet dissection */
	struct ip		*ip;
	unsigned int	error;

	/* extra */
	unsigned int ipf,tcps;

	fprintf( stderr, "\n###########################" );
	fprintf( stderr, "\n#     libntoh Example     #" );
	fprintf( stderr, "\n# ----------------------- #" );
	fprintf( stderr, "\n# Written by Chema Garcia #" );
	fprintf( stderr, "\n# ----------------------- #" );
	fprintf( stderr, "\n#  http://safetybits.net  #" );
	fprintf( stderr, "\n#   chema@safetybits.net  #" );
	fprintf( stderr, "\n#   sch3m4@brutalsec.net  #" );
	fprintf( stderr, "\n###########################\n" );

	fprintf( stderr, "\n[i] libntoh version: %s\n", ntoh_version() );

	if ( argc < 3 )
	{
		fprintf( stderr, "\n[+] Usage: %s <options>\n", argv[0] );
		fprintf( stderr, "\n+ Options:" );
		fprintf( stderr, "\n\t-i | --iface <val> -----> Interface to read packets from" );
		fprintf( stderr, "\n\t-f | --file <val> ------> File path to read packets from" );
		fprintf( stderr, "\n\t-F | --filter <val> ----> Capture filter (must contain \"tcp\" or \"ip\")" );
		fprintf( stderr, "\n\t-c | --client ----------> Receive client data only");
		fprintf( stderr, "\n\t-s | --server ----------> Receive server data only\n\n");
		exit( 1 );
	}

	/* check parameters */
	while ( 1 )
	{
		int option_index = 0;
		static struct option long_options[] =
		{
		{ "iface" , 1 , 0 , 'i' } ,
		{ "file" , 1 , 0 , 'f' } ,
		{ "filter" , 1 , 0 , 'F' } ,
		{ "client" , 0 , 0 , 'c' },
		{ "server" , 0 , 0 , 's' },
		{ 0 , 0 , 0 , 0 } };

		if ( ( c = getopt_long( argc, argv, "i:f:F:cs", long_options, &option_index ) ) < 0 )
			break;

		switch ( c )
		{
			case 'i':
				source = optarg;
				handle = pcap_open_live( optarg, 65535, 1, 0, errbuf );
				break;

			case 'f':
				source = optarg;
				handle = pcap_open_offline( optarg, errbuf );
				break;

			case 'F':
				filter = optarg;
				break;

			case 'c':
				receive |= RECV_CLIENT;
				break;

			case 's':
				receive |= RECV_SERVER;
				break;
		}
	}

	if ( !receive )
		receive = (RECV_CLIENT | RECV_SERVER);

	if ( !handle )
	{
		fprintf( stderr, "\n[e] Error loading %s: %s\n", source, errbuf );
		exit( -1 );
	}

	if ( pcap_compile( handle, &fp, filter, 0, 0 ) < 0 )
	{
		fprintf( stderr, "\n[e] Error compiling filter \"%s\": %s\n\n", filter, pcap_geterr( handle ) );
		pcap_close( handle );
		exit( -2 );
	}

	if ( pcap_setfilter( handle, &fp ) < 0 )
	{
		fprintf( stderr, "\n[e] Cannot set filter \"%s\": %s\n\n", filter, pcap_geterr( handle ) );
		pcap_close( handle );
		exit( -3 );
	}
	pcap_freecode( &fp );

	/* verify datalink */
	if ( pcap_datalink( handle ) != DLT_EN10MB )
	{
		fprintf ( stderr , "\n[e] libntoh is independent from link layer, but this example only works with ethernet link layer\n");
		pcap_close ( handle );
		exit ( -4 );
	}

	fprintf( stderr, "\n[i] Source: %s / %s", source, pcap_datalink_val_to_description( pcap_datalink( handle ) ) );
	fprintf( stderr, "\n[i] Filter: %s", filter );

	fprintf( stderr, "\n[i] Receive data from client: ");
	if ( receive & RECV_CLIENT )
		fprintf( stderr , "Yes");
	else
		fprintf( stderr , "No");

	fprintf( stderr, "\n[i] Receive data from server: ");
	if ( receive & RECV_SERVER )
		fprintf( stderr , "Yes");
	else
		fprintf( stderr , "No");

	signal( SIGINT, &shandler );
	signal( SIGTERM, &shandler );

	/*******************************************/
	/** libntoh initialization process starts **/
	/*******************************************/

	// Initialize the library (TCP and IPv4)
	ntoh_init ();

	/* Create new TCP session: 
	pntoh_tcp_session_t ntoh_tcp_new_session ( unsigned int max_streams , unsigned int max_timewait , unsigned int *error );

    max_streams: Maximum number of allowed streams in this session
    max_timewait: Maximum number of streams with TIME-WAIT status in this session
    *error: Returned error code

	*/
	if ( ! (tcp_session = ntoh_tcp_new_session ( 0 , 0 , &error ) ) )
	{
		fprintf ( stderr , "\n[e] Error %d creating TCP session: %s" , error , ntoh_get_errdesc ( error ) );
		exit ( -5 );
	}

	fprintf ( stderr , "\n[i] Max. TCP streams allowed: %d" , ntoh_tcp_get_size ( tcp_session ) );

	// Create new IPv4 session: pntoh_ipv4_session_t ntoh_ipv4_new_session(unsigned int max_flows, unsigned long max_mem, unsigned int *error)
	if ( ! (ipv4_session = ntoh_ipv4_new_session ( 0 , 0 , &error )) )
	{	
		/*Free session: 
		void ntoh_tcp_free_session(pntoh_tcp_session_t session)
		*/
		ntoh_tcp_free_session ( tcp_session );
		fprintf ( stderr , "\n[e] Error %d creating IPv4 session: %s" , error , ntoh_get_errdesc ( error ) );
		exit ( -6 );
	}

	fprintf ( stderr , "\n[i] Max. IPv4 flows allowed: %d\n\n" , ntoh_ipv4_get_size ( ipv4_session ) );

	/* capture starts */
	while ( ( packet = pcap_next( handle, &header ) ) != 0 )
	{
		/* get packet headers */
		/*Check IP header*/
		ip = (struct ip*) ( packet + sizeof ( struct ether_header ) );
		if ( (ip->ip_hl * 4 ) < sizeof(struct ip) )
			continue;

		/* it is an IPv4 fragment */
		/** Macro to check if an IPv4 datagram is part of a fragment datagram
		#define NTOH_IPV4_IS_FRAGMENT(off)          ( ( (8*(ntohs(off) & 0x1FFF)) > 0 || (ntohs(off) & 0x2000) ) && !(ntohs(off) & 0x4000) )
		*/
		if ( NTOH_IPV4_IS_FRAGMENT(ip->ip_off) )
			send_ipv4_fragment ( ip , &ipv4_callback );
		/* or a TCP segment */
		else if ( ip->ip_p == IPPROTO_TCP )
			send_tcp_segment ( ip , &tcp_callback );
	}
	// Get the number of stored streams in a session
	tcps = ntoh_tcp_count_streams( tcp_session );
	//Get the number of stored IPv4 flows in a session
	ipf = ntoh_ipv4_count_flows ( ipv4_session );

	/* no streams left */
	if ( ipf + tcps > 0 )
	{
		fprintf( stderr, "\n\n[+] There are currently %i stored TCP stream(s) and %i IPv4 flow(s). You can wait them to get closed or press CTRL+C\n" , tcps , ipf );
		pause();
	}

	shandler( 0 );

	//dummy return
	return 0;
}
