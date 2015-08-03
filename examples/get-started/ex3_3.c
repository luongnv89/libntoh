/*
In this example, we are going to work with tcp segment. It will count the size of data sent by each peer
compile: 
	gcc -g -o test ex3_1.c -lntoh -lpcap -lpthread
Run test & expected result:
./test -f ../data-set/googlefr-tcp-in-order.pcap 
[INFO] (ex3_3.c:107) libntoh version: 0.4a
[INFO] (ex3_3.c:188) Packet index: 0 
[INFO] (ex3_3.c:214) New stream is added from:  192.168.0.45:48487
[INFO] (ex3_3.c:215) to: 64.233.166.94:80
[INFO] (ex3_3.c:40) [SYN Sent] 192.168.0.45:48487 (SYN Sent) --> 192.168.0.45:80 (Listen)
[INFO] (ex3_3.c:41) tcp callback is called
[INFO] (ex3_3.c:188) Packet index: 1 
[INFO] (ex3_3.c:40) [SYN Rcv] 64.233.166.94:80 (SYN Rcv) --> 64.233.166.94:48487 (SYN Sent)
[INFO] (ex3_3.c:41) tcp callback is called
[INFO] (ex3_3.c:188) Packet index: 2 
[INFO] (ex3_3.c:40) [Established] 192.168.0.45:48487 (Established) --> 192.168.0.45:80 (Established)
[INFO] (ex3_3.c:41) tcp callback is called
[INFO] (ex3_3.c:188) Packet index: 3 
[INFO] (ex3_3.c:188) Packet index: 4 
[INFO] (ex3_3.c:40) [Established] 192.168.0.45:48487 (Established) --> 192.168.0.45:80 (Established)
[INFO] (ex3_3.c:41) tcp callback is called
[INFO] (ex3_3.c:65) Segment payload length: 111
[INFO] (ex3_3.c:188) Packet index: 5 
[INFO] (ex3_3.c:188) Packet index: 6 
[INFO] (ex3_3.c:40) [Established] 64.233.166.94:80 (Established) --> 64.233.166.94:48487 (Established)
[INFO] (ex3_3.c:41) tcp callback is called
[INFO] (ex3_3.c:40) [Established] 64.233.166.94:80 (Established) --> 64.233.166.94:48487 (Established)
[INFO] (ex3_3.c:41) tcp callback is called
[INFO] (ex3_3.c:65) Segment payload length: 2836
[INFO] (ex3_3.c:188) Packet index: 7 
[INFO] (ex3_3.c:40) [Established] 192.168.0.45:48487 (Established) --> 192.168.0.45:80 (Established)
[INFO] (ex3_3.c:41) tcp callback is called
[INFO] (ex3_3.c:188) Packet index: 8 
[INFO] (ex3_3.c:40) [Established] 64.233.166.94:80 (Established) --> 64.233.166.94:48487 (Established)
[INFO] (ex3_3.c:41) tcp callback is called
[INFO] (ex3_3.c:65) Segment payload length: 1418
[INFO] (ex3_3.c:188) Packet index: 9 
[INFO] (ex3_3.c:40) [Established] 192.168.0.45:48487 (Established) --> 192.168.0.45:80 (Established)
[INFO] (ex3_3.c:41) tcp callback is called
[INFO] (ex3_3.c:188) Packet index: 10 
[INFO] (ex3_3.c:40) [Established] 64.233.166.94:80 (Established) --> 64.233.166.94:48487 (Established)
[INFO] (ex3_3.c:41) tcp callback is called
[INFO] (ex3_3.c:65) Segment payload length: 1418
[INFO] (ex3_3.c:188) Packet index: 11 
[INFO] (ex3_3.c:40) [Established] 192.168.0.45:48487 (Established) --> 192.168.0.45:80 (Established)
[INFO] (ex3_3.c:41) tcp callback is called
[INFO] (ex3_3.c:188) Packet index: 12 
[INFO] (ex3_3.c:40) [Established] 64.233.166.94:80 (Established) --> 64.233.166.94:48487 (Established)
[INFO] (ex3_3.c:41) tcp callback is called
[INFO] (ex3_3.c:65) Segment payload length: 8508
[INFO] (ex3_3.c:188) Packet index: 13 
[INFO] (ex3_3.c:40) [Established] 192.168.0.45:48487 (Established) --> 192.168.0.45:80 (Established)
[INFO] (ex3_3.c:41) tcp callback is called
[INFO] (ex3_3.c:188) Packet index: 14 
[INFO] (ex3_3.c:40) [Established] 64.233.166.94:80 (Established) --> 64.233.166.94:48487 (Established)
[INFO] (ex3_3.c:41) tcp callback is called
[INFO] (ex3_3.c:65) Segment payload length: 1418
[INFO] (ex3_3.c:188) Packet index: 15 
[INFO] (ex3_3.c:40) [Established] 192.168.0.45:48487 (Established) --> 192.168.0.45:80 (Established)
[INFO] (ex3_3.c:41) tcp callback is called
[INFO] (ex3_3.c:188) Packet index: 16 
[INFO] (ex3_3.c:40) [Established] 64.233.166.94:80 (Established) --> 64.233.166.94:48487 (Established)
[INFO] (ex3_3.c:41) tcp callback is called
[INFO] (ex3_3.c:65) Segment payload length: 1418
[INFO] (ex3_3.c:188) Packet index: 17 
[INFO] (ex3_3.c:40) [Established] 192.168.0.45:48487 (Established) --> 192.168.0.45:80 (Established)
[INFO] (ex3_3.c:41) tcp callback is called
[INFO] (ex3_3.c:188) Packet index: 18 
[INFO] (ex3_3.c:40) [Established] 64.233.166.94:80 (Established) --> 64.233.166.94:48487 (Established)
[INFO] (ex3_3.c:41) tcp callback is called
[INFO] (ex3_3.c:65) Segment payload length: 1418
[INFO] (ex3_3.c:188) Packet index: 19 
[INFO] (ex3_3.c:40) [Established] 192.168.0.45:48487 (Established) --> 192.168.0.45:80 (Established)
[INFO] (ex3_3.c:41) tcp callback is called
[INFO] (ex3_3.c:188) Packet index: 20 
[INFO] (ex3_3.c:40) [Established] 64.233.166.94:80 (Established) --> 64.233.166.94:48487 (Established)
[INFO] (ex3_3.c:41) tcp callback is called
[INFO] (ex3_3.c:65) Segment payload length: 1418
[INFO] (ex3_3.c:188) Packet index: 21 
[INFO] (ex3_3.c:40) [Established] 192.168.0.45:48487 (Established) --> 192.168.0.45:80 (Established)
[INFO] (ex3_3.c:41) tcp callback is called
[INFO] (ex3_3.c:188) Packet index: 22 
[INFO] (ex3_3.c:40) [Established] 64.233.166.94:80 (Established) --> 64.233.166.94:48487 (Established)
[INFO] (ex3_3.c:41) tcp callback is called
[INFO] (ex3_3.c:65) Segment payload length: 1804
[INFO] (ex3_3.c:188) Packet index: 23 
[INFO] (ex3_3.c:40) [Closing] 192.168.0.45:48487 (Fin Wait1) --> 192.168.0.45:80 (Close Wait)
[INFO] (ex3_3.c:41) tcp callback is called
[INFO] (ex3_3.c:188) Packet index: 24 
[INFO] (ex3_3.c:40) [Closing] 192.168.0.45:48487 (Fin Wait1) --> 192.168.0.45:80 (Close Wait)
[INFO] (ex3_3.c:41) tcp callback is called
[INFO] (ex3_3.c:40) [Closing] 64.233.166.94:80 (Close Wait) --> 64.233.166.94:48487 (Fin Wait2)
[INFO] (ex3_3.c:41) tcp callback is called
[INFO] (ex3_3.c:188) Packet index: 25 
[INFO] (ex3_3.c:40) [Closed] 192.168.0.45:48487 (Time Wait) --> 192.168.0.45:80 (Closed)
[INFO] (ex3_3.c:41) tcp callback is called
[INFO] (ex3_3.c:53) Synchronization/Closed -Closed | Connection closed by Client(192.168.0.45)
[INFO] (ex3_3.c:57) Total transfered data:
[INFO] (ex3_3.c:58) - Client: 111 bytes
[INFO] (ex3_3.c:59) - Server: 21656 bytes

That's it!
That's it!
*/
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <pcap.h>
#include <libntoh.h>
#include <dbg.h>

#define SIZE_ETHERNET 14

/* data structure to link to session */
typedef struct{
	unsigned long client;
	unsigned long sever;
}byte_count_t,*pbyte_count_t;

pcap_t *handle;

void shandler(int s){
	if(s!=0)
		signal(s,&shandler);
	pcap_close(handle);
	ntoh_exit();
	fprintf(stderr,"\n\n");
	exit(s);
}

/* TCP callback function*/
void tcp_callback(pntoh_tcp_stream_t stream, pntoh_tcp_peer_t orig,pntoh_tcp_peer_t dest, pntoh_tcp_segment_t seg,int reason, int extra){
	pbyte_count_t btcount = (pbyte_count_t)(stream->udata);
	log_info("[%s] %s:%d (%s) --> %s:%d (%s)",ntoh_tcp_get_status(stream->status),inet_ntoa(*(struct in_addr*)&orig->addr),ntohs(orig->port),ntoh_tcp_get_status(orig->status),inet_ntoa(*(struct in_addr*)&dest->addr),ntohs(dest->port),ntoh_tcp_get_status(dest->status));
	log_info("tcp callback is called");
	switch(reason){
		/* connection synchronization */
		case NTOH_REASON_SYNC:
			switch(extra){
				case NTOH_REASON_MAX_SYN_RETRIES_REACHED:
				case NTOH_REASON_MAX_SYNACK_RETRIES_REACHED:
				case NTOH_REASON_HSFAILED:
				case NTOH_REASON_EXIT:
				case NTOH_REASON_TIMEDOUT:
				case NTOH_REASON_CLOSED:
					if(extra==NTOH_REASON_CLOSED){
						log_info("%s/%s -%s | Connection closed by %s(%s)",ntoh_get_reason(reason),ntoh_get_reason(extra),ntoh_tcp_get_status(stream->status),stream->closedby == NTOH_CLOSEDBY_CLIENT?"Client":"Server",inet_ntoa(*(struct in_addr*)&(stream->client.addr)));
					}else{
						log_info("\t %s/%s - %s",ntoh_get_reason(reason),ntoh_get_reason(extra),ntoh_tcp_get_status(stream->status));
					}
					log_info("Total transfered data:");
					log_info("- Client: %lu bytes",btcount->client);
					log_info("- Server: %lu bytes",btcount->sever);
					free(btcount);
					break;
			}
			break;
		case NTOH_REASON_DATA:
			log_info("Segment payload length: %i",seg->payload_len);
			if(orig == &(stream->client)){
				btcount->client += seg->payload_len;
			}else{
				btcount->sever += seg->payload_len;
			}
			break;
	}
	return ;
}

int main(int argc,char *argv[]){
	/* parameters parsing*/
	int c;

	/* pcap */
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "ip";
	char *source = 0;
	char *filter = filter_exp;	
	const unsigned char *packet = 0;
	struct pcap_pkthdr header;
	pbyte_count_t btcount = 0;
	
	/* TCP processing */
	pntoh_tcp_session_t tcpsession = 0;
	ntoh_tcp_tuple5_t tcpt5 = {0};
	pntoh_tcp_stream_t tcpstream = 0;
	unsigned int error = 0;
	/* Return of adding tcp segment */
	int ret = 0;

	/* TCP and IP headers dissection */
	struct ip *iphdr = 0;
	struct tcphdr *tcphdr = 0;
	size_t size_ip = 0;
	size_t size_tcp = 0;
	size_t size_total = 0;
	int packet_index = 0;	


	log_info("libntoh version: %s",ntoh_version());
	if(argc<3){
		log_info("Usage: %s <option>\n",argv[0]);
		log_info("Option:");
		log_info("\t-i | --iface <val> ---> Interface to read packets from");
		log_info("\t-f | --file <val> ---> File path to read packets from");
		log_info("\t-F | --filter <val> ---> Capture filter (must contain \"tcp\" or \"ip\")\n\n");
		exit(1);
	}
	
	/* Check parameters*/
	while(1){
		int option_index = 0;
		static struct option long_options[] = {
			{"iface",1,0,'i'},
			{"file",1,0,'f'},
			{"filter",1,0,'F'},
			{0,0,0,0}
		};
		
		if ((c = getopt_long(argc,argv,"i:f:F:",long_options,&option_index))<0)
			break;
		
		switch(c){
			case 'i':
				source = optarg;
				handle = pcap_open_live(optarg,65535,1,0,errbuf);
				break;
			case 'f':
				source = optarg;
				handle = pcap_open_offline(optarg,errbuf);
				break;
			case 'F':
				filter = optarg;
				break;
			default:
				if(handle!=0)
					pcap_close(handle);
				exit(-1);
		}
	}

	if(!handle){
		log_err(" Error loading %s: %s\n",source,errbuf);
		exit(-2);
	}

	if(pcap_compile(handle,&fp,filter,0,0)<0){
		log_err(" Error compiling filter \"%s\": %s\n\n",filter,pcap_geterr(handle));
		pcap_close(handle);
		exit(-3);
	}

	if(pcap_setfilter(handle,&fp)<0){
		log_err(" Cannot set filter: \"%s\": %s\n\n",filter,pcap_geterr(handle));
		pcap_close(handle);
		exit(-4);
	}

	pcap_freecode(&fp);

	/* verify datalink */
	if(pcap_datalink(handle) != DLT_EN10MB){
		log_err(" libntoh is independent from link layer, but this example only works with ethernet link layer\n");
		pcap_close(handle);
		exit(-5);
	}

	signal(SIGINT,&shandler);
	
	/* initializes libntoh (TCP and IPv4) */
	ntoh_init();
	
	/* creates a new TCP session */
	if(!(tcpsession = ntoh_tcp_new_session(0,0,&error))){
		log_err("Error %d creating the TCP session: %s",error,ntoh_get_errdesc(error));
		shandler(0);
	}
	
	/* capture starts */
	while(( packet = pcap_next(handle,&header))!=0){
		log_info("Packet index: %d ",packet_index);
		/* Check IP header */
		iphdr =(struct ip*)(packet + SIZE_ETHERNET);
		if(( size_ip = iphdr->ip_hl *4 )<sizeof(struct ip))
			/* Only process ip packet */
			continue;
		
		/* Check TCP header */
		if(iphdr->ip_p!=IPPROTO_TCP)
			continue;
		
		size_total = ntohs(iphdr->ip_len);
		
		tcphdr = (struct tcphdr*)((unsigned char*)iphdr + size_ip);
		if((size_tcp = tcphdr->th_off*4)<sizeof(struct tcphdr))
			continue;
		
		/* fill TCP tuple5 fields */
		ntoh_tcp_get_tuple5 (iphdr,tcphdr,&tcpt5);

		/* look for/create this TCP stream */
		if(!(tcpstream = ntoh_tcp_find_stream(tcpsession,&tcpt5))){
			btcount = (pbyte_count_t)calloc(1,sizeof(byte_count_t));
			if(!(tcpstream = ntoh_tcp_new_stream(tcpsession,&tcpt5,&tcp_callback,(void*)btcount,&error,0,0))){
				log_err("Error %d creating new stream: %s",error,ntoh_get_errdesc(error));
			}else{
				log_info("New stream is added from:  %s:%d",inet_ntoa(*(struct in_addr*)&tcpt5.source),ntohs(tcpt5.sport));
				log_info("to: %s:%d",inet_ntoa(*(struct in_addr*)&tcpt5.destination),ntohs(tcpt5.dport));
			}
		}

		/* Add this segment to the stream */
		switch((ret = ntoh_tcp_add_segment(tcpsession,tcpstream,iphdr,size_total,0))){
			/* Added successfully */
			case NTOH_OK:
			/* This is ACK message - don't need to add to stream */
			case NTOH_SYNCHRONIZING:
				break;
			default:
				log_err("Error %d adding segment: %s",ret,ntoh_get_retval_desc(ret));
				break;
		}
		packet_index +=1;
	}

	shandler(0);
	return 0;
}
