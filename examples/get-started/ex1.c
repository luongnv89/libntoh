/*
	This example aims to provide a very basic program which shows the version of libntoh - just to make sure we installed successfully

compile:
	gcc -o test ex1.c -lpthread -pcap -lntoh
Run test and expected result:
./test -f ../data-set/googlefr-tcp-in-order.pcap 
[INFO] (ex1.c:38) libntoh version: 0.4a
[INFO] (ex1.c:110)  Got a packet!
[INFO] (ex1.c:110)  Got a packet!
[INFO] (ex1.c:110)  Got a packet!
[INFO] (ex1.c:110)  Got a packet!
[INFO] (ex1.c:110)  Got a packet!
[INFO] (ex1.c:110)  Got a packet!
[INFO] (ex1.c:110)  Got a packet!
[INFO] (ex1.c:110)  Got a packet!
[INFO] (ex1.c:110)  Got a packet!
[INFO] (ex1.c:110)  Got a packet!
[INFO] (ex1.c:110)  Got a packet!
[INFO] (ex1.c:110)  Got a packet!
[INFO] (ex1.c:110)  Got a packet!
[INFO] (ex1.c:110)  Got a packet!
[INFO] (ex1.c:110)  Got a packet!
[INFO] (ex1.c:110)  Got a packet!
[INFO] (ex1.c:110)  Got a packet!
[INFO] (ex1.c:110)  Got a packet!
[INFO] (ex1.c:110)  Got a packet!
[INFO] (ex1.c:110)  Got a packet!
[INFO] (ex1.c:110)  Got a packet!
[INFO] (ex1.c:110)  Got a packet!
[INFO] (ex1.c:110)  Got a packet!
[INFO] (ex1.c:110)  Got a packet!
[INFO] (ex1.c:110)  Got a packet!
[INFO] (ex1.c:110)  Got a packet!

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

pcap_t *handle;

void shandler(int s){
	if(s!=0)
		signal(s,&shandler);
	pcap_close(handle);
	fprintf(stderr,"\n\n");
	exit(s);
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

	/* capture starts */
	while(( packet = pcap_next(handle,&header))!=0){
		log_info(" Got a packet!");
	}

	shandler(0);
	return 0;
}
