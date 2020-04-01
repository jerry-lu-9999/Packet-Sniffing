/*
 * Standard C includes
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

/*
 * Standard UNIX includes
 */
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>

/*
 * Other includes
 */
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <pcap.h>

/*
 * Includes for BPF
 */
#include <sys/time.h>
#include <sys/ioctl.h>

/*
 * Local include files
 */
#include "webspy.h"
#include "httpfilter.h"

/*
 * The descriptor of the output file.
 */
FILE * outfile;

	char hbuf[NI_MAXHOST];			//NI_MAXHOST is defined as 1025
	char *path_name;		
	char ipbuf[15];				    //the maximum number of characters IPv4 address can have is 15
	int port_num;
/*
 * Function Prototypes
 */
void process_packet (u_char *, const struct pcap_pkthdr *, const u_char *);

/*
 * Function: init_pcap ()
 *
 * Purpose:
 *	This function initializes the packet capture library for reading
 *	packets from a packet capturing program.
 */
pcap_t *
init_pcap (FILE * thefile, char * filename)
{
	char		error[PCAP_ERRBUF_SIZE];	/* Error buffer */
	pcap_t *	pcapd;				/* Pcap descriptor */

	/*
	 * Setup the global file pointer.
	 */
	outfile = thefile;

	/*
	 * Open the dump file and get a pcap descriptor.
	 */
	if ((pcapd=pcap_open_offline (filename, error)) == NULL)
	{
		fprintf (stderr, "Error is %s\n", error);
		return NULL;
	}

	return pcapd;
}

/*
 * Function: print_ether
 *
 * Description:
 *   Print the Ethernet header.
 *
 * Inputs:
 *   outfile - The file to which to print the Ethernet header information
 *   packet  - A pointer to the pointer to the packet information.
 *
 * Outputs:
 *   packet  - The pointer is advanced to the first byte past the Ethernet
 *             header.
 */
void
print_ether (FILE * outfile, const unsigned char ** packet)
{
	struct ether_header header;
	int index;

	/*
	 * Align the data by copying it into a Ethernet header structure.
	 */
	bcopy (*packet, &header, sizeof (struct ether_header));

	/*
	 * Adjust the pointer to point after the Ethernet header.
	 */
	*packet += sizeof (struct ether_header);

	/*
	 * Return indicating no errors.
	 */
	return;
}

/*
 * Function: print_ip
 *
 * Description:
 *   Print the IPv4 header.
 *
 * Inputs:
 *   outfile - The file to which to print the Ethernet header information
 *   packet  - A pointer to the pointer to the packet information.
 *
 * Outputs:
 *   packet  - The pointer is advanced to the first byte past the IPv4
 *             header.
 */
void
print_ip (FILE * outfile, const unsigned char ** packet)
{
	struct ip ip_header;
	int index;

	/*
	 * After reading comments in tcpdump source code, I discovered that
	 * the dump file does not guarantee that the IP header is aligned
	 * on a word boundary.
	 *
	 * This is apparently what's causing me problems, so I will word align
	 * it just like tcpdump does.
	 */
	bcopy (*packet, &ip_header, sizeof (struct ip));


	/*
	 * Determine size of IP header. 
	 * We use the IHL field in IP header to see how many bytes are in the header
	 */
	int ip_length = ip_header.ip_hl * 32 / 8;	
	bool options = false;	int options_len = 0;			   
	if	(ip_length == 20){
		options = false;
	}else if (ip_length > 20){
		options = true;
		options_len = ip_length - 20;
	}

	struct sockaddr_in sa;    /* input */
    socklen_t len;         /* input */

    memset(&sa, 0, sizeof(struct sockaddr_in));

    /* For IPv4*/
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(inet_ntoa(ip_header.ip_dst));
    len = sizeof(struct sockaddr_in);

    if (getnameinfo((struct sockaddr *) &sa, len, hbuf, sizeof(hbuf), 
        NULL, 0, NI_NAMEREQD)) {
		//perror("Error here");
        //printf("the IP address is %s\n", inet_ntoa(ip_header.ip_dst));
		strcpy(ipbuf, inet_ntoa(ip_header.ip_dst));
		ipbuf[14] = '\0';
    }
    else {
        //printf("The hostname is %s\n", hbuf);
    }

	*packet += ip_length;
	/*
	 * Return indicating no errors.
	 */
	return;
}

void
print_tcp (FILE *outfile, const unsigned char ** packet)
{
	struct tcphdr tcp;

	bcopy(*packet, &tcp, sizeof (struct tcphdr));

	/* 
	 * Determine TCP header length
	 */

	int tcp_len = tcp.th_off * 32 / 8;				//actual length including options in Bytes

	// fprintf (outfile, "================= TCP HEADER ==============\n");

	// fprintf (outfile, "%d", htons(tcp.th_dport));
	// fprintf (outfile, "\n");

	// fprintf (outfile, "Destination port\n");
	if (htons(tcp.th_dport) == 80)
	{
		port_num = 80;
	}else if (htons(tcp.th_dport) == 443)
	{
		port_num = 443;
	}
	*packet += tcp_len;
}

void
print_http(FILE *outfile, const unsigned char ** packet)
{
  	char* result = NULL;
	result =(char*)malloc(1000); 
	result[0] = '\0';

  	if(port_num == 80)
  	{
		const unsigned char *start;
		const unsigned char *begin;

		begin = *packet;
		// the pointer stop right after the first whitespace
		while(**packet != ' '){
			*packet += 1;
		}
		size_t length = *packet - begin;
		char *method = (char*)malloc(sizeof(char*)*(length+1));
		strncpy(method, begin, length);
		method[length] = '\0';
		
		if(strcmp(method, "GET") != 0 && strcmp(method, "POST") != 0 && strcmp(method, "PUT") != 0)
		{
			return;
		} 
		*packet+= 1;	
		start = *packet;

		//stop at the second whitespace
		while (**packet != ' '){	
			*packet+=1;
		}
		size_t len = *packet - start;
		path_name = (char*)malloc(sizeof(char*)*(len+1));
		strncpy(path_name, start, len);
		path_name[len] = '\0';
			
		strcat(result, "http://");
		strcat(result, hbuf);
		printf("%s", result);
		printf("%s\n", path_name);
	}else if(port_num == 443)
	{
		strcat(result, "https://");
		strcat(result, ipbuf);
		printf("%s", result);
		printf("/OMITTED\n");
	}

}
/*
 * Function: process_packet ()
 *
 * Purpose:
 *	This function is called each time a packet is captured.  It will
 *	determine if the packet is one that is desired, and then it will
 *	print the packet's information into the output file.
 *
 * Inputs:
 *	thing         - I have no idea what this is.
 *	packet_header - The header that libpcap precedes a packet with.  It
 *	                indicates how much of the packet was captured.
 *	packet        - A pointer to the captured packet.
 *
 * Outputs:
 *	None.
 *
 * Return value:
 *	None.
 */
void
process_packet (u_char * thing,
                const struct pcap_pkthdr * packet_header,
                const u_char * packet)
{
	/* Determine where the IP Header is */
	const unsigned char *		pointer;

	/* Length of the data */
	long		packet_length;

	/*
	 * Filter the packet using our BPF filter.
	 */
	if ((pcap_offline_filter (&HTTPFilter, packet_header, packet) == 0))
	{
		return;
	}

	/*
	 * Print the Ethernet Header
	 */
	pointer = packet;
	print_ether (outfile, &pointer);

	/*
	 * Find the pointer to the IP header.
	 */
	print_ip (outfile, &pointer);

	print_tcp(outfile, &pointer);

	print_http(outfile, &pointer);

	return;
}
