#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <endian.h>
#include <iostream>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <thread>
#include <unistd.h>

#define REQUEST_TYPE   8    // used to send ICMP echo requests to host
#define REQUEST_CODE   0
#define ICMPV4_ECHO           8
#define SIZE_OF_DATA      32       // defaut size_of_data
#define DEFAULT_TTL            30       // default timeout

using namespace std;

typedef struct icmp_hdr
{
    // 8-bit field that specifies the type of ICMP message
    unsigned char   ICMP_message_type;
    // 8-bit field that provides context information for the ICMP message
    unsigned char   icmp_code;
     // 16-bit field that stores the checksum of the ICMP header and data
    unsigned short  icmp_checksum;
    // 16-bit field that identifies the sender of the ICMP message
    unsigned short  ICMP_id;
    // 16-bit field that uniquely identifies each ICMP message sent by the sender
    unsigned short  icmp_sequence;
    // 32-bit field to store a timestamp related to the ICMP message
    unsigned int   icmp_timestamp;
} ICMP_HDR;


/*variabes to be used*/
char destination_address[256] = { 0 };      
char var[1] = { };
int protocol_addr_family = AF_UNSPEC;     
int protocol_type = IPPROTO_ICMP;       
int s;
int len_of_packet;
struct address_info *dest;
struct address_info *local;


/*Functions to be used*/

int PrintAddress(struct address_info *sa);

int set_ICMP_protocol(struct address_info *sa);

int SetTtl(int s, int ttl);

// Function to resolve an IP address to its corresponding address information.
struct address_info *resolve_address(char *addr, char *port, int af, int type, int proto);

unsigned int route_info_endpoint(void);
unsigned int route_info_protocol(void);

// Function to initialize the ICMP header with specified buffer and data size.
void Intialize_ICMP_Header(char *buf, int datasize);

// Function to set the ICMP sequence number in the buffer.
void Set_ICMP_Sequence_Number(char *buf);

// Function to compute the ICMP checksum for the packet.
void Compute_ICMP_Checksum(int s, char *buf, int len_of_packet, struct address_info *dest);

void process_packet();

// Function to compute the checksum of a given buffer.
unsigned short checksum(unsigned short *buffer, int size);

unsigned int route_info_endpoint()
{

	// Enter the Trace Destination
	cout << "Enter the Destination Address " << endl;
	cin >> destination_address;
	cout << "Tracing for: "  << destination_address << endl;
	return 0;
}


// Function that will specify which routing protocol is being implemented
unsigned int route_info_protocol(void)
{
    // Declare Protocol_version and initialize it to 4.
    unsigned int Protocol_version;
    Protocol_version=4;

    // Print the protocol version.
    cout << "Protocol IPv"  << Protocol_version << endl;

    // Check if the protocol version is IPv4. Set the AF_INET address family if it is.
    if (Protocol_version == 4 )
    {
            protocol_addr_family = AF_INET; // Assuming protocol_addr_family is a global variable.
    }
    else // If the protocol version is not IPv4, return 1 to indicate an error.
    {
        cout << "It's not IPV4 " << endl;
        return 1;
    }

    // Return 0 to indicate success.
    return 0;
}

struct address_info *resolve_address(char *addr, char *port, int af, int type, int proto)
{

	struct address_info addrInfo, *res = NULL;

	int  rc;

	memset(&addrInfo, 0, sizeof(addrInfo));
	addrInfo.ai_flags = ((addr) ? 0 : AI_PASSIVE);
	addrInfo.ai_family = af;
	addrInfo.ai_socktype = type;
	addrInfo.ai_protocol = proto;

	rc = getaddrinfo(addr, port, &addrInfo, &res);
	if (rc != 0)
	{
		printf("Inavlid address / Address Resolution Failed");
		return NULL;
	}
	else
		printf("Address Resolution successfull\n");
	return res;
}


//This function takes a pointer to the address_info structure and prints the address information
int PrintAddress(struct address_info *sa)
{
    //Variable declarations
    char host[NI_MAXHOST], serv[NI_MAXSERV];
    int hostlen = NI_MAXHOST, servlen = NI_MAXSERV, rc; //Assigning values to variables

    //getnameinfo function translates a socket address to a corresponding host and service, Here it returns the numerical form of the hostname and port number
    rc = getnameinfo(sa->ai_addr, sa->ai_addrlen, host, hostlen, serv, servlen, NI_NUMERICHOST | NI_NUMERICSERV);

    //If rc is not equal to zero, then print an error message along with the error code and return the error code
    if (rc != 0)
    {
        fprintf(stderr, "%s: getnameinfo() failed with error code %d\n", _FILE_, rc);
        return rc;
    }
    else
        printf("PrintAddress(): Address Printed Successfully\n");//If rc is equals to zero, this statement gets executed.

    if (strcmp(serv, "0") != 0)
    {
        //Checks if the family type of address in the address_info structure is AF_INET(i.e., IPv4) or not. If true, It prints the host and port enclosed in brackets.
        if (sa->ai_addr->sa_family == AF_INET)
            printf("[%s]:%s", host, serv);
        else
            //If false(i.e.,IPv6), It prints host and port separated by a colon.
            printf("%s:%s", host, serv);
    }
    else
        //If the value of serv is "0", then it means that the port number is not available, hence only print the host.
        printf("%s", host);

    return 0;  
}


// This function sets the type of protocol to be used
int set_ICMP_protocol(struct address_info *sa)
{
	// Initialize the variable `protocol_addr_family` with the value of 
    // `sa->ai_family` which represents the protocol family for the given address.
    protocol_addr_family = sa->ai_family;

    // Check if the protocol family is IPv4 (AF_INET).
    if (protocol_addr_family == AF_INET) {
        
        // If it is IPv4, then set the protocol type as `IPPROTO_ICMP`.
        // `IPPROTO_ICMP` corresponds to the protocol number of the ICMP protocol.
        protocol_type = IPPROTO_ICMP;
    }
    
    return protocol_type;
}

/    Main Function 
int main (void)
{
	*var = 0;
//    /int s;
    int rc,ttl,notdone;
    int gTtl = DEFAULT_TTL;              // Default TTL value

	len_of_packet = 0;

	char *icmpbuf = NULL;
 
	cout << "Trace Route " << endl;

	// Finding the Destination address and the Protocol to be used
	route_info_endpoint();
	route_info_protocol();

	dest = resolve_address(destination_address,var,protocol_addr_family,0,0);
	  if (dest == NULL)
	  {
		 printf("Bad name %s\n", destination_address);
		 return 1;
	  }
	  else
		printf("ResolveAddress() is OK!\n");

	PrintAddress(dest);

	set_ICMP_protocol(dest);

	local = resolve_address(NULL, var, protocol_addr_family, 0, 0);
	//This will resolve the IP address of current host
	// var represents IP address of host
	  if (local == NULL)
	  {
		 printf("IP address didn't binded successfully\n");
		 return 1;
	  }
	  else
		printf("ResolveAddress() successfully wo!\n");
	  PrintAddress(local);

	s = socket(protocol_addr_family, SOCK_RAW, protocol_type);
//The socket function creates a new socket file descriptor and returns it 
//on success. The file descriptor represents a communication endpoint and is 
//used in subsequent function calls to operate on the socket.

if (s == -1)
{
    //If the socket file descriptor is invalid (-1), print an error message and return -1
    printf("Unable to create a socket\n");
    return -1;
}
else
//Otherwise, print a success message with the socket file descriptor value
    printf("socket() successfully created!, fd is %d \n",s);

if (protocol_addr_family == AF_INET)
    len_of_packet += sizeof(ICMP_HDR);

/* Add in the data size */
//Increase the length of the packet by adding the size of the data
len_of_packet += SIZE_OF_DATA;

icmpbuf = (char *)malloc(len_of_packet);
if (icmpbuf == NULL)
{
    //If memory allocation fails, print an error message and return -1
    fprintf(stderr, "Malloc for ICMP buffer failed with error code\n");
    return -1;
}
else
    printf("Malloc() for ICMP buffer is OK!\n");

/***********/
//If the protocol address family is IPv4, initialize the ICMP header in the buffer
if (protocol_addr_family == AF_INET)
{
    Intialize_ICMP_Header(icmpbuf, SIZE_OF_DATA);
}

//Associate the socket with the local IP address and port number
rc = bind(s, local->ai_addr, local->ai_addrlen);
if (rc == -1)
{
    //If binding fails, print an error message and return 1
    fprintf(stderr, "bind() failed with error code \n");
    return 1;
}
else{
		printf("bind() is OK!: Local Address Bound\n");
		//PrintAddress(local->ai_addr, local->ai_addrlen);
	    ttl = 1;  //Intially the TTL is set to 1 and then incremented until it reaches destination

		do
		{
			notdone = 1;
			SetTtl(s, ttl); // set the Time to live

			// Set the sequence number and compute the checksum
			Set_ICMP_Sequence_Number(icmpbuf);
			Compute_ICMP_Checksum(s, icmpbuf, len_of_packet, dest);

			// Send the ICMP echo request
			std::thread first (&process_packet);     // spawn new thread that calls foo()
			rc = sendto(s, icmpbuf, len_of_packet, 0, dest->ai_addr, dest->ai_addrlen);
			//send(s,icmpbuf,len_of_packet,0);
			if (rc == -1)
			{
				fprintf(stderr, "sendto() terminated with an error\n");
				return -1;
			}
			else
				printf("sendto() executed successfully\n");
			first.join();


			ttl++;
			sleep(1);

		} while ((notdone) && (ttl < gTtl));

		free(icmpbuf);


	}
    return 0;
}
// Parsing- IPV4 Length
	*bit_parsing_buffer = *(receiver_buffer + 28); // Assign receiver_buffer to bit_parsing_buf, this contain 1 byte
	*ipv4_length = *bit_parsing_buffer << 4;	   // Truncate half of the byte so only 4 bit length remains
	*ipv4_length = *ipv4_length >> 4;			   // Shift buffer back the orignal offset
	printf("    Length: %x\n", *ipv4_length);

	// Parsing- IPV4 Differential Dervices
	*ipv4_diff_serv_field = *(receiver_buffer + 29);
	printf("    Differentianted Service Field: 0x%x (%d)\n", *ipv4_diff_serv_field, *ipv4_diff_serv_field);

	// Parsing- IPV4 Total Length
	//*total_length = *(receiver_buffer + 4);
	memcpy(ipv4_total_length, receiver_buffer + 30, 2);
	printf("    IPV4 Total Length: 0x%x (%d)\n", be16toh(*ipv4_total_length), be16toh(*ipv4_total_length));

	// Parsing- IPV4 Identification
	memcpy(ipv4_identification, receiver_buffer + 32, 2);
	printf("    IPV4 Identification: 0x%x (%d)\n", be16toh(*ipv4_identification), be16toh(*ipv4_identification));

	// Parsing- IPV4 Flags
	memcpy(ipv4_flags, receiver_buffer + 34, 2);
	printf("    IPV4 Flags: 0x%x (%d)\n", be16toh(*ipv4_flags), be16toh(*ipv4_flags));

	// Parsing- IPV4 TTL
	*ipv4_time_to_live = *(receiver_buffer + 36);
	// memcpy ( time_to_live,receiver_buffer+8 ,1);
	printf("    IPV4-TTL: 0x%x (%d)\n", *ipv4_time_to_live, *ipv4_time_to_live);

	// Parsing- IPV4 Protocol
	*ipv4_protocol_icmp = *(receiver_buffer + 37);
	printf("    IPV4-Protocol: 0x%x (%d)\n", *ipv4_protocol_icmp, *ipv4_protocol_icmp);

	// Parsing- IPV4 Checksum
	memcpy(ipv4_header_checksum, receiver_buffer + 38, 2);
	printf("    IPV4-Checksum: 0x%x (%d)\n", be16toh(*ipv4_header_checksum), be16toh(*ipv4_header_checksum));
	
    //Parsing- IPV4 Source IP Address
	struct sockaddr_in icmp_source_ip_structure;
	char *icmp_source_addr;
	memcpy(ipv4_source_ipAddress, receiver_buffer + 40, 4);										  // Copy the 4 bytes of data starting at index 40 in receiver_buffer array into the ipv4_source_ipAddress array.
	icmp_source_ip_structure.sin_addr.s_addr = *ipv4_source_ipAddress;							  // Assign the value in ipv4_source_ipAddress array to the sin_addr field in icmp_source_ip_structure.
	icmp_source_addr = inet_ntoa(icmp_source_ip_structure.sin_addr);							  // Convert the binary format of the ICMP source IP address in icmp_source_ip_structure from network byte order to dotted decimal notation using inet_ntoa() function. Assign the result as a string to the icmp_source_addr pointer.
	printf("    ICMP-Source IP: %s (0x%x)\n", icmp_source_addr, be32toh(*ipv4_source_ipAddress)); // Print the extracted ICMP source IP address in both dotted decimal notation and hexadecimal format.

	// Parsing- IPV4 Destination IP Address
	struct sockaddr_in icmp_dest_ip_structure;
	char *icmp_dest_addr;
	memcpy(ipv4_destination_ipAddress, receiver_buffer + 44, 4);										   // Copy the 4 bytes of data starting at index 44 in receiver_buffer array into the ipv4_destination_ipAddress array.
	icmp_dest_ip_structure.sin_addr.s_addr = *ipv4_destination_ipAddress;								   // Assign the value in ipv4_destination_ipAddress array to the sin_addr field in icmp_dest_ip_structure.
	icmp_dest_addr = inet_ntoa(icmp_dest_ip_structure.sin_addr);										   // Convert the binary format of the ICMP destination IP address in icmp_dest_ip_structure from network byte order to dotted decimal notation using inet_ntoa() function. Assign the result as a string to the icmp_dest_addr pointer.
	printf("    ICMP- Destination IP: %s (0x%x)\n", icmp_dest_addr, be32toh(*ipv4_destination_ipAddress)); // Print the extracted ICMP destination IP address in both dotted decimal notation and hexadecimal format.

	//Parsing- ICMP Type
		*ICMP_message_type = *(receiver_buffer+48);
    	printf("      ICMP-Type: 0x%x (%d)\n",*ICMP_message_type,*ICMP_message_type);

	//Parsing- ICMP Code
		*icmp_code = *(receiver_buffer+49);
    	printf("      ICMP-Code: 0x%x (%d)\n",*icmp_code,*icmp_code);

   //Parsing- ICMP Checksum
  	    memcpy ( icmp_checksum,receiver_buffer+50 ,2);
		printf("      ICMP-Checksum: 0x%x (%d)\n",be16toh(*icmp_checksum),be16toh(*icmp_checksum));

    //Parsing- ICMP Identifier
    	memcpy ( icmp_identifier,receiver_buffer+52 ,2);
		printf("      ICMP-Identifier: 0x%x (%d)\n",be16toh(*icmp_identifier),be16toh(*icmp_identifier));

		  //Parsing- ICMP Sequence Number
    	memcpy ( icmp_sequence_number,receiver_buffer+54 ,2);
		printf("      ICMP-Sequence: 0x%x (%d)\n",be16toh(*icmp_sequence_number),be16toh(*icmp_sequence_number));

}
