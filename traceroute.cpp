#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <endian.h>
#include <iostream>
#include <thread>
#include <unistd.h>


#define REQUEST_TYPE   8    // used to send ICMP echo requests to host
#define REQUEST_CODE   0
#define ICMPV4_ECHO           8
#define SIZE_OF_DATA      32       // defaut size_of_data
#define DEFAULT_TTL            30       // default timeout

using namespace std;

// ICMP header
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


//Trace Route
/****Variables****/
char destination_address[256] = { 0 };      // Destination
char var[1] = { };
int protocol_addr_family = AF_UNSPEC;     // Address family to use
int protocol_type = IPPROTO_ICMP;       // Protocol value
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

// Functions to retrieve the routing information for the endpoint and protocol,
unsigned int route_info_endpoint(void);
unsigned int route_info_protocol(void);

// Function to initialize the ICMP header with specified buffer and data size.
void Intialize_ICMP_Header(char *buf, int data_size);

// Function to set the ICMP sequence number in the buffer.
void Set_ICMP_Sequence_Number(char *buf);

// Function to compute the ICMP checksum for the packet.
void Compute_ICMP_Checksum(int s, char *buf, int len_of_packet, struct address_info *dest);

void process_packet();

// Function to compute the checksum of a given buffer.
unsigned short checksum(unsigned short *buffer, int size);


// Description:
//    Main Function 
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

/** Add in the data size **/
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

/*********************************/
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
			std::chrono::high_resolution_clock::time_point start_time;


			// Set the sequence number and compute the checksum
			Set_ICMP_Sequence_Number(icmpbuf);
			Compute_ICMP_Checksum(s, icmpbuf, len_of_packet, dest);

			// Send the ICMP echo request
			start_time = std::chrono::high_resolution_clock::now();
			std::thread first (&process_packet);     // spawn new thread that calls foo()
			printf("sending the data to the destination : %d",ttl);
			rc = sendto(s, icmpbuf, len_of_packet, 0, dest->ai_addr, dest->ai_addrlen);
			auto end_time = std::chrono::high_resolution_clock::now();
			auto elapsed_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
			std::cout << "Time taken: " << elapsed_time.count() << " microseconds" << std::endl;
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


 //Function: route_info_endpoint
 // Description:
 //   Takes user input and returns endpoint location
 //   ex: www.google.com
 //
unsigned int route_info_endpoint()
{

	// Entering the Trace Destination
	cout << "Enter the Destination Address " << endl;
	//TODO-Add Error Handler for name
	cin >> destination_address;
	cout << "Tracing for: "  << destination_address << endl;
	return 0;
}



int SetTtl(int s, int ttl)
{
    int optlevel, option, rc;
    rc = 0;

    // Check the protocol address family to determine which socket options to use
    if (protocol_addr_family == AF_INET)
    {
        optlevel = IPPROTO_IP;
        option = IP_TTL;
    }
    else
    {
        rc = 0; // placeholder value
    }

    // If no errors occurred while checking the protocol family,
    // set the Time-to-Live (TTL) value for the socket using setsockopt()
    if (rc == 0)
    {
        rc = setsockopt(s, optlevel, option, (char *)&ttl, sizeof(ttl));
    }
    // If an error occurred while checking the protocol family or setting the TTL,
    // print an error message to stderr.
    else if (rc == -1)
    {
        fprintf(stderr, "SetTtl(): terminated with an error\n");
    }
    // If the function was successful, print a success message to stdout.
    else
        printf("SetTtl(): successfully executed\n");

    // Return the final results of the function as an integer.
    return rc;
}




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
        fprintf(stderr, "%s: getnameinfo() failed with error code %d\n", __FILE__, rc);
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



unsigned short checksum(unsigned short *buffer, int size)
{
	unsigned long cksum = 0;
	while (size > 1)
	{
		cksum += *buffer++;
		size -= sizeof(unsigned short);
	}
	if (size)
	{
		cksum += *(unsigned char*)buffer;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (unsigned short)(~cksum);
}

// This function will intialize the ICMP header
void Intialize_ICMP_Header(char *buf, int data_size)

{
	ICMP_HDR   *icmp_hdr = NULL;
	char       *datagram = NULL;
	icmp_hdr = (ICMP_HDR *)buf;
	icmp_hdr->ICMP_message_type = REQUEST_TYPE;        // request an ICMP echo
	icmp_hdr->icmp_code = REQUEST_CODE;
	icmp_hdr->ICMP_id = (unsigned short)getpid();
	icmp_hdr->icmp_checksum = 0;
	icmp_hdr->icmp_sequence = 0;
	icmp_hdr->icmp_timestamp =  (unsigned int)time(NULL);
	datagram = buf + sizeof(ICMP_HDR);
	// Place some junk in the buffer.
	memset(datagram, 'E', data_size);
}

// Function: Set_ICMP_Sequence_Number
// Description:
//    This routine sets the sequence number of the ICMP request packet.
void Set_ICMP_Sequence_Number(char *buf)
{
	unsigned long    seq_num = 0;
	seq_num = (unsigned long)time(NULL);

	if (protocol_addr_family == AF_INET)
	{
		ICMP_HDR    *icmpv4 = NULL;
		icmpv4 = (ICMP_HDR *)buf;
		icmpv4->icmp_sequence = (unsigned short)seq_num;
	}
}

// This function takes an integer s, a character pointer named buf, an integer len_of_packet, and a struct address_info pointer named dest as arguments
void Compute_ICMP_Checksum(int s, char *buf, int len_of_packet, struct address_info *dest)
{
    // Check if the protocol address family is IPv4
    if (protocol_addr_family == AF_INET)
    {
        // Declare the pointer icmpv4 of type ICMP_HDR and set it to NULL
        ICMP_HDR    *icmpv4 = NULL;
        
        // Cast the buffer to an ICMP header struct pointer
        icmpv4 = (ICMP_HDR *)buf;
        
        // Set the ICMP checksum field in the buffer to 0
        icmpv4->icmp_checksum = 0;

        // Calculate the ICMP checksum for the packet using the checksum() function
        // The checksum() function calculates the checksum value from the given buffer and the length of the packet
        icmpv4->icmp_checksum = checksum((unsigned short *)buf, len_of_packet);
    }
}


void process_packet()
{
	unsigned char  ipv4_time_to_live[1] = {0};
	unsigned char  ipv4_protocol_icmp[1] = {0};
	unsigned short ipv4_header_checksum[1] = {0};
	unsigned int   ipv4_source_ipAddress[1] = {0};
	unsigned int   ipv4_destination_ipAddress[1] = {0};
	unsigned char  ICMP_message_type[1] = {0};
	unsigned char  icmp_code[1] = {0};
	unsigned short icmp_checksum[1] = {0};
	unsigned short icmp_identifier[1] = {0};
	unsigned short icmp_sequence_number[1] = {0};
	unsigned char receiver_buffer[65000] = {0};
	unsigned char bit_parsing_buffer[1] = {0};
	unsigned char header_version[1] = {0};
	unsigned char header_length[1] = {0};
	unsigned char diff_serv_codepoint[1] = {0};
	unsigned char server_congestion[1] = {0};
    unsigned short total_length[1] = {0};
    unsigned short identification [1] = {0};
	unsigned short flags [1] = {0};
	unsigned char time_to_live[1] = {0};
	unsigned char protocol_icmp[1]={0};
	unsigned short header_checksum[1] = {0};
	unsigned int   source_ipAddress[1] = {0};
	unsigned int   destination_ipAddress[1] = {0};
	unsigned char  ipv4_type[1] = {0};
	unsigned char  ipv4_code[1] = {0};
	unsigned short ipv4_checksum[1] = {0};
	unsigned char  ipv4_version[1] = {0};
	unsigned char  ipv4_length[1] = {0};
	unsigned char  ipv4_diff_serv_field[1] = {0}; 
	unsigned short ipv4_total_length[1] = {0};
	unsigned short ipv4_identification [1] = {0};
	unsigned short ipv4_flags [1] = {0};




	int status; // Declare integer variable status

	printf("Length of the packet including header and size of data %d \n", len_of_packet); // Print packet length for debugging purposes
	// status = recv(s, receiver_buffer, len_of_packet,0);
	status = recv(s, receiver_buffer, 56, 0); // Receive network packet and store it in receiver buffer array. The size of the packet is either 56 bytes or determined by len_of_packet variable.
	// printf("recv from value %d \n", status);  // Print the number of bytes received for debugging purposes.

	// for (int x = 0; x < len_of_packet; x++) // Loop through each byte in the received packet and print it out in hexadecimal format
	// {
	// 	printf("%x", receiver_buffer[x]);
	// }
	// printf("\n");

	//*header_version = *receiver_buffer >> 4;	// Extract header version from first byte in received packet using bit manipulation. Shift right four bits to get leftmost four bits. Assign this value to header_version array.
	//printf("  Version: %x\n", *header_version); // Print the extracted header version for debugging purposes.

	// Parsing- Header Length
	*bit_parsing_buffer = *receiver_buffer;			 // Assign the first byte of the received packet to bit_parsing_buffer array for further manipulation
	*header_length = *bit_parsing_buffer << 4;		 // Extract header length from bit_parsing_buffer using bit manipulation. Shift left four bits effectively discarding the rightmost four bits. Assign the truncated value to header_length array.
	*header_length = *header_length >> 4;			 // Shifts the header length back four bits to restore the original offset
	//printf("  Header Length: %x\n", *header_length); // Print the extracted header length for debugging purposes.

	// // Parsing- Differentianted Service Field
	// printf("  Differentianted Service Field : 0x%x\n", *(receiver_buffer + 1));							 // Print Differentiated Service Field for debugging purposes
	// *bit_parsing_buffer = *(receiver_buffer + 1);														 // Assign the second byte of the received packet to bit_parsing_buffer array for further manipulation
	// *diff_serv_codepoint = *bit_parsing_buffer >> 2;													 // Extract Differentiated Service Codepoint from bit_parsing_buffer using bit manipulation. Shift right two bits to get leftmost six bits. Assign this value to diff_serv_codepoint array.
	// printf("     Differentianted Service Codepoint : 0x%x\n", *diff_serv_codepoint);					 // Print the extracted Differentiated Service Codepoint for debugging purposes.
	// *server_congestion = *bit_parsing_buffer << 6;											 // Extract Explicit Congestion Notification bits from bit_parsing_buffer using bit manipulation. Shift left six bits effectively discarding the rightmost two bits. Assign the truncated value to diff_serv_explicit_congestion array.
	// *server_congestion = *server_congestion >> 6;								 // Shifts the Explicit Congestion Notification bits back six bits to restore original offset.
	// printf("     Differentianted Service Explicit Congection : 0x%x\n", *server_congestion); // Print the extracted Explicit Congestion Notification bits for debugging purposes.

	// Parsing- Total Length
	//*total_length = *(receiver_buffer + 4);
	// memcpy(total_length, receiver_buffer + 2, 2);
	// printf("  Total Length: 0x%x (%d)\n", be16toh(*total_length), be16toh(*total_length));

	// // Parsing- Identification
	// memcpy(identification, receiver_buffer + 4, 2);
	// printf("  Identification: 0x%x (%d)\n", be16toh(*identification), be16toh(*identification));

	// // Parsing- Flags
	// memcpy(flags, receiver_buffer + 6, 2);
	// printf("  Flags: 0x%x (%d)\n", be16toh(*flags), be16toh(*flags));

	// Parsing- TTL
	// *time_to_live = *(receiver_buffer + 8);
	// // memcpy ( time_to_live,receiver_buffer+8 ,1);
	// printf("  TTL: 0x%x (%d)\n", *time_to_live, *time_to_live);

	// Parsing- Protocol
	//*protocol_icmp = *(receiver_buffer + 9);
	//printf("  Protocol: %d\n", *protocol_icmp);

	// Parsing- Header Checksum
	memcpy(header_checksum, receiver_buffer + 10, 2);
	printf("  Header Checksum: 0x%x (%d)\n", be16toh(*header_checksum), be16toh(*header_checksum));

    //Parsing- Source IP Address
	struct sockaddr_in source_ip_structure;										 
	char *source_addr;															 
	memcpy(source_ipAddress, receiver_buffer + 12, 4);							 // Copy the 4 bytes of data starting at index 12 in receiver_buffer array into the source_ipAddress array.
	source_ip_structure.sin_addr.s_addr = *source_ipAddress;					 // Assign the value in source_ipAddress array to the sin_addr field in source_ip_structure.
	source_addr = inet_ntoa(source_ip_structure.sin_addr);						 // Convert the binary format of the source IP address in source_ip_structure from network byte order to dotted decimal notation using inet_ntoa() function. Assign the result as a string to the source_addr pointer.
	printf("  Source IP: %s (0x%x)\n", source_addr, be32toh(*source_ipAddress)); // Print the extracted source IP address in both dotted decimal notation and hexadecimal format.

	// Parsing- Destination IP Address
	struct sockaddr_in dest_ip_structure;												 
	char *dest_addr;																	 
	memcpy(destination_ipAddress, receiver_buffer + 16, 4);								 // Copy the 4 bytes of data starting at index 16 in receiver_buffer array into the destination_ipAddress array.
	dest_ip_structure.sin_addr.s_addr = *destination_ipAddress;							 // Assign the value in destination_ipAddress array to the sin_addr field in dest_ip_structure.
	dest_addr = inet_ntoa(dest_ip_structure.sin_addr);									 // Convert the binary format of the destination IP address in dest_ip_structure from network byte order to dotted decimal notation using inet_ntoa() function. Assign the result as a string to the dest_addr pointer.
	printf("  Destination IP: %s (0x%x)\n", dest_addr, be32toh(*destination_ipAddress)); // Print the extracted destination IP address in both dotted decimal notation and hexadecimal format.

	// Parsing- IPV4 Type
	*ipv4_type = *(receiver_buffer + 20);						  // Assign the value at index 20 in receiver_buffer to the ipv4_type array.
	printf("    IPV4 Type: 0x%x (%d)\n", *ipv4_type, *ipv4_type); 

	// Parsing- IPV4 Code
	*ipv4_code = *(receiver_buffer + 21);						  // Assign the value at index 21 in receiver_buffer to the ipv4_code array.
	printf("    IPV4 Code: 0x%x (%d)\n", *ipv4_code, *ipv4_code); 

	// Parsing- IPV4 Checksum
	memcpy(ipv4_checksum, receiver_buffer + 22, 2);												// Copy the 2 bytes of data starting at index 22 in receiver_buffer array into the ipv4_checksum array.
	printf("    IPV4 Checksum: 0x%x (%d)\n", be16toh(*ipv4_checksum), be16toh(*ipv4_checksum)); // Convert the network byte order data in ipv4_checksum array to host byte order using be16toh() function. Print the extracted IPV4 Checksum for debugging purposes.

	// // Parsing- IPV4 Version
	// *ipv4_version = *(receiver_buffer + 28) >> 4; // Extract the version number of IPV4 packet from first 4 bits of byte at index 28 in receiver_buffer using bit manipulation. Shift right four bits to get leftmost four bits. Assign this value to ipv4_version array.
	// printf("    Version: %x\n", *ipv4_version);	  

	// // Parsing- IPV4 Length
	// *bit_parsing_buffer = *(receiver_buffer + 28); // Assign receiver_buffer to bit_parsing_buf, this contain 1 byte
	// *ipv4_length = *bit_parsing_buffer << 4;	   // Truncate half of the byte so only 4 bit length remains
	// *ipv4_length = *ipv4_length >> 4;			   // Shift buffer back the orignal offset
	// printf("    Length: %x\n", *ipv4_length);

	// Parsing- IPV4 Differential Dervices
	// *ipv4_diff_serv_field = *(receiver_buffer + 29);
	// printf("    Differentianted Service Field: 0x%x (%d)\n", *ipv4_diff_serv_field, *ipv4_diff_serv_field);

	// // Parsing- IPV4 Total Length
	// //*total_length = *(receiver_buffer + 4);
	// memcpy(ipv4_total_length, receiver_buffer + 30, 2);
	// printf("    IPV4 Total Length: 0x%x (%d)\n", be16toh(*ipv4_total_length), be16toh(*ipv4_total_length));

	// Parsing- IPV4 Identification
	memcpy(ipv4_identification, receiver_buffer + 32, 2);
	printf("    IPV4 Identification: 0x%x (%d)\n", be16toh(*ipv4_identification), be16toh(*ipv4_identification));

	// // Parsing- IPV4 Flags
	// memcpy(ipv4_flags, receiver_buffer + 34, 2);
	// printf("    IPV4 Flags: 0x%x (%d)\n", be16toh(*ipv4_flags), be16toh(*ipv4_flags));

	// // Parsing- IPV4 TTL
	// *ipv4_time_to_live = *(receiver_buffer + 36);
	// // memcpy ( time_to_live,receiver_buffer+8 ,1);
	// printf("    IPV4-TTL: 0x%x (%d)\n", *ipv4_time_to_live, *ipv4_time_to_live);

	// // Parsing- IPV4 Protocol
	// *ipv4_protocol_icmp = *(receiver_buffer + 37);
	// printf("    IPV4-Protocol: 0x%x (%d)\n", *ipv4_protocol_icmp, *ipv4_protocol_icmp);

	// Parsing- IPV4 Checksum
	// memcpy(ipv4_header_checksum, receiver_buffer + 38, 2);
	// printf("    IPV4-Checksum: 0x%x (%d)\n", be16toh(*ipv4_header_checksum), be16toh(*ipv4_header_checksum));
	
    //Parsing- IPV4 Source IP Address
// 	struct sockaddr_in icmp_source_ip_structure;
// 	char *icmp_source_addr;
// 	memcpy(ipv4_source_ipAddress, receiver_buffer + 40, 4);										  // Copy the 4 bytes of data starting at index 40 in receiver_buffer array into the ipv4_source_ipAddress array.
// 	icmp_source_ip_structure.sin_addr.s_addr = *ipv4_source_ipAddress;							  // Assign the value in ipv4_source_ipAddress array to the sin_addr field in icmp_source_ip_structure.
// 	icmp_source_addr = inet_ntoa(icmp_source_ip_structure.sin_addr);							  // Convert the binary format of the ICMP source IP address in icmp_source_ip_structure from network byte order to dotted decimal notation using inet_ntoa() function. Assign the result as a string to the icmp_source_addr pointer.
// 	printf("    ICMP-Source IP: %s (0x%x)\n", icmp_source_addr, be32toh(*ipv4_source_ipAddress)); // Print the extracted ICMP source IP address in both dotted decimal notation and hexadecimal format.

// 	// Parsing- IPV4 Destination IP Address
// 	struct sockaddr_in icmp_dest_ip_structure;
// 	char *icmp_dest_addr;
// 	memcpy(ipv4_destination_ipAddress, receiver_buffer + 44, 4);										   // Copy the 4 bytes of data starting at index 44 in receiver_buffer array into the ipv4_destination_ipAddress array.
// 	icmp_dest_ip_structure.sin_addr.s_addr = *ipv4_destination_ipAddress;								   // Assign the value in ipv4_destination_ipAddress array to the sin_addr field in icmp_dest_ip_structure.
// 	icmp_dest_addr = inet_ntoa(icmp_dest_ip_structure.sin_addr);										   // Convert the binary format of the ICMP destination IP address in icmp_dest_ip_structure from network byte order to dotted decimal notation using inet_ntoa() function. Assign the result as a string to the icmp_dest_addr pointer.
// 	printf("    ICMP- Destination IP: %s (0x%x)\n", icmp_dest_addr, be32toh(*ipv4_destination_ipAddress)); // Print the extracted ICMP destination IP address in both dotted decimal notation and hexadecimal format.

// 	//Parsing- ICMP Type
// 		*ICMP_message_type = *(receiver_buffer+48);
//     	printf("      ICMP-Type: 0x%x (%d)\n",*ICMP_message_type,*ICMP_message_type);

// 	//Parsing- ICMP Code
// 		*icmp_code = *(receiver_buffer+49);
//     	printf("      ICMP-Code: 0x%x (%d)\n",*icmp_code,*icmp_code);

//    //Parsing- ICMP Checksum
//   	    memcpy ( icmp_checksum,receiver_buffer+50 ,2);
// 		printf("      ICMP-Checksum: 0x%x (%d)\n",be16toh(*icmp_checksum),be16toh(*icmp_checksum));

//     //Parsing- ICMP Identifier
//     	memcpy ( icmp_identifier,receiver_buffer+52 ,2);
// 		printf("      ICMP-Identifier: 0x%x (%d)\n",be16toh(*icmp_identifier),be16toh(*icmp_identifier));

// 		  //Parsing- ICMP Sequence Number
//     	memcpy ( icmp_sequence_number,receiver_buffer+54 ,2);
// 		printf("      ICMP-Sequence: 0x%x (%d)\n",be16toh(*icmp_sequence_number),be16toh(*icmp_sequence_number));

}
