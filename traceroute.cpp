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
