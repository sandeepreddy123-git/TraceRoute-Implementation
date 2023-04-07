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
    unsigned char   icmp_type;       // Type of ICMP message (e.g. echo request, echo reply, etc.)
    unsigned char   icmp_code;       // ICMP code (specific to each message type)
    unsigned short  icmp_checksum;   // Checksum to ensure message integrity
    unsigned short  _icmp_id;        // ICMP identifier field (usually set to process ID)
    unsigned short  icmp_sequence;   // ICMP sequence number (used to match echo requests and replies)
    unsigned int    icmp_timestamp;  // ICMP timestamp (used to calculate RTT)
} ICMP_HDR;


/*variabes to be used*/
char gDestination[256] = { 0 };      
char var[1] = { };
int gAddressFamily = AF_UNSPEC;     
int gProtocol = IPPROTO_ICMP;       
int s;
int packetlen;
struct addrinfo *dest;
struct addrinfo *local;
