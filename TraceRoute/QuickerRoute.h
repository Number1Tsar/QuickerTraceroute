#include "pch.h"
#include "NetworkPackets.h"

#define MAX_HOPS 30											//	Maximum number of HOPs Accessible by tracert
#define ERROR_VALUE -1										//	Error value
#define SUCCESS_VALUE 0										//	Success value
#define DESTINATION_BEYOND_MAX_HOPS 2						//	Indicates destination beyond MAX_HOPS
#define DEFAULT_TIME_OUT 500								//	Starting Retransmission value
#define TTL_EXPIRE_PKT_SIZE 56								//	Minimum value of ICMP TTL Expire response packet
#define ECHO_REPLY_PKT_SIZE 28								//	Minumum value of ICMP Ping Reply response packet

/*
	Macro for measuring Time Difference
*/
#define TIME(X,Y) (((Y) - (X)) * 1000) / CLOCKS_PER_SEC

/*
	Required ICMP parameters to display after Traceroute.
*/
struct statusParameters
{
	int ttl;								//	Time to live set for the packet. Equal to sequence number of probe
	LARGE_INTEGER sendTime;					//	Sent Time stamp of the probe. Used to Calculate RTT when reply is received
	double RTT;								//	RTT of ICMP query
	int probesSent;							//	Numbers of Attempts made. MAX attempt is 3
	u_long IP;								//	IP address of router which replied with TIMEOUT message
	char domainName[512];					//	Domain Name of the responsing router. Obtained from DNSlookup
	char char_ip[16];						//	IP address as character array. only required for printings
	bool received;							//	Packet Received or Not. Will be used to detect duplicate response. Anything is possible in Computer NWs!
	bool isEcho;							//	An indication that the packet is the ECHO probe.
	int type;								//	Type of ICMP packet. Used in case of Error detection.
	int code;								//	Type of ICMP code. Used in case of Error detection.
};

class QuickerRoute
{
private:
	/*
		ICMP Socket maintained by the Class
	*/
	SOCKET sock;

	/*
		Destination Server Address
	*/
	struct sockaddr_in serverAddress;

	/*
		Frequency of the CPU. Required to calculate high precision time difference.
		Must be initialized only once at the beginning.
	*/
	LARGE_INTEGER frequency;

	/*
		Array of N threads for looking up each reply packet.
	*/
	HANDLE queryThreads[MAX_HOPS + 1];

	/*
		Array of statusParamter which will be shared with DNS threads.
	*/
	statusParameters hopInfo[MAX_HOPS + 1];

	/*
		Initialize status paramters.
	*/
	void initParameters();

	/*
		Calculate and return Internet Checksum
	*/
	u_short ip_checksum(u_short *buffer, int size);

	/*
		Create a ICMP packet with given ttl, attach the processId and send it to the host.
		Return ERROR in case of sockopt or send error.
		Return SUCCESS if every thing checks out.
	*/
	int sendICMPProbe(int ttl);

	/*
		Receive ICMP response from socket.
	*/
	int recvICMPResponse(int& pingReplyHop);

	/*
		Print Final Trace Route stats
	*/
	void printResult();


public:
	/*
		Constructor
		Creates ICMP socket and Initializes high frequency counter for Time Stamping
	*/
	QuickerRoute();

	/*
		Destructor.
		Closes socket
	*/
	~QuickerRoute();

	/*
		Performes Paralle Trace route for given host address.
	*/
	int trace(const char* host);

	/*
		A DNS thread used to perform reverse lookup on obtained Router IPs
	*/
	friend DWORD WINAPI reverseLookup_thread(LPVOID param);

};

