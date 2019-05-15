#include "pch.h"
#include "QuickerRoute.h"


/*
	Performs Reverse Lookup on the Routers IP address.
	If Name cannot be resolved, stores "<no DNS entry>" to the routerName.
*/
DWORD WINAPI reverseLookup_thread(LPVOID param)
{
	statusParameters* status = (statusParameters*)param;
	in_addr addr;
	addr.S_un.S_addr = status->IP;
	char *ip_ntoa = inet_ntoa(addr);
	memcpy(status->char_ip, ip_ntoa, 16);
	struct addrinfo hints;
	struct addrinfo *res = 0;
	hints.ai_family = AF_INET;
	int dnsStatus = getaddrinfo(ip_ntoa, 0, 0, &res);
	char host[512];
	dnsStatus = getnameinfo(res->ai_addr, res->ai_addrlen, host, 512, 0, 0, 0);
	if (strcmp(host, ip_ntoa) == 0) memcpy(status->domainName, "<no DNS entry>", 15);
	else memcpy(status->domainName, host, 512);
	return 0;
}

/*
	Constructor
*/
QuickerRoute::QuickerRoute()
{
	/*
		Initialize ICMP socket for communication
	*/
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock == INVALID_SOCKET)
	{
		printf("Unable to create ICMP socket. Terminating\n");
		WSACleanup();
		exit(-1);
	}

	/*
		Initialize the high precision counter.
	*/
	QueryPerformanceFrequency(&frequency);

}

/*
	Initializes the shared Parameters.
*/
void QuickerRoute::initParameters()
{
	for (int i = 0; i <= MAX_HOPS; i++)
	{
		hopInfo[i].ttl = 0;
		hopInfo[i].RTT = 0.0;
		hopInfo[i].isEcho = false;
		hopInfo[i].received = false;
		hopInfo[i].probesSent = 0;
		memset(hopInfo[i].char_ip, 0, 16);
		memset(hopInfo[i].domainName, 0, 512);
	}
}

/*
	Does Internet checksum calculation
*/
u_short QuickerRoute::ip_checksum(u_short *buffer, int size)
{
	u_long cksum = 0;

	while (size > 1)
	{
		cksum += *buffer++;
		size -= sizeof(u_short);
	}

	if (size)cksum += *(u_char *)buffer;

	cksum = (cksum >> 16) + (cksum & 0xffff);

	return (u_short)(~cksum);
}

/*
	Sends ICMPProbe with given TTL value
*/
int QuickerRoute::sendICMPProbe(int ttl)
{
	u_char send_buf[MAX_ICMP_SIZE];
	ICMPHeader *icmp = (ICMPHeader *)send_buf;
	icmp->type = ICMP_ECHO_REQUEST;
	icmp->code = 0;
	icmp->id = (u_short)GetCurrentProcessId();
	icmp->seq = ttl;
	icmp->checksum = 0;
	int packet_size = sizeof(ICMPHeader);
	icmp->checksum = ip_checksum((u_short *)send_buf, packet_size);

	if (setsockopt(sock, IPPROTO_IP, IP_TTL, (const char *)&ttl, sizeof(ttl)) == SOCKET_ERROR)
	{
		printf("setsockopt failed with %d\n", WSAGetLastError());
		return ERROR_VALUE;
	}

	if (sendto(sock, (char *)icmp, sizeof(ICMPHeader), 0, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR)
	{

		printf("Error in sendto: %d. Aborting...\n", WSAGetLastError());
		return ERROR_VALUE;
	}

	hopInfo[ttl].probesSent++;
	QueryPerformanceCounter(&hopInfo[ttl].sendTime);
	hopInfo[ttl].ttl = ttl;

	return SUCCESS_VALUE;
}

/*
	Listens for ICMP reply packets. Invokes DNS reverse lookup thread asynchronously.
	Waits for all DNS and retransmission packets to be handled before exiting.
*/
int QuickerRoute::recvICMPResponse(int& pingReplyHop)
{
	/*
		ICMP Socket Read Event
	*/
	WSAEVENT socketRecvEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	/*
		Decides when to exit the Listen Mode
	*/
	bool finish = false;


	if (WSAEventSelect(sock, socketRecvEvent, FD_READ) == SOCKET_ERROR)
	{
		printf("error with WSAEventSelect %d\n", WSAGetLastError());
		return ERROR_VALUE;
	}

	struct sockaddr_in response;
	int size = sizeof(response);
	int bytesRecv;
	bool echoPacketRecv = false;

	clock_t hopTimer = clock() + DEFAULT_TIME_OUT;

	/*
		Marks the number of DNS threads dispatched
	*/
	int numThreads = 0;

	while (!finish)
	{
		u_char rec_buf[MAX_REPLY_SIZE];

		DWORD timeout = (DWORD)(hopTimer - clock());

		int ret = WaitForSingleObject(socketRecvEvent, timeout);

		switch (ret)
		{
			/*
				Handle ICMP socket Recv Event
			*/
		case WAIT_OBJECT_0:
		{
			bytesRecv = recvfrom(sock, (char*)&rec_buf, MAX_REPLY_SIZE, 0, (struct sockaddr*)&response, &size);

			if (bytesRecv == SOCKET_ERROR)
			{
				printf("Error while recv from socket. %d\n", WSAGetLastError());
				return ERROR_VALUE;
			}


			IPHeader *router_ip_hdr = (IPHeader *)rec_buf;

			/*
				IP Header can be variable size. The total IP header size
				can be determined by header length parameter.
			*/
			int IPHeaderSize = router_ip_hdr->h_len * 4;

			ICMPHeader *router_icmp_hdr = (ICMPHeader *)(rec_buf + IPHeaderSize);
			IPHeader *orig_ip_hdr = (IPHeader *)(router_icmp_hdr + 1);
			ICMPHeader *orig_icmp_hdr = (ICMPHeader *)(orig_ip_hdr + 1);

			/*
				TTL Expire packets are at least 56 bytes in size.
				Then check if the ip protocol is ICMP and processId is the current processID.
			*/
			if (bytesRecv >= TTL_EXPIRE_PKT_SIZE)
			{
				if (orig_ip_hdr->proto == IPPROTO_ICMP && orig_icmp_hdr->id == (u_short)GetCurrentProcessId())
				{
					int ttl = orig_icmp_hdr->seq;
					if (router_icmp_hdr->type == ICMP_TTL_EXPIRED && router_icmp_hdr->code == 0)
					{
						if (!hopInfo[ttl].received)
						{
							hopInfo[ttl].IP = (router_ip_hdr->source_ip);
							LARGE_INTEGER endTime;
							QueryPerformanceCounter(&endTime);
							LARGE_INTEGER diff;
							diff.QuadPart = endTime.QuadPart - hopInfo[ttl].sendTime.QuadPart;
							diff.QuadPart *= 1000000;
							diff.QuadPart /= frequency.QuadPart;
							hopInfo[ttl].RTT = diff.QuadPart / 1000.0;
							hopInfo[ttl].type = ICMP_TTL_EXPIRED;
							hopInfo[ttl].code = 0;
							queryThreads[numThreads++] = CreateThread(NULL, 0, reverseLookup_thread, &hopInfo[ttl], 0, NULL);
							hopInfo[ttl].received = true;
						}
					}
					/*
						Error ICMP packets.
					*/
					else
					{
						if (!hopInfo[ttl].received)
						{
							hopInfo[ttl].IP = (router_ip_hdr->source_ip);
							LARGE_INTEGER endTime;
							QueryPerformanceCounter(&endTime);
							LARGE_INTEGER diff;
							diff.QuadPart = endTime.QuadPart - hopInfo[ttl].sendTime.QuadPart;
							diff.QuadPart *= 1000000;
							diff.QuadPart /= frequency.QuadPart;
							hopInfo[ttl].RTT = diff.QuadPart / 1000.0;
							hopInfo[ttl].type = router_icmp_hdr->type;
							hopInfo[ttl].code = router_icmp_hdr->code;
							queryThreads[numThreads++] = CreateThread(NULL, 0, reverseLookup_thread, &hopInfo[ttl], 0, NULL);
							hopInfo[ttl].received = true;
						}
					}
				}
			}
			/*
				ECHO REPLY packets are at least 28 bytes in size.
				Chcek if the protocol and processId is the current processID.
			*/
			else if (bytesRecv >= ECHO_REPLY_PKT_SIZE)
			{
				if (router_ip_hdr->proto == IPPROTO_ICMP && router_icmp_hdr->id == (u_short)GetCurrentProcessId())
				{
					int ttl = router_icmp_hdr->seq;
					if (router_icmp_hdr->type == ICMP_ECHO_REPLY && router_icmp_hdr->code == 0)
					{
						if (!echoPacketRecv)
						{
							hopInfo[ttl].IP = (router_ip_hdr->source_ip);
							LARGE_INTEGER endTime;
							QueryPerformanceCounter(&endTime);
							LARGE_INTEGER diff;
							diff.QuadPart = endTime.QuadPart - hopInfo[ttl].sendTime.QuadPart;
							diff.QuadPart *= 1000000;
							diff.QuadPart /= frequency.QuadPart;
							hopInfo[ttl].RTT = diff.QuadPart / 1000.0;
							hopInfo[ttl].isEcho = true;
							queryThreads[numThreads++] = CreateThread(NULL, 0, reverseLookup_thread, &hopInfo[ttl], 0, NULL);
							hopInfo[ttl].type = ICMP_ECHO_REPLY;
							hopInfo[ttl].code = 0;
							hopInfo[ttl].received = true;
							echoPacketRecv = true;
							pingReplyHop = ttl;
						}
					}
					/*
						Error ICMP response
					*/
					else
					{
						if (!echoPacketRecv)
						{
							hopInfo[ttl].IP = (router_ip_hdr->source_ip);
							LARGE_INTEGER endTime;
							QueryPerformanceCounter(&endTime);
							LARGE_INTEGER diff;
							diff.QuadPart = endTime.QuadPart - hopInfo[ttl].sendTime.QuadPart;
							diff.QuadPart *= 1000000;
							diff.QuadPart /= frequency.QuadPart;
							hopInfo[ttl].RTT = diff.QuadPart / 1000.0;
							hopInfo[ttl].isEcho = true;
							queryThreads[numThreads++] = CreateThread(NULL, 0, reverseLookup_thread, &hopInfo[ttl], 0, NULL);
							hopInfo[ttl].type = router_icmp_hdr->type;
							hopInfo[ttl].code = router_icmp_hdr->code;
							hopInfo[ttl].received = true;
							echoPacketRecv = true;
							pingReplyHop = ttl;
						}

					}
				}
			}
			/*
				If Response is smaller than 28 bytes, ignore it.
			*/
		}
		break;

		/*
			On timeOut, Retransmitt the missing Probes and dynamically calculate the new Retransmission Timeout.

		*/
		case WAIT_TIMEOUT:
		{
			bool rtx = false;
			DWORD maxRTO = 0;
			for (int i = 1; i < pingReplyHop; i++)
			{
				DWORD ballPark = DEFAULT_TIME_OUT;
				if (!hopInfo[i].received && hopInfo[i].probesSent < 3)
				{
					if (i > 1 && hopInfo[i - 1].received) ballPark = (DWORD)hopInfo[i - 1].RTT * 2;
					if (i < MAX_HOPS && hopInfo[i + 1].received)
					{
						if (ballPark == DEFAULT_TIME_OUT) ballPark = (DWORD)hopInfo[i + 1].RTT * 2;
						else
						{
							ballPark = ballPark + (DWORD)hopInfo[i + 1].RTT * 2;
							ballPark = ballPark / 2;
						}
					}
					maxRTO = max(maxRTO, ballPark);
					sendICMPProbe(i);
					rtx = true;
				}
			}
			if (!rtx) finish = true;
			else hopTimer = clock() + maxRTO;
		}
		break;
		default:break;
		}
	}

	/*
		Wait for all pending DNS threads to finish
	*/
	WaitForMultipleObjects(numThreads, queryThreads, TRUE, INFINITE);

	/*
		Close All DNS Threads
	*/
	for (int i = 0; i < numThreads; i++)
	{
		CloseHandle(queryThreads[i]);
	}

	return (pingReplyHop < (MAX_HOPS + 1)) ? SUCCESS_VALUE : DESTINATION_BEYOND_MAX_HOPS;
}

/*
	Prints the Traceroute Stats
*/
void QuickerRoute::printResult()
{
	for (int i = 1; i <= MAX_HOPS; i++)
	{
		printf("%d ", hopInfo[i].ttl);
		if (hopInfo[i].probesSent >= 3)
		{
			printf("*\n");
			continue;
		}
		printf("%s ", hopInfo[i].domainName);
		printf("(%s) ", hopInfo[i].char_ip);
		printf(" %.3f ms (%d) ", hopInfo[i].RTT, hopInfo[i].probesSent);
		if (hopInfo[i].type != ICMP_ECHO_REPLY && hopInfo[i].type != ICMP_TTL_EXPIRED)
		{
			printf("Other Error: Type %d, Code %d", hopInfo[i].type, hopInfo[i].code);
		}
		printf("\n");
		if (hopInfo[i].isEcho) break;
	}
}

/*
	Performs TraceRoute
*/
int QuickerRoute::trace(const char* host)
{
	/*
		Resolve Destination IP Address
	*/
	serverAddress.sin_family = AF_INET;
	DWORD IP = inet_addr(host);
	if (IP == INADDR_NONE)
	{
		struct hostent* remote;
		if ((remote = gethostbyname(host)) == NULL)
		{
			printf("host does not exists %s\n",host);
			return ERROR_VALUE;
		}
		else memcpy((char*)&(serverAddress.sin_addr), remote->h_addr, remote->h_length);
	}
	else
	{
		serverAddress.sin_addr.S_un.S_addr = IP;
	}

	/*
		Initialize the status parameters
	*/
	initParameters();

	/*
		begin
	*/

	printf("Tracerouting to %s\n", inet_ntoa(serverAddress.sin_addr));

	/*
		Send ICMP probes
	*/
	clock_t startTime = clock();

	for (int i = 1; i <= MAX_HOPS; i++)
	{
		if (sendICMPProbe(i) == ERROR_VALUE)
		{
			closesocket(sock);
			WSACleanup();
			printf("Aborting...\n");
			return ERROR_VALUE;
		}
	}

	/*
		Hop Number of Destination Address. When the ECHO REPLY is recieved pingReplyHop will
		be set to the seq number of the response. Any seq beyond this will be ignored.
	*/
	int pingReplyHop = MAX_HOPS + 1;

	/*
		Listen for ICMP responses
	*/
	int ret = recvICMPResponse(pingReplyHop);

	if (ret == ERROR_VALUE)
	{
		closesocket(sock);
		WSACleanup();
		printf("Aborting...\n");
		return ERROR_VALUE;
	}

	clock_t endTime = clock();

	int timeTaken = TIME(startTime, endTime);


	/*
		Print TraceRoutes
	*/

	printResult();

	printf("\nTotal execution time: %d ms\n\n", timeTaken);


	return SUCCESS_VALUE;
}

/*
	Gracefully clears Everything
*/
QuickerRoute::~QuickerRoute()
{
	closesocket(sock);
}

