#include "pch.h"
#include "NetworkPackets.h"
#include "QuickerRoute.h"


/*
	Main
*/
int main(int argc, char* argv[])
{
	/*
		Winsock init routine
	*/
	WSADATA wsaData;
	WORD wVersionRequested = MAKEWORD(2, 2);

	if (WSAStartup(wVersionRequested, &wsaData) != 0)
	{
		printf("WSAStartup error %d\n", WSAGetLastError());
		WSACleanup();
		return 0;
	}

	const char* host;

	/*
		Extract hostname from command line argument
	*/
	if (argc != 2)
	{
		printf("The traceroute accept one argument as hostname.\n");
		WSACleanup();
		return 0;
	}
	host = argv[1];

	/*
		Create a Parallel Trace route Object and start tracing the given Address.
	*/
	QuickerRoute tracer;
	tracer.trace(host);

	WSACleanup();
	return 0;
}