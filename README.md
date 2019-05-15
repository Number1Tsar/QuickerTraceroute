# QuickerTraceroute
A faster version of traceroute command for windows environment. Unlike regular traceroute, instead of sending and receiving ICMP packets from one hop at a time, ICMP packets with increasing TTL are sent to all the routers in parallel and the response from them are processed accordingly. This allows the path to be traced must faster than tracert command.
A maximum of 30 Hops are attempted to trace the destination address and maximum of 3 retries are made to send/receive ICMP packets from each router. If unable to receive after 3 attempts, the router is marked as * in the output.
The output is shown in following format

    <Hop count> <DNS name of router> <IP address of router> <Round trip time> <Number of retry made>


# To Run
./TraceRoute.exe <hostname>

# Example:

`./TraceRoute.exe www.google.com`

    Tracerouting to 172.217.6.132
    
    1 <no DNS entry> (192.168.0.1)  4.248 ms (1)
    
    2 *
    
    3 173-219-197-200.suddenlink.net (173.219.197.200)  10.285 ms (1)
    
    4 173-219-152-250.suddenlink.net (173.219.152.250)  14.994 ms (1)
    
    5 <no DNS entry> (72.14.202.216)  14.115 ms (1)
    
    6 <no DNS entry> (108.170.240.193)  14.577 ms (1)
    
    7 <no DNS entry> (72.14.232.167)  14.491 ms (1)
    
    8 dfw25s16-in-f4.1e100.net (172.217.6.132)  14.074 ms (1)`
    
    
