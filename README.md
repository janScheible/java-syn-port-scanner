# java-syn-port-scanner

Java syn port scanner prototype using [pcap4j](https://www.pcap4j.org/).
Tested with Ubuntu 24.04 and Java 21.
Requires `libpcap-dev`.
The `ip` tool is also required to get the default gateway's MAC address.

To allow `libpcap` to capture raw socket packets the permissions must be set for the Java process.
For example: `sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f /usr/bin/java)`

## Functionality

Only a `SYN` packet is sent in the Java code.
The `RST` package (in case of an open port) that is visible in Wireshark is not send by the Java code but by the kernel (that knows nothing about the outgoing connection).
The ICMP packets at the beginning are from the ping that is used to make sure that we can get the default gateway's MAC address.

The following sections show the three different outcomes.

### Open port

![Open port](open-port.png 'Open port')

### Closed port with answer

![Closed port with answer](closed-port-with-answer.png 'Closed port with answer')

### Closed port without answer

Some server do not answer at all for closed ports.
In that case the port scanner exits after a timeout of 5 seconds.

![Closed port without answer](closed-port-without-answer.png 'Closed port without answer')
