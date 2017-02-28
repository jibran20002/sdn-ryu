# sdn-ryu
The project aims to make use of external (Northbound) interface for determining whether to forward the packet to destination. The further enhancement aims at integrating with BSS/OSS using Westbound interface with Diameter API. This can be used for charging references or for future support / enhancement. Hence, this project helps to demonstrates to some extent the capabilities of SDN and possibilities of integration with other sub-systems.

Implementation details:
The project is to be implemented using Mininet with OVSK and RYU controller. The reason for selecting RYU controller is to make use of OpenFlow 1.3 with python programming. 

Bali BV – Base Version Release details:
The controller should initially instruct the OVS (virtual switch) to forward all the packets with the TCP port number 80 (starting off with HTTP port) to the controller for further handling. The controller will also implement L3 switch routing (IP forwarding) based on learnings from the ARP messages. Once the switch forwards the TCP port 80 segment to the controller, the controller should decode the IP layer first and then the Transport layer for performing pre-checks. Once the pre-checks pass, the controller should establish a UDP connection with a remote Northbound server passing the whole OpenFlow PacketIn message with the data payload to the remote server. The remote server here will write the raw message received into a file. The Bali version is expected to forward the message to the destination (i.e. the controller should forward the message) irrespective of whether the message delivered to Northbound interface or a positive acknowledged was received from the Northbound interface.

Goa CV – Enhanced Version Release details:
The Goa enhanced version should include another port handling apart from TCP 80 (maybe SSH port 22). The controller should forward or drop the packet based on response from the Northbound interface. Also, instead of raw OpenFlow PacketIn message being passed to Northbound, a PCAP dump type message may be passed.

Ibiza CV – Enhanced Version Release details:
The Ibiza enhanced version should build on Goa version with support for TCP or UDP connection to the Northbound interface (earlier versions used UDP only). Enhancement for this version is mainly to incorporate Diameter API. The API is to use the TCP/UDP Northbound connection and probably move this integration (or add another TCP/UDP connection) to Westbound interface for B/OSS integration (like charging or management requests and responses). 
