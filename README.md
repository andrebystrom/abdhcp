# abdhcp - DHCP server in C
Simple and portable LAN Ethernet DHCP server.

![Build release](https://github.com/andrebystrom/abdhcp/actions/workflows/build.yml/badge.svg)

# Building
Clone the project, cd into it and run 
>make

The binary is created in the build directory.

# Usage
First make sure to assign your computer a static IPv4 address and disable any DHCP servers running on your network, eg. on your router.
Note that the program needs superuser privileges since we are using a privileged port for DHCP.

>abdhcp -n \<start address>:\<end address> -s \<server address> -m \<subnet mask> [-g \<gateway>] [-d \<dns server>]

The flag -v can be used to get more detailed output.

For example, on the network 192.168.0.0/24 with server IP 192.168.0.1 and
DHCP scope of 192.168.0.100-192.168.0.200:

>./abdhcp -n 192.168.0.100:192.168.0.200 -s 192.168.0.1 -m 255.255.255.0


# Resources
[DHCP packet format](https://techhub.hpe.com/eginfolib/networking/docs/switches/5120si/cg/5998-8491_l3-ip-svcs_cg/content/436042653.htm)

[DHCP RFC](https://www.rfc-editor.org/rfc/rfc2131)

[DHCP options RFC](https://www.rfc-editor.org/rfc/rfc2132)

# Features
- [x] Discover
- [x] Offer
- [X] Request
- [X] Ack
- [ ] Nak
- [ ] Inform
- [X] Release
- [ ] Decline
