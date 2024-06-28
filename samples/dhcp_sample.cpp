#include

<iostream>

#include
<vector>

#include
<cstring>

#include
<netinet/in.h>

#include

<sys/socket.h>

#include

<unistd.h>

#include

<arpa/inet.h>

#include

<net/ethernet.h>

#include

<net/if.h>

#include

<sys/ioctl.h>

#include

<linux/if_packet.h>

#include

<netinet/ip.h>

#include

<netinet/udp.h>

#include

<poll.h>

#define
MAX_PACKETS 100
#define
DHCP_MAGIC_COOKIE "\x63\x82\x53\x63"

struct DhcpHeader {
    u_char op;
    u_char htype;
    u_char hlen;
    u_char hops;
    u_int32_t xid;
    u_short secs;
    u_short flags;
    u_int32_t ciaddr;
    u_int32_t yiaddr;
    u_int32_t siaddr;
    u_int32_t giaddr;
    u_char chaddr[16];
    u_char sname[64];
    u_char file[128];
    u_char options[312]; // DHCP options
};

struct EthernetHeader {
    u_char dest[6];
    u_char src[6];
    u_short type;
};

// Global vector to store received packets
std::vector <std::vector<u_char>> receivedPackets;

unsigned short calculate_checksum(unsigned short *buffer, int size) {
    unsigned long cksum = 0;
    while (size > 1) {
        cksum += *buffer++;
        size -= sizeof(unsigned short);
    }
    if (size) {
        cksum += *(unsigned char *) buffer;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (unsigned short) (~cksum);
}

void send_and_receive_dhcp_packet(const char *interface, const char *source_mac, const char *client_mac,
                                  u_int32_t transaction_id, const std::vector <std::pair<u_char, std::vector < u_char>>

> &options,
int ip_id,
int ip_ttl, u_int32_t
src_ip,
u_int32_t dst_ip
) {
int clientSocket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
if (clientSocket < 0) {
perror("Error creating socket");
return;
}

struct ifreq ifr;
memset(&ifr,
0, sizeof(ifr));
strncpy(ifr
.ifr_name, interface, IFNAMSIZ - 1);
if (
ioctl(clientSocket, SIOCGIFINDEX, &ifr
) < 0) {
perror("Error getting interface index");
close(clientSocket);
return;
}

EthernetHeader ethHeader;
sscanf(source_mac,
"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &ethHeader.src[0], &ethHeader.src[1], &ethHeader.src[2],
&ethHeader.src[3], &ethHeader.src[4], &ethHeader.src[5]);
sscanf("ff:ff:ff:ff:ff:ff", "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &ethHeader.dest[0], &ethHeader.dest[1], &ethHeader.dest[2],
&ethHeader.dest[3], &ethHeader.dest[4], &ethHeader.dest[5]);
ethHeader.
type = htons(ETH_P_IP);

struct ip ipHeader;
ipHeader.
ip_hl = 5;
ipHeader.
ip_v = 4;
ipHeader.
ip_tos = 0;
ipHeader.
ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + sizeof(DhcpHeader));
ipHeader.
ip_id = htons(ip_id);
ipHeader.
ip_off = 0;
ipHeader.
ip_ttl = ip_ttl;
ipHeader.
ip_p = IPPROTO_UDP;
ipHeader.ip_src.
s_addr = htonl(src_ip);
ipHeader.ip_dst.
s_addr = htonl(dst_ip);
ipHeader.
ip_sum = 0;
ipHeader.
ip_sum = calculate_checksum((unsigned short *) &ipHeader, ipHeader.ip_hl * 4);

struct udphdr udpHeader;
udpHeader.
uh_sport = htons(68);
udpHeader.
uh_dport = htons(67);
udpHeader.
uh_ulen = htons(sizeof(struct udphdr) + sizeof(DhcpHeader));
udpHeader.
uh_sum = 0;

DhcpHeader dhcpHeader;
memset(&dhcpHeader,
0, sizeof(DhcpHeader));
dhcpHeader.
op = 1;
dhcpHeader.
htype = 1;
dhcpHeader.
hlen = 6;
dhcpHeader.
xid = htonl(transaction_id);
dhcpHeader.
secs = htons(0);
dhcpHeader.
flags = htons(0x8000);
memcpy(dhcpHeader
.chaddr, client_mac, 6);

u_char *options_ptr = dhcpHeader.options;
options_ptr[0] = 0x63; // DHCP magic cookie
options_ptr[1] = 0x82;
options_ptr[2] = 0x53;
options_ptr[3] = 0x63;
options_ptr += 4;

for (
const auto &option
: options) {
*options_ptr++ = option.
first;
*options_ptr++ = option.second.

size();

for (
const auto &val
: option.second) {
*options_ptr++ =
val;
}
}
*
options_ptr = 255; // End option

char buffer[sizeof(EthernetHeader) + sizeof(struct ip) + sizeof(struct udphdr) + sizeof(DhcpHeader)];
memcpy(buffer, &ethHeader,
sizeof(EthernetHeader));
memcpy(buffer
+ sizeof(EthernetHeader), &ipHeader, sizeof(struct ip));
memcpy(buffer
+ sizeof(EthernetHeader) + sizeof(struct ip), &udpHeader, sizeof(struct udphdr));
memcpy(buffer
+ sizeof(EthernetHeader) + sizeof(struct ip) + sizeof(struct udphdr), &dhcpHeader, sizeof(DhcpHeader));

struct sockaddr_ll addr = {0};
addr.
sll_ifindex = ifr.ifr_ifindex;
addr.
sll_halen = ETH_ALEN;
memcpy(addr
.sll_addr, ethHeader.dest, ETH_ALEN);

if (
sendto(clientSocket, buffer,
sizeof(buffer), 0, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
perror("Error sending packet");
close(clientSocket);
return;
}

struct pollfd fds[1];
fds[0].
fd = clientSocket;
fds[0].
events = POLLIN;

while (true) {
int poll_result = poll(fds, 1, 10000); // 10 seconds timeout
if (poll_result > 0) {
if (fds[0].
revents &POLLIN
) {
char recv_buffer[2048];
ssize_t len = recvfrom(clientSocket, recv_buffer, sizeof(recv_buffer), 0, NULL, NULL);
if (len > 0) {
struct ip *received_ip = (struct ip *) (recv_buffer + sizeof(EthernetHeader));
struct udphdr *received_udp = (struct udphdr *) (recv_buffer + sizeof(EthernetHeader) + received_ip->ip_hl * 4);

if (received_udp->uh_dport == htons(68)) {  // Check for DHCP client port
std::vector <u_char> packet(recv_buffer, recv_buffer + len);
receivedPackets.
push_back(packet);
std::cout << "DHCP packet received." <<
std::endl;
break; // Stop after receiving the first valid DHCP packet
}
}
}
} else if (poll_result == 0) {
std::cout << "No response received within timeout." <<
std::endl;
break;
} else {
perror("Poll error");
break;
}
}

close(clientSocket);
}


void process_dhcp_packet(const std::vector <u_char> &packet) {
    if (packet.size() < sizeof(EthernetHeader) + sizeof(struct ip) + sizeof(struct udphdr) + sizeof(DhcpHeader)) {
        std::cout << "Packet too small" << std::endl;
        return;
    }

    const EthernetHeader *ethHeader = reinterpret_cast<const EthernetHeader *>(&packet[0]);
    const struct ip *ipHeader = reinterpret_cast<const struct ip *>(&packet[sizeof(EthernetHeader)]);
    const struct udphdr *udpHeader = reinterpret_cast<const struct udphdr *>(&packet[sizeof(EthernetHeader) +
                                                                                     sizeof(struct ip)]);
    const DhcpHeader *dhcpHeader = reinterpret_cast<const DhcpHeader *>(&packet[sizeof(EthernetHeader) +
                                                                                sizeof(struct ip) +
                                                                                sizeof(struct udphdr)]);

    std::cout << "Ethernet Header" << std::endl;
    std::cout << "  Source MAC: ";
    for (int i = 0; i < 6; i++) std::cout << std::hex << (int) ethHeader->src[i] << (i < 5 ? ":" : "\n");
    std::cout << "  Destination MAC: ";
    for (int i = 0; i < 6; i++) std::cout << std::hex << (int) ethHeader->dest[i] << (i < 5 ? ":" : "\n");

    std::cout << "IP Header" << std::endl;
    std::cout << "  Source IP: " << inet_ntoa(ipHeader->ip_src) << std::endl;
    std::cout << "  Destination IP: " << inet_ntoa(ipHeader->ip_dst) << std::endl;

    std::cout << "UDP Header" << std::endl;
    std::cout << "  Source Port: " << ntohs(udpHeader->uh_sport) << std::endl;
    std::cout << "  Destination Port: " << ntohs(udpHeader->uh_dport) << std::endl;

    std::cout << "DHCP Header" << std::endl;
    std::cout << "  Opcode: " << std::dec << (int) dhcpHeader->op << std::endl;
    std::cout << "  Hardware Type: " << (int) dhcpHeader->htype << std::endl;
    std::cout << "  Hardware Address Length: " << (int) dhcpHeader->hlen << std::endl;
    std::cout << "  Hops: " << (int) dhcpHeader->hops << std::endl;
    std::cout << "  Transaction ID: " << ntohl(dhcpHeader->xid) << std::endl;
    std::cout << "  Seconds: " << ntohs(dhcpHeader->secs) << std::endl;
    std::cout << "  Flags: " << ntohs(dhcpHeader->flags) << std::endl;
    std::cout << "  Client IP Address: " << inet_ntoa(*(struct in_addr *) &dhcpHeader->ciaddr) << std::endl;
    std::cout << "  Your IP Address: " << inet_ntoa(*(struct in_addr *) &dhcpHeader->yiaddr) << std::endl;
    std::cout << "  Server IP Address: " << inet_ntoa(*(struct in_addr *) &dhcpHeader->siaddr) << std::endl;
    std::cout << "  Gateway IP Address: " << inet_ntoa(*(struct in_addr *) &dhcpHeader->giaddr) << std::endl;
    std::cout << "  Client MAC Address: ";
    for (int i = 0; i < 6; i++) std::cout << std::hex << (int) dhcpHeader->chaddr[i] << (i < 5 ? ":" : "\n");

    std::cout << "DHCP Options" << std::endl;
    const u_char *options_ptr = dhcpHeader->options;
    while (*options_ptr != 255) {
        u_char option_code = *options_ptr++;
        u_char option_len = *options_ptr++;
        std::cout << "  Option " << std::dec << (int) option_code << ": ";
        for (int i = 0; i < option_len; i++) {
            std::cout << std::hex << (int) *options_ptr++ << (i < option_len - 1 ? ":" : "\n");
        }
    }
}

int main() {
    const char *interface = "ens33";
    const char *source_mac = "00:0c:29:95:c3:65";
    const char *client_mac = "00:1a:2b:3c:4d:5e";
    u_int32_t transaction_id = 0x3903F326;

    std::vector < std::pair < u_char, std::vector < u_char>>> options = {
            {
                    53, {
                                1
                        }
            }, // DHCP Message Type: DHCPDISCOVER
            {
                    55, {
                                1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121
                        }
            } // Parameter Request List
    };

    send_and_receive_dhcp_packet(interface, source_mac, client_mac, transaction_id, options, 1, 64, INADDR_ANY,
                                 INADDR_BROADCAST);

    for (const auto &packet : receivedPackets) {
        process_dhcp_packet(packet);
    }

    return 0;
}
