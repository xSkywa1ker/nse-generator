#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <vector>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/if_packet.h>
#include <net/if.h>

#define DHCP_DISCOVER 1
#define DHCP_OPTION_MESSAGE_TYPE 53
#define DHCP_OPTION_END 255

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
    u_char magic_cookie[4];
    u_char options[308];
};

uint16_t checksum(uint16_t *buf, int nwords) {
    uint32_t sum = 0;
    for (int i = 0; i < nwords; i++) {
        sum += ntohs(buf[i]);
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return htons(~sum);
}

void send_dhcp_discover(const char* interface, const u_char* client_mac, u_int32_t transaction_id, u_short flags, 
                        const std::vector<std::vector<u_char>>& options) {
    int clientSocket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (clientSocket < 0) {
        perror("Error creating socket");
        return;
    }

    // DHCP Header
    DhcpHeader dhcpHeader = {0};
    dhcpHeader.op = 1; // Boot Request
    dhcpHeader.htype = 1; // Ethernet
    dhcpHeader.hlen = 6; // Hardware address length
    dhcpHeader.hops = 0;
    dhcpHeader.xid = htonl(transaction_id); // Transaction ID
    dhcpHeader.secs = htons(0);
    dhcpHeader.flags = htons(flags); // Flags
    dhcpHeader.ciaddr = htonl(0);
    dhcpHeader.yiaddr = htonl(0);
    dhcpHeader.siaddr = htonl(0);
    dhcpHeader.giaddr = htonl(0);
    memcpy(dhcpHeader.chaddr, client_mac, 6);
    dhcpHeader.magic_cookie[0] = 0x63;
    dhcpHeader.magic_cookie[1] = 0x82;
    dhcpHeader.magic_cookie[2] = 0x53;
    dhcpHeader.magic_cookie[3] = 0x63;

    int option_index = 0;
    for (const auto& option : options) {
        memcpy(&dhcpHeader.options[option_index], option.data(), option.size());
        option_index += option.size();
    }
    dhcpHeader.options[option_index++] = DHCP_OPTION_END;

    // Packet Buffer
    uint8_t buffer[1500] = {0};

    // Ethernet Header
    struct ethhdr *eth = (struct ethhdr *)buffer;
    memset(eth->h_dest, 0xff, 6); // Broadcast
    memcpy(eth->h_source, client_mac, 6);
    eth->h_proto = htons(ETH_P_IP);

    // IP Header
    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0x00;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(DhcpHeader) - 308 + option_index);
    ip->id = htons(0);
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->saddr = inet_addr("0.0.0.0");
    ip->daddr = inet_addr("255.255.255.255");
    ip->check = 0;
    ip->check = checksum((uint16_t *)ip, ip->ihl * 2);

    // UDP Header
    struct udphdr *udp = (struct udphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
    udp->source = htons(68);
    udp->dest = htons(67);
    udp->len = htons(sizeof(struct udphdr) + sizeof(DhcpHeader) - 308 + option_index);
    udp->check = 0;

    // DHCP Payload
    uint8_t *dhcp = buffer + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
    memcpy(dhcp, &dhcpHeader, sizeof(DhcpHeader) - 308 + option_index);

    struct sockaddr_ll addr = {0};
    addr.sll_ifindex = if_nametoindex(interface);
    addr.sll_halen = ETH_ALEN;
    memset(addr.sll_addr, 0xff, 6);

    int sentBytes = sendto(clientSocket, buffer, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(DhcpHeader) - 308 + option_index, 0, (struct sockaddr *)&addr, sizeof(addr));
    if (sentBytes < 0) {
        perror("Error sending packet");
    } else {
        std::cout << "Packet sent successfully, bytes: " << sentBytes << std::endl;
    }

    close(clientSocket);
}

int main() {
    const char* interface = "ens33";
    const u_char client_mac[6] = {0x00, 0x0c, 0x29, 0x95, 0xc3, 0x64};
    u_int32_t transaction_id = 0x643c9869;
    u_short flags = 0x8000; // Broadcast flag

    std::vector<std::vector<u_char>> options = {
        {DHCP_OPTION_MESSAGE_TYPE, 1, DHCP_DISCOVER} // DHCP Discover
    };

    send_dhcp_discover(interface, client_mac, transaction_id, flags, options);

    return 0;
}

