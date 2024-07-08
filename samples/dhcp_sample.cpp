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
#include <sys/ioctl.h>  // Added for SIOCGIFINDEX and ioctl

#define DHCP_DISCOVER 1
#define DHCP_OFFER 2
#define DHCP_REQUEST 3
#define DHCP_DECLINE 4
#define DHCP_ACK 5
#define DHCP_NAK 6
#define DHCP_RELEASE 7
#define DHCP_INFORM 8

#define DHCP_OPTION_MESSAGE_TYPE 53
#define DHCP_OPTION_END 255

#define SIZE_ETHERNET 14

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

struct ip_header {
    u_char ver_ihl;
    u_char tos;
    u_short tlen;
    u_short identification;
    u_short flags_fo;
    u_char ttl;
    u_char proto;
    u_short crc;
    struct in_addr saddr;
    struct in_addr daddr;
    u_int op_pad;
};

struct udp_header {
    u_short sport;
    u_short dport;
    u_short len;
    u_short crc;
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

void mac_str_to_bytes(const char* mac_str, u_char* mac_bytes) {
    sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &mac_bytes[0], &mac_bytes[1], &mac_bytes[2],
           &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]);
}

void send_dhcp_discover(const char* interface, const char* client_mac_str, u_int32_t transaction_id, u_short secs, u_short flags,
                        u_int32_t ciaddr, u_int32_t yiaddr, u_int32_t siaddr, u_int32_t giaddr,
                        u_char ttl, const char* src_ip, const char* dest_ip, u_short src_port, u_short dest_port,
                        u_char option_type, u_char option_length, u_char option_value) {
    u_char client_mac[6];
    mac_str_to_bytes(client_mac_str, client_mac);

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
    dhcpHeader.secs = htons(secs);
    dhcpHeader.flags = htons(flags); // Flags
    dhcpHeader.ciaddr = ciaddr;
    dhcpHeader.yiaddr = yiaddr;
    dhcpHeader.siaddr = siaddr;
    dhcpHeader.giaddr = giaddr;
    memcpy(dhcpHeader.chaddr, client_mac, 6);
    dhcpHeader.magic_cookie[0] = 0x63;
    dhcpHeader.magic_cookie[1] = 0x82;
    dhcpHeader.magic_cookie[2] = 0x53;
    dhcpHeader.magic_cookie[3] = 0x63;

    // DHCP Options
    int option_index = 0;
    dhcpHeader.options[option_index++] = option_type;
    dhcpHeader.options[option_index++] = option_length;
    dhcpHeader.options[option_index++] = option_value;
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
    ip->ttl = ttl;
    ip->protocol = IPPROTO_UDP;
    ip->saddr = inet_addr(src_ip);
    ip->daddr = inet_addr(dest_ip);
    ip->check = 0;
    ip->check = checksum((uint16_t *)ip, ip->ihl * 2);

    // UDP Header
    struct udphdr *udp = (struct udphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
    udp->source = htons(src_port);
    udp->dest = htons(dest_port);
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

void receive_dhcp_offer(const char* interface) {
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("Error creating socket");
        return;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("Error getting interface index");
        close(sockfd);
        return;
    }

    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = ifr.ifr_ifindex;
    sa.sll_protocol = htons(ETH_P_ALL);

    if (bind(sockfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("Error binding socket to interface");
        close(sockfd);
        return;
    }

    uint8_t buffer[1500];
    while (true) {
        int recvBytes = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
        if (recvBytes < 0) {
            perror("Error receiving packet");
            continue;
        }

        struct ethhdr *eth = (struct ethhdr *)buffer;
        if (ntohs(eth->h_proto) != ETH_P_IP) {
            continue;
        }

        struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        if (ip->protocol != IPPROTO_UDP) {
            continue;
        }

        struct udphdr *udp = (struct udphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
        if (ntohs(udp->source) != 67 || ntohs(udp->dest) != 68) {
            continue;
        }

        DhcpHeader *dhcp = (DhcpHeader *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr));
        if (dhcp->op != 2) { // Boot Reply
            continue;
        }

        std::cout << "Received DHCP Offer" << std::endl;
        std::cout << "Your IP Address: " << inet_ntoa(*(struct in_addr *)&dhcp->yiaddr) << std::endl;
        break;
    }

    close(sockfd);
}



