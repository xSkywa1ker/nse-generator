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

#define MAX_PACKETS 100

// Структура для DHCP заголовка
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
    u_char options[312];  // Extended for options
};

// Структура для DHCP опции
struct DhcpOption {
    u_char code;
    u_char length;
    u_char data[256];
};

// Структура для полученного DHCP пакета
struct ReceivedDhcpPacket {
    DhcpHeader dhcpHeader;
    std::vector<DhcpOption> options;
};

std::vector<ReceivedDhcpPacket> receivedDhcpPackets; // This needs to be declared globally or appropriately passed around if used locally

// Function to calculate checksum (This is a simplistic and may not be entirely accurate for all use cases)
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

void send_dhcp_packet(const char* interface, const char* client_mac, u_int32_t transaction_id, u_int32_t server_ip, u_int32_t requested_ip) {
    int clientSocket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (clientSocket < 0) {
        perror("Error creating socket");
        return;
    }

    DhcpHeader dhcpHeader = {1, 1, 6, 0, htonl(transaction_id), 0, 0, 0, 0, 0, 0, 0, {}, {}, {}, {}};
    memcpy(dhcpHeader.chaddr, client_mac, 6);

    int option_index = 0;
    dhcpHeader.options[option_index++] = 53; // Message type
    dhcpHeader.options[option_index++] = 1;
    dhcpHeader.options[option_index++] = 3; // DHCP Request
    dhcpHeader.options[option_index++] = 50; // Request IP
    dhcpHeader.options[option_index++] = 4;
    memcpy(&dhcpHeader.options[option_index], &requested_ip, 4);
    option_index += 4;
    dhcpHeader.options[option_index++] = 54; // Server ID
    dhcpHeader.options[option_index++] = 4;
    memcpy(&dhcpHeader.options[option_index], &server_ip, 4);
    option_index += 4;
    dhcpHeader.options[option_index] = 255; // End

    uint8_t buffer[1500] = {0};
    struct ethhdr *eth = (struct ethhdr *)buffer;
    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    struct udphdr *udp = (struct udphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
    uint8_t *dhcp = buffer + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

    memset(eth->h_dest, 0xff, 6);
    memcpy(eth->h_source, client_mac, 6);
    eth->h_proto = htons(ETH_P_IP);

    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(DhcpHeader) + option_index - 312); // Adjusted total length
    ip->id = 0;
    ip->ttl = 255;
    ip->protocol = IPPROTO_UDP;
    ip->saddr = 0;
    ip->daddr = inet_addr("255.255.255.255");
    ip->check = checksum((uint16_t *)ip, ip->ihl * 2);

    udp->source = htons(68);
    udp->dest = htons(67);
    udp->len = htons(sizeof(struct udphdr) + sizeof(DhcpHeader) + option_index - 312); // Correct length
    udp->check = 0; // This is typically not computed and left as zero

    memcpy(dhcp, &dhcpHeader, sizeof(DhcpHeader) + option_index - 312); // Adjusted copy

    struct sockaddr_ll addr = {0};
    addr.sll_ifindex = if_nametoindex(interface);
    addr.sll_halen = ETH_ALEN;
    memset(addr.sll_addr, 0xff, 6);

    int sentBytes = sendto(clientSocket, buffer, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(DhcpHeader) + option_index - 312, 0, (struct sockaddr *)&addr, sizeof(addr));
    if (sentBytes < 0) {
        perror("Error sending packet");
    } else {
        std::cout << "Packet sent successfully, bytes: " << sentBytes << std::endl;
    }

    close(clientSocket);
}

int main() {
    const char* interface = "ens33";
    const char* client_mac = "\x00\x11\x22\x33\x44\x55";
    u_int32_t transaction_id = 123456;
    u_int32_t server_ip = inet_addr("192.168.91.1");
    u_int32_t requested_ip = inet_addr("192.168.91.138");

    send_dhcp_packet(interface, client_mac, transaction_id, server_ip, requested_ip);

    return 0;
}
