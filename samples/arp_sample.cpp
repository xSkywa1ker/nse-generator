#include <iostream>
#include <vector>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>  // Include this for ARP constants

#define MAX_PACKETS 100

struct ArpHeader {
    u_short hardwareType;
    u_short protocolType;
    u_char hardwareSize;
    u_char protocolSize;
    u_short opcode;
    u_char senderMAC[6];
    u_char senderIP[4];
    u_char targetMAC[6];
    u_char targetIP[4];
};

struct EthernetHeader {
    u_char destinationMAC[6];
    u_char sourceMAC[6];
    u_short etherType;
};

struct ReceivedArpPacket {
    EthernetHeader ethHeader;
    ArpHeader arpHeader;
};

std::vector<ReceivedArpPacket> receivedArpPackets;

void process_received_arp_packets() {
    if (receivedArpPackets.empty()) {
        std::cout << "No ARP packets received." << std::endl;
        return;
    }

    // Process ARP packets in the array
    for (const auto& receivedArpPacket : receivedArpPackets) {
        std::cout << "ARP Response Received:" << std::endl;
        std::cout << "Sender MAC: ";
        for (int i = 0; i < 6; ++i) {
            printf("%02X ", receivedArpPacket.arpHeader.senderMAC[i]);
        }
        std::cout << std::endl;

        std::cout << "Sender IP: ";
        for (int i = 0; i < 4; ++i) {
            std::cout << (int)receivedArpPacket.arpHeader.senderIP[i];
            if (i < 3) std::cout << ".";
        }
        std::cout << std::endl;
    }
}

void send_and_receive_arp_packet(
        const char* source_mac, const char* source_ip,
        const char* target_mac, const char* target_ip,
        const char* interface, u_short opcode,
        u_short hardwareType, u_short protocolType,
        u_char hardwareSize, u_char protocolSize
) {
    // Create a raw socket
    int clientSocket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (clientSocket < 0) {
        perror("Error creating socket");
        return;
    }

    // Get the interface index
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
    if (ioctl(clientSocket, SIOCGIFINDEX, &ifr) < 0) {
        perror("Error getting interface index");
        close(clientSocket);
        return;
    }
    int ifindex = ifr.ifr_ifindex;

    // Construct Ethernet header
    EthernetHeader ethHeader;
    sscanf(source_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &ethHeader.sourceMAC[0], &ethHeader.sourceMAC[1], &ethHeader.sourceMAC[2],
           &ethHeader.sourceMAC[3], &ethHeader.sourceMAC[4], &ethHeader.sourceMAC[5]);
    sscanf(target_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &ethHeader.destinationMAC[0], &ethHeader.destinationMAC[1], &ethHeader.destinationMAC[2],
           &ethHeader.destinationMAC[3], &ethHeader.destinationMAC[4], &ethHeader.destinationMAC[5]);
    ethHeader.etherType = htons(ETH_P_ARP);

    // Construct ARP header
    ArpHeader arpHeader;
    arpHeader.hardwareType = htons(hardwareType);
    arpHeader.protocolType = htons(protocolType);
    arpHeader.hardwareSize = hardwareSize;
    arpHeader.protocolSize = protocolSize;
    arpHeader.opcode = htons(opcode);
    memcpy(arpHeader.senderMAC, ethHeader.sourceMAC, 6);
    inet_pton(AF_INET, source_ip, arpHeader.senderIP);
    memcpy(arpHeader.targetMAC, ethHeader.destinationMAC, 6);
    inet_pton(AF_INET, target_ip, arpHeader.targetIP);

    // Combine Ethernet and ARP headers
    char packet[sizeof(EthernetHeader) + sizeof(ArpHeader)];
    memcpy(packet, &ethHeader, sizeof(EthernetHeader));
    memcpy(packet + sizeof(EthernetHeader), &arpHeader, sizeof(ArpHeader));

    // Set up the sockaddr_ll structure
    struct sockaddr_ll addr = {};
    addr.sll_ifindex = ifindex;
    addr.sll_halen = ETH_ALEN;
    memcpy(addr.sll_addr, ethHeader.destinationMAC, ETH_ALEN);

    // Send the packet
    if (sendto(clientSocket, packet, sizeof(packet), 0, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Error sending packet");
        close(clientSocket);
        return;
    }

    // Receive packets
    char receivedBuffer[1024];
    while (receivedArpPackets.size() < MAX_PACKETS) {
        int bytesReceived = recvfrom(clientSocket, receivedBuffer, sizeof(receivedBuffer), 0, NULL, NULL);
        if (bytesReceived > 0) {
            EthernetHeader* receivedEthHeader = (EthernetHeader*)receivedBuffer;
            if (ntohs(receivedEthHeader->etherType) == ETH_P_ARP) {
                ArpHeader* receivedArpHeader = (ArpHeader*)(receivedBuffer + sizeof(EthernetHeader));
                if (ntohs(receivedArpHeader->opcode) == ARPOP_REPLY) {
                    ReceivedArpPacket receivedArpPacket;
                    memcpy(&receivedArpPacket.ethHeader, receivedEthHeader, sizeof(EthernetHeader));
                    memcpy(&receivedArpPacket.arpHeader, receivedArpHeader, sizeof(ArpHeader));
                    receivedArpPackets.push_back(receivedArpPacket);
                }
            }
        }
    }

    close(clientSocket);
}

int main() {
    const char* source_mac = "00:0c:29:95:c3:64";
    const char* source_ip = "192.168.91.133";
    const char* target_mac = "FF:FF:FF:FF:FF:FF";
    const char* target_ip = "192.168.91.135";
    const char* interface = "ens33";
    u_short opcode = ARPOP_REQUEST;
    u_short hardwareType = ARPHRD_ETHER;
    u_short protocolType = ETH_P_IP;
    u_char hardwareSize = 6;
    u_char protocolSize = 4;

    send_and_receive_arp_packet(source_mac, source_ip, target_mac, target_ip, interface, opcode, hardwareType, protocolType, hardwareSize, protocolSize);
    process_received_arp_packets();

    return 0;
}
