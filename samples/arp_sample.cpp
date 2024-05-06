#include <iostream>
#include <vector>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if_arp.h>

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

struct ReceivedArpPacket {
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
            std::cout << (int)receivedArpPacket.arpHeader.senderIP[i] << ".";
        }
        std::cout << std::endl;
    }
}

void send_and_receive_arp_packet(const char* source_mac, const char* source_ip, const char* target_mac, const char* target_ip, const char* interface) {
    // Создание сокета
    int clientSocket = socket(AF_PACKET, SOCK_PACKET, htons(ETH_P_ARP));
    if (clientSocket < 0) {
        perror("Error creating socket");
        return;
    }

    ArpHeader arpHeader;
    arpHeader.hardwareType = htons(ARPHRD_ETHER);
    arpHeader.protocolType = htons(ETH_P_IP);
    arpHeader.hardwareSize = 6;
    arpHeader.protocolSize = 4;
    arpHeader.opcode = htons(ARPOP_REQUEST);

    sscanf(source_mac, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
           &arpHeader.senderMAC[0], &arpHeader.senderMAC[1], &arpHeader.senderMAC[2],
           &arpHeader.senderMAC[3], &arpHeader.senderMAC[4], &arpHeader.senderMAC[5]);
    inet_pton(AF_INET, source_ip, arpHeader.senderIP);

    sscanf(target_mac, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
           &arpHeader.targetMAC[0], &arpHeader.targetMAC[1], &arpHeader.targetMAC[2],
           &arpHeader.targetMAC[3], &arpHeader.targetMAC[4], &arpHeader.targetMAC[5]);
    inet_pton(AF_INET, target_ip, arpHeader.targetIP);

    struct sockaddr addr;
    memset(&addr, 0, sizeof(addr));
    strcpy(addr.sa_data, interface); // Укажите имя сетевого интерфейса, с которого отправляется пакет

    sendto(clientSocket, &arpHeader, sizeof(ArpHeader), 0, &addr, sizeof(addr));

    char receivedBuffer[1024];
    while (receivedArpPackets.size() < MAX_PACKETS) {
        int bytesReceived = recvfrom(clientSocket, receivedBuffer, sizeof(receivedBuffer), 0, NULL, NULL);
        if (bytesReceived > 0) {
            ReceivedArpPacket receivedArpPacket;
            memcpy(&receivedArpPacket.arpHeader, receivedBuffer, sizeof(ArpHeader));
            receivedArpPackets.push_back(receivedArpPacket);
        }
    }
    close(clientSocket);
}

int main() {
    const char* source_mac = "00:0c:29:95:c3:64";
    const char* source_ip = "192.168.22.136";
    const char* target_mac = "FF:FF:FF:FF:FF:FF";
    const char* target_ip = "192.168.22.137";
    const char* interface = "ens33";

    send_and_receive_arp_packet(source_mac, source_ip, target_mac, target_ip, interface);
    process_received_arp_packets();

    return 0;
}
