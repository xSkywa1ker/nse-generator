#include <iostream>
#include <vector>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>

#define MAX_PACKETS 100

struct UdpHeader {
    u_short sourcePort;
    u_short destinationPort;
    u_short length;
    u_short checksum;
};

struct ReceivedPacket {
    UdpHeader udpHeader;
    int sourcePort;
};

std::vector<ReceivedPacket> receivedPackets;

unsigned short calculate_checksum(const char* data, size_t length) {
    unsigned long sum = 0;
    const unsigned short* ptr = (const unsigned short*)data;
    while (length > 1) {
        sum += *ptr++;
        length -= 2;
    }
    if (length > 0) {
        sum += *((unsigned char*)ptr);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~sum;
}

void send_and_receive_udp_packet(int source_port, int dest_port, const char* source_ip, const char* dest_ip, size_t dataLength, const char* data) {
    // Создание сокета
    int clientSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (clientSocket < 0) {
        perror("Error creating socket");
        return;
    }

    UdpHeader udpHeader;
    udpHeader.sourcePort = htons(source_port);
    udpHeader.destinationPort = htons(dest_port);
    udpHeader.length = htons(sizeof(UdpHeader) + dataLength);
    udpHeader.checksum = 0;

    char buffer[sizeof(UdpHeader) + dataLength];
    memcpy(buffer, &udpHeader, sizeof(UdpHeader));
    memcpy(buffer + sizeof(UdpHeader), data, dataLength);

    udpHeader.checksum = calculate_checksum(buffer, sizeof(UdpHeader) + dataLength);
    memcpy(buffer, &udpHeader, sizeof(UdpHeader));

    struct sockaddr_in destAddress;
    memset(&destAddress, 0, sizeof(destAddress));
    destAddress.sin_family = AF_INET;
    destAddress.sin_port = htons(dest_port);
    destAddress.sin_addr.s_addr = inet_addr(dest_ip);

    struct sockaddr_in localAddress;
    memset(&localAddress, 0, sizeof(localAddress));
    localAddress.sin_family = AF_INET;
    localAddress.sin_port = htons(source_port);
    localAddress.sin_addr.s_addr = inet_addr(source_ip);

    if (bind(clientSocket, (struct sockaddr*)&localAddress, sizeof(localAddress)) < 0) {
        perror("Error binding socket");
        close(clientSocket);
        return;
    }

    int bytesSent = sendto(clientSocket, buffer, sizeof(UdpHeader) + dataLength, 0, (struct sockaddr*)&destAddress, sizeof(destAddress));
    if (bytesSent < 0) {
        perror("Error sending packet");
        close(clientSocket);
        return;
    }

    struct sockaddr_in clientAddress;
    socklen_t addrLen = sizeof(clientAddress);
    char receivedBuffer[1024];

    fd_set readfds;
    struct timeval timeout;
    FD_ZERO(&readfds);
    FD_SET(clientSocket, &readfds);
    timeout.tv_sec = 5;  // 5 секунд ожидания
    timeout.tv_usec = 0;

    int selectResult = select(clientSocket + 1, &readfds, NULL, NULL, &timeout);
    if (selectResult > 0) {
        int bytesReceived = recvfrom(clientSocket, receivedBuffer, sizeof(receivedBuffer), 0, (struct sockaddr*)&clientAddress, &addrLen);
        if (bytesReceived < 0) {
            perror("Error receiving packet");
        } else {
            if (bytesReceived > 0) {
                ReceivedPacket receivedPacket;
                memcpy(&receivedPacket.udpHeader, receivedBuffer, sizeof(UdpHeader));
                receivedPacket.sourcePort = ntohs(clientAddress.sin_port);
                receivedPackets.push_back(receivedPacket);
            }
        }
    } else if (selectResult == 0) {
        std::cout << "Receive timeout." << std::endl;
    } else {
        perror("Error in select");
    }

    close(clientSocket);
}

void receive_udp_packet() {
    if (receivedPackets.empty()) {
        std::cout << "No UDP packets received." << std::endl;
        return;
    }
    ReceivedPacket& receivedPacket = receivedPackets[0];
    std::cout << "Source Port: " << ntohs(receivedPacket.sourcePort) << std::endl;
    std::cout << "Destination Port: " << ntohs(receivedPacket.udpHeader.destinationPort) << std::endl;
    std::cout << "Length: " << ntohs(receivedPacket.udpHeader.length) << std::endl;
    std::cout << "Checksum: " << ntohs(receivedPacket.udpHeader.checksum) << std::endl;
}

int main() {

    send_and_receive_udp_packet(65534, 7, "192.168.91.133", "192.168.91.136", 10, "Hello, UDP!");
    receive_udp_packet();
    return 0;
}
