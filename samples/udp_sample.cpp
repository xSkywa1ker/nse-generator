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

void send_udp_packet(int source_port, int dest_port, const char* source_ip, const char* dest_ip, size_t dataLength, const char* data) {
    // Создание сокета
    int clientSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (clientSocket < 0) {
        perror("Error creating socket");
        return;
    }

    // Заполнение структуры с информацией об адресе сервера
    struct sockaddr_in serverAddress;
    memset(&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(dest_port);
    serverAddress.sin_addr.s_addr = inet_addr(dest_ip);

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

    if (sendto(clientSocket, buffer, sizeof(buffer), 0, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) == -1) {
        perror("Error sending packet");
        close(clientSocket);
        return;
    }

    std::cout << "UDP packet sent to " << dest_ip << ":" << dest_port << std::endl;

    close(clientSocket);
}

void receive_udp_packet(int listen_port, u_short expectedSourcePort, u_short expectedDestPort, u_short expectedLength, u_short expectedChecksum) {
    // Создание сокета
    int serverSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (serverSocket < 0) {
        perror("Error creating socket");
        return;
    }

    struct sockaddr_in serverAddress;
    memset(&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(listen_port);

    if (bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        perror("Error binding socket");
        close(serverSocket);
        return;
    }

    struct sockaddr_in clientAddress;
    socklen_t addrLen = sizeof(clientAddress);
    char receivedBuffer[1024];

    int bytesReceived = recvfrom(serverSocket, receivedBuffer, sizeof(receivedBuffer), 0, (struct sockaddr*)&clientAddress, &addrLen);
    if (bytesReceived > 0) {
        ReceivedPacket receivedPacket;
        memcpy(&receivedPacket.udpHeader, receivedBuffer, sizeof(UdpHeader));
        receivedPacket.sourcePort = ntohs(clientAddress.sin_port);
        receivedPackets.push_back(receivedPacket);

        std::cout << "UDP packet received from " << inet_ntoa(clientAddress.sin_addr) << ":" << ntohs(clientAddress.sin_port) << std::endl;

        if (receivedPacket.udpHeader.sourcePort == expectedSourcePort &&
            receivedPacket.udpHeader.destinationPort == expectedDestPort &&
            receivedPacket.udpHeader.length == expectedLength &&
            receivedPacket.udpHeader.checksum == expectedChecksum) {

            std::cout << "Matching packet found:" << std::endl;
            std::cout << "Source Port: " << ntohs(receivedPacket.udpHeader.sourcePort) << std::endl;
            std::cout << "Destination Port: " << ntohs(receivedPacket.udpHeader.destinationPort) << std::endl;
            std::cout << "Length: " << ntohs(receivedPacket.udpHeader.length) << std::endl;
            std::cout << "Checksum: " << ntohs(receivedPacket.udpHeader.checksum) << std::endl;

            receivedPackets.erase(receivedPackets.begin());
        } else {
            std::cout << "No matching packet found." << std::endl;
        }
    } else {
        perror("Error receiving packet");
    }

    close(serverSocket);
}

//int main() {
//    const char* data = "Hello, UDP!";
//    const int source_port = 64321;
//    const int dest_port = 64321;
//    const char* source_ip = "192.168.91.133";  // Использование локального IP для тестирования
//    const char* dest_ip = "192.168.91.135";    // Использование локального IP для тестирования
//
//    send_udp_packet(source_port, dest_port, source_ip, dest_ip, strlen(data), data);
//
//    // Expected values for receive_udp_packet
//    u_short expectedSourcePort = htons(source_port);
//    u_short expectedDestPort = htons(dest_port);
//    u_short expectedLength = htons(sizeof(UdpHeader) + strlen(data));
//    u_short expectedChecksum = calculate_checksum(data, strlen(data));
//
//    receive_udp_packet(dest_port, expectedSourcePort, expectedDestPort, expectedLength, expectedChecksum);
//
//    return 0;
//}
