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
    std::cout  << "FLAG" << std::endl;
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
    std::cout  << "FLAG" << std::endl;
    char buffer[sizeof(UdpHeader) + dataLength];
    memcpy(buffer, &udpHeader, sizeof(UdpHeader));
    memcpy(buffer + sizeof(UdpHeader), data, dataLength);

    udpHeader.checksum = calculate_checksum(buffer, sizeof(UdpHeader) + dataLength);
    memcpy(buffer, &udpHeader, sizeof(UdpHeader));

    struct sockaddr_in destAddress;
    memset(&destAddress, 0, sizeof(destAddress));
    destAddress.sin_family = AF_INET;
    destAddress.sin_addr.s_addr = inet_addr(dest_ip);
    std::cout  << "FLAG" << std::endl;
    sendto(clientSocket, buffer, sizeof(buffer), 0, (struct sockaddr*)&destAddress, sizeof(destAddress));
    std::cout  << "FLAG1" << std::endl;

    struct sockaddr_in clientAddress;
    socklen_t addrLen = sizeof(clientAddress);
    char receivedBuffer[1024];

    int bytesReceived = recvfrom(clientSocket, receivedBuffer, sizeof(receivedBuffer), 0, (struct sockaddr*)&clientAddress, &addrLen);
    if (bytesReceived > 0) {
        ReceivedPacket receivedPacket;
        memcpy(&receivedPacket.udpHeader, receivedBuffer, sizeof(UdpHeader));
        receivedPacket.sourcePort = ntohs(clientAddress.sin_port);
        receivedPackets.push_back(receivedPacket);
    }
    close(clientSocket);
}

void receive_udp_packet(u_short expectedSourcePort, u_short expectedDestPort, u_short expectedLength, u_short expectedChecksum) {
    if (receivedPackets.empty()) {
        std::cout << "No UDP packets received." << std::endl;
        return;
    }

    bool packetFound = false;

    for (auto it = receivedPackets.begin(); it != receivedPackets.end(); ++it) {
        if (it->udpHeader.sourcePort == expectedSourcePort &&
            it->udpHeader.destinationPort == expectedDestPort &&
            it->udpHeader.length == expectedLength &&
            it->udpHeader.checksum == expectedChecksum) {

            std::cout << "Matching packet found:" << std::endl;
            std::cout << "Source Port: " << ntohs(it->sourcePort) << std::endl;
            std::cout << "Destination Port: " << ntohs(it->udpHeader.destinationPort) << std::endl;
            std::cout << "Length: " << ntohs(it->udpHeader.length) << std::endl;
            std::cout << "Checksum: " << ntohs(it->udpHeader.checksum) << std::endl;

            receivedPackets.erase(it);
            packetFound = true;
            break;
        }
    }

    if (!packetFound) {
        std::cout << "No matching packet found." << std::endl;
    }
}
//int main() {
//    const char* data = "Hello, UDP!";
//    const int source_port = 64321;
//    const int dest_port = 64321;
//    const char* source_ip = "192.168.22.136";
//    const char* dest_ip = "192.168.22.137";
//
//    send_and_receive_udp_packet(source_port, dest_port, source_ip, dest_ip, strlen(data), data);
//    receive_udp_packet();
//
//    return 0;
//}
