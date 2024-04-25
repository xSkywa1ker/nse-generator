#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <vector>

int clientSocket;

// Структура для заголовка UDP пакета
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

// Функция отправки UDP пакета
void send_udp_packet(int source_port, int dest_port,  size_t dataLength, const char* data) {
    struct sockaddr_in serverAddress;
    memset(&serverAddress, 0, sizeof(serverAddress));
    const char* ipAddress = "192.168.3.10";

    if (clientSocket < 0) {
        perror("Error creating socket");
        return;
    }

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(dest_port);
    serverAddress.sin_addr.s_addr = inet_addr(ipAddress);

    clientSocket = socket(AF_INET, SOCK_DGRAM, 0);

    sendto(clientSocket, data, dataLength, 0, (struct sockaddr*)&serverAddress, sizeof(serverAddress));
}

// Функция принятия UDP пакета
void receive_udp_packet(int listen_port) {
    struct sockaddr_in clientAddress;
    socklen_t addrLen = sizeof(clientAddress);
    char buffer[1024]; // Буфер для приёма данных

    // Создание сокета
    int serverSocket = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in serverAddress;
    memset(&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddress.sin_port = htons(listen_port);

    // Привязка сокета к адресу
    bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress));

    // Получение данных
    recvfrom(serverSocket, buffer, sizeof(buffer), 0, (struct sockaddr*)&clientAddress, &addrLen);

    // Обработка полученных данных
    ReceivedPacket receivedPacket;
    receivedPacket.sourcePort = ntohs(clientAddress.sin_port);
    receivedPackets.push_back(receivedPacket);

}
