#include <iostream>
#include <vector>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>

#define MAX_PACKETS 100

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

unsigned short calculate_checksum(const char* data, size_t length) {
    unsigned long sum = 0;
    while (length > 1) {
        sum += *((unsigned short*)data);
        data += 2;
        length -= 2;
    }
    if (length > 0) {
        sum += *((unsigned char*)data);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum = ~sum;
    return (unsigned short)sum;
}

void send_and_receive_udp_packet(int source_port, int dest_port, const char* source_ip, const char* dest_ip, size_t dataLength, const char* data) {
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

    // Отправка UDP пакета
    UdpHeader udpHeader;
    udpHeader.sourcePort = htons(source_port);
    udpHeader.destinationPort = htons(dest_port);
    udpHeader.length = htons(sizeof(UdpHeader) + dataLength);
    udpHeader.checksum = 0; // Здесь будет вычислено значение контрольной суммы позже

    // Создание буфера для UDP пакета
    char buffer[sizeof(UdpHeader) + dataLength];
    memcpy(buffer, &udpHeader, sizeof(UdpHeader));
    memcpy(buffer + sizeof(UdpHeader), data, dataLength);

    // Вычисление контрольной суммы и установка в заголовок
    udpHeader.checksum = calculate_checksum(buffer, sizeof(UdpHeader) + dataLength);
    memcpy(buffer, &udpHeader, sizeof(UdpHeader)); // Обновляем заголовок с правильной контрольной суммой

    // Отправка пакета
    struct sockaddr_in destAddress;
    memset(&destAddress, 0, sizeof(destAddress));
    destAddress.sin_family = AF_INET;
    destAddress.sin_addr.s_addr = inet_addr(dest_ip);

    sendto(clientSocket, buffer, sizeof(buffer), 0, (struct sockaddr*)&destAddress, sizeof(destAddress));

    // Получение UDP пакетов
    struct sockaddr_in clientAddress;
    socklen_t addrLen = sizeof(clientAddress);
    char receivedBuffer[1024]; // Буфер для приема данных

    // Получение данных
    int bytesReceived = recvfrom(clientSocket, receivedBuffer, sizeof(receivedBuffer), 0, (struct sockaddr*)&clientAddress, &addrLen);
    if (bytesReceived > 0) {
        // Обработка полученных данных
        ReceivedPacket receivedPacket;
        memcpy(&receivedPacket.udpHeader, receivedBuffer, sizeof(UdpHeader));
        receivedPacket.sourcePort = ntohs(clientAddress.sin_port);
        receivedPackets.push_back(receivedPacket);
    }

    // Закрытие сокета
    close(clientSocket);
}

void receive_udp_packet() {
    if (receivedPackets.empty()) {
        std::cout << "No UDP packets received." << std::endl;
        return;
    }

    // Вывод полей первого пакета из массива
    ReceivedPacket& receivedPacket = receivedPackets[0];
    std::cout << "Source Port: " << ntohs(receivedPacket.sourcePort) << std::endl;
    std::cout << "Destination Port: " << ntohs(receivedPacket.udpHeader.destinationPort) << std::endl;
    std::cout << "Length: " << ntohs(receivedPacket.udpHeader.length) << std::endl;
    std::cout << "Checksum: " << ntohs(receivedPacket.udpHeader.checksum) << std::endl;
}

int main() {
    const char* data = "Hello, UDP!";
    const int source_port = 12345; // Замените на нужный порт
    const int dest_port = 54321; // Замените на нужный порт
    const char* source_ip = "127.0.0.1"; // Замените на нужный IP адрес
    const char* dest_ip = "127.0.0.1"; // Замените на нужный IP адрес

    // Отправка и получение UDP пакетов
    send_and_receive_udp_packet(source_port, dest_port, source_ip, dest_ip, strlen(data), data);
    receive_udp_packet();

    return 0;
}
