#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <vector>

int clientSocket;

// Структура для заголовка ICMP пакета
struct IcmpHeader {
    uint8_t type;           // Тип сообщения ICMP
    uint8_t code;           // Код сообщения ICMP
    uint16_t checksum;      // Контрольная сумма
    uint16_t identifier;    // Идентификатор
    uint16_t sequenceNumber;// Порядковый номер
    // Данные ICMP пакета (можно добавить по желанию)
};

struct ReceivedPacket {
    IcmpHeader icmpHeader;
    int sourcePort;
};

std::vector<ReceivedPacket> receivedPackets;

// Функция отправки ICMP пакета
void send_icmp_packet(const char* dest_ip) {
    struct sockaddr_in serverAddress;
    memset(&serverAddress, 0, sizeof(serverAddress));

    if (clientSocket < 0) {
        perror("Error creating socket");
        return;
    }

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(0); // Произвольный порт

    // Создание сокета
    clientSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    // Формирование ICMP пакета
    IcmpHeader icmpPacket;
    // Заполнение icmpPacket данными

    // Отправка ICMP пакета
    sendto(clientSocket, &icmpPacket, sizeof(icmpPacket), 0, (struct sockaddr*)&serverAddress, sizeof(serverAddress));
}

// Функция принятия ICMP пакета
void receive_icmp_packet() {
    struct sockaddr_in clientAddress;
    socklen_t addrLen = sizeof(clientAddress);
    char buffer[1024]; // Буфер для приёма данных

    // Создание сокета
    int serverSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    // Получение данных
    recvfrom(serverSocket, buffer, sizeof(buffer), 0, (struct sockaddr*)&clientAddress, &addrLen);

    // Обработка полученных данных
    ReceivedPacket receivedPacket;
    // Заполнение receivedPacket данными из буфера, если необходимо

    receivedPackets.push_back(receivedPacket);
    // Дополнительная обработка полученных данных, если необходимо
}

