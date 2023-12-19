#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <vector>

int clientSocket;

// Структура для заголовка IP пакета
struct IpHeader {
    uint8_t versionIHL;
    uint8_t dscpECN;
    uint16_t totalLength;
    uint16_t identification;
    uint16_t flagsFragmentOffset;
    uint8_t timeToLive;
    uint8_t protocol;
    uint16_t headerChecksum;
    uint32_t sourceIP;
    uint32_t destinationIP;
};

// Структура для заголовка TCP пакета
struct TcpHeader {
    u_short sourcePort;
    u_short destinationPort;
    u_int32_t sequenceNumber;
    u_int32_t acknowledgmentNumber;
    u_char th_offx2;
    u_char flags;
    u_short windowSize;
    u_short checksum;
    u_short urgentPointer;
};

struct ReceivedPacket {
    TcpHeader tcpHeader;
    u_char flags;
    int sourcePort;
};

std::vector<ReceivedPacket> receivedPackets;

// Функция отправки TCP пакета
void send_tcp_packet(
        uint16_t ipIdentification, uint8_t ipTimeToLive, uint16_t tcpWindowSize, int source_port, int dest_port, uint32_t tcpSequenceNumber, uint32_t tcpAcknowledgmentNumber,
        uint16_t flags, const char* data = nullptr, size_t dataLength = 0) {

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
    if (flags == 0x02) {
        std::cout << "Sending SYN to " << dest_port << std::endl;
        // Создание сокета
        clientSocket = socket(AF_INET, SOCK_STREAM, 0);
        // Установка соединения с сервером
        if (connect(clientSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
            perror("Error connecting to server");
            close(clientSocket);
            return;  // Добавьте return после вывода ошибки
        }
        return;
    }


    // Формирование IP заголовка
    IpHeader ipHeader;
    ipHeader.versionIHL = 0x45; // IPv4, Header Length (IHL) = 5
    ipHeader.dscpECN = 0;       // Default DSCP and ECN
    ipHeader.totalLength = htons(sizeof(IpHeader) + sizeof(TcpHeader) + dataLength);
    ipHeader.identification = htons(ipIdentification);
    ipHeader.flagsFragmentOffset = 0;     // No fragmentation
    ipHeader.timeToLive = ipTimeToLive;   // TTL
    ipHeader.protocol = IPPROTO_TCP;      // TCP Protocol
    ipHeader.destinationIP = inet_addr(ipAddress);

    // Формирование TCP заголовка
    TcpHeader tcpHeader;
    tcpHeader.sourcePort = htons(source_port);
    tcpHeader.destinationPort = htons(dest_port);
    tcpHeader.sequenceNumber = htonl(tcpSequenceNumber);
    tcpHeader.acknowledgmentNumber = htonl(tcpAcknowledgmentNumber);
    tcpHeader.flags = (sizeof(TcpHeader) / 4) << 4 | flags; // Data Offset and Flags
    tcpHeader.windowSize = htons(tcpWindowSize);
    tcpHeader.checksum = 0;              // Checksum (0 for autofill)
    tcpHeader.urgentPointer = 0;         // Urgent Pointer

    // Обработка флагов
    if (flags & 0x08) {
        // Обработка флага PSH (Push)
        data = "hello";
        std::cout << "Sending PSH to " << dest_port << std::endl;
        if (data != nullptr && dataLength > 0) {
            send(clientSocket, data, dataLength, 0);
        }
    }

    if (flags & 0x10) {
        // Обработка флага ACK (Acknowledgment)
        // Отправка подтверждения, если необходимо
        std::cout << "Sending ACK to " << dest_port << std::endl;
        send(clientSocket, &tcpHeader, sizeof(tcpHeader), 0);
    }

    if (flags & 0x04) {
        // Обработка флага RST (Reset)
        std::cout << "Sending RST to " << dest_port << std::endl;
        struct linger sl;
        bzero(&sl, sizeof(sl));
        sl.l_onoff = 1;
        sl.l_linger = 0;
        if (setsockopt(clientSocket, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl)) < 0)
            perror("setsockopt");
        close(clientSocket);
        return;
    }

    if (flags & 0x01) {
        // Обработка флага FIN (Finish)
        std::cout << "Sending FIN to " << dest_port << std::endl;
        // Закрытие сокета или отправка подтверждения, если необходимо
        close(clientSocket);
        return;
    }

    // Принятие TCP пакета после отправки
    TcpHeader receivedTcpHeader;
    recv(clientSocket, &receivedTcpHeader, sizeof(receivedTcpHeader), 0);

    // Сохранение информации о принятом пакете
    ReceivedPacket receivedPacket;
    receivedPacket.tcpHeader = receivedTcpHeader;
    receivedPacket.flags = receivedTcpHeader.flags;
    receivedPacket.sourcePort = ntohs(receivedTcpHeader.sourcePort);
    receivedPackets.push_back(receivedPacket);
    std::cout << "Add packet" << std::endl;
}

// Функция обработки TCP пакета
void listen_tcp_packet(int dest_port, u_char expectedFlags) {
    // Ищем пакет в векторе, соответствующий указанным параметрам
    auto it = receivedPackets.begin();
    while (it != receivedPackets.end()) {
        printf("Received flags: 0x%02x From port: %d (Expected: 0x%02x)\n", it->flags,it->sourcePort, expectedFlags);
        if (it->tcpHeader.destinationPort == dest_port && it->tcpHeader.flags == expectedFlags) {
            printf("Received packet with expected flags: 0x%02x from source port: %d\n", expectedFlags, it->sourcePort);
            it = receivedPackets.erase(it);
            return;
        } else {
            ++it;
        }
    }
    printf("No packet with expected flags: 0x%02x found\n", expectedFlags);

}int main() {
	send_tcp_packet(21168, 128, 61690, 49674,  1, 349829,00, 0x02 );
	listen_tcp_packet(49674, 0x14);
	send_tcp_packet(21424, 128, 61690, 49675,  2, 414489,00, 0x02 );
	listen_tcp_packet(49675, 0x14);
	send_tcp_packet(21680, 128, 61690, 49676,  3, 414066,00, 0x02 );
	listen_tcp_packet(49676, 0x14);
	send_tcp_packet(21936, 128, 61690, 49677,  4, 37513,00, 0x02 );
	listen_tcp_packet(49677, 0x14);
	send_tcp_packet(22192, 128, 61690, 49678,  5, 202592,00, 0x02 );
	listen_tcp_packet(49678, 0x14);
	send_tcp_packet(22448, 128, 61690, 49679,  6, 365607,00, 0x02 );
	listen_tcp_packet(49679, 0x14);
	send_tcp_packet(22704, 128, 61690, 49680,  7, 156420,00, 0x02 );
	listen_tcp_packet(49680, 0x12);
	send_tcp_packet(22960, 128, 61690, 49681,  8, 22147,00, 0x02 );
	send_tcp_packet(23216, 128, 61690, 49682,  9, 350568,00, 0x02 );
	send_tcp_packet(23472, 128, 61690, 49684, 10, 196613,00, 0x02 );
	listen_tcp_packet(49681, 0x14);
	listen_tcp_packet(49682, 0x12);
	listen_tcp_packet(49684, 0x14);
	send_tcp_packet(23728, 128, 61690, 49685, 11, 332551,00, 0x02 );
	send_tcp_packet(23984, 128, 61690, 49686, 12, 393815,00, 0x02 );
	send_tcp_packet(24240, 128, 516, 49680,  7, 156420,50458, 0x10 );
	listen_tcp_packet(49685, 0x14);
	listen_tcp_packet(49686, 0x14);
	send_tcp_packet(24496, 128, 61690, 49687, 13, 276838,00, 0x02 );
	send_tcp_packet(24752, 128, 516, 49682,  9, 350568,24415, 0x10 );
	listen_tcp_packet(49687, 0x12);
	send_tcp_packet(25008, 128, 61690, 49688, 14, 94320,00, 0x02 );
	listen_tcp_packet(49688, 0x14);
	send_tcp_packet(25264, 128, 516, 49687, 13, 276838,29230, 0x10 );
	send_tcp_packet(25520, 128, 61690, 49689, 15, 401561,00, 0x02 );
	listen_tcp_packet(49689, 0x14);
	send_tcp_packet(25776, 128, 61690, 49690, 16, 156050,00, 0x02 );
	listen_tcp_packet(49690, 0x14);
	send_tcp_packet(26032, 128, 61690, 49691, 17, 208960,00, 0x02 );
	listen_tcp_packet(49691, 0x12);
	send_tcp_packet(26288, 128, 61690, 49692, 18, 131168,00, 0x02 );
	listen_tcp_packet(49692, 0x14);
	send_tcp_packet(26544, 128, 516, 49691, 17, 208960,14721, 0x10 );
	send_tcp_packet(26800, 128, 61690, 49693, 19, 397589,00, 0x02 );
	listen_tcp_packet(49693, 0x12);
	send_tcp_packet(27056, 128, 61690, 49694, 20, 1289,00, 0x02 );
	listen_tcp_packet(49694, 0x14);
}