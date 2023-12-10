#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

int  clientSocket;

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
    uint16_t sourcePort;
    uint16_t destinationPort;
    uint32_t sequenceNumber;
    uint32_t acknowledgmentNumber;
    uint8_t flags;
    uint16_t windowSize;
    uint16_t checksum;
    uint16_t urgentPointer;
};

// Функция отправки TCP пакета
void send_tcp_packet(
        uint16_t ipIdentification,uint8_t ipTimeToLive,uint16_t tcpWindowSize, int source_port,int dest_port, uint32_t tcpSequenceNumber, uint32_t tcpAcknowledgmentNumber,
        uint8_t flags) {

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
        // Создание сокета
        clientSocket = socket(AF_INET, SOCK_STREAM, 0);
        // Установка соединения с сервером
        if (connect(clientSocket, (struct sockaddr *) &serverAddress, sizeof(serverAddress)) < 0) {
            perror("Error connecting to server");
            close(clientSocket);
            return;
        }
    }
    /* struct linger sl;
     bzero(&sl, sizeof(sl));
     sl.l_onoff = 1;
     sl.l_linger = 0;
     if (setsockopt(clientSocket, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl)) < 0)
         perror("setsockopt");*/
    if (flags == 0x14) {
        //Отправка RST
        close(clientSocket);
    }

    // Формирование IP заголовка
    IpHeader ipHeader;
    ipHeader.versionIHL = 0x45;  // IPv4, Header Length (IHL) = 5
    ipHeader.dscpECN = 0;       // Default DSCP and ECN
    ipHeader.totalLength = htons(sizeof(IpHeader) + sizeof(TcpHeader));
    ipHeader.identification = htons(ipIdentification);
    ipHeader.flagsFragmentOffset = 0;       // No fragmentation
    ipHeader.timeToLive = ipTimeToLive;     // TTL
    ipHeader.protocol = IPPROTO_TCP;        // TCP Protocol
    ipHeader.destinationIP = inet_addr(ipAddress);

    // Формирование TCP заголовка
    TcpHeader tcpHeader;
    tcpHeader.sourcePort = htons(source_port);
    tcpHeader.destinationPort = htons(dest_port);
    tcpHeader.sequenceNumber = htonl(tcpSequenceNumber);
    tcpHeader.acknowledgmentNumber = htonl(tcpAcknowledgmentNumber);
    tcpHeader.flags = (sizeof(TcpHeader) / 4) << 4 | flags;  // Data Offset and Flags
    tcpHeader.windowSize = htons(tcpWindowSize);
    tcpHeader.checksum = 0;              // Checksum (0 for autofill)
    tcpHeader.urgentPointer = 0;         // Urgent Pointer

    // Отправка IP заголовка
    send(clientSocket, &ipHeader, sizeof(ipHeader), 0);

    // Отправка TCP заголовка
    send(clientSocket, &tcpHeader, sizeof(tcpHeader), 0);
}

// Функция прослушивания сокета
void listen_tcp_packet( int dest_port, uint8_t expectedFlags) {
    const char* ipAddress = "192.168.3.10";
    struct sockaddr_in serverAddress;
    memset(&serverAddress, 0, sizeof(serverAddress));
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(dest_port);
    serverAddress.sin_addr.s_addr = inet_addr(ipAddress);

    // Прием TCP пакета
    TcpHeader receivedTcpHeader;
    recv(clientSocket, &receivedTcpHeader, sizeof(receivedTcpHeader), 0);

    // Сравнение полей с ожидаемыми
    if (receivedTcpHeader.flags == expectedFlags) {
        std::cout << "Received packet with expected flags: " << receivedTcpHeader.flags << std::endl;
    } else {
        std::cout << "Received packet with unexpected flags: " << receivedTcpHeader.flags << " Expected: " << expectedFlags << std::endl;
    }

    // Закрытие сокета после приема пакета
    //close(clientSocket);
}
int main() {
	send_tcp_packet(19910, 128, 61690, 52900, 139, 276054,00, 02 );
	listen_tcp_packet(52900, 18);
	send_tcp_packet(20166, 128, 5152, 52900, 139, 276054,14148, 16 );
	send_tcp_packet(24262, 128, 00, 52900, 139, 276054,14148, 20 );
}