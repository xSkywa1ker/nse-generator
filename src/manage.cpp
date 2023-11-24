#include <iostream>
#include <fstream>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

struct EthernetHeader {
    uint8_t dest_mac[ETH_ALEN];
    uint8_t src_mac[ETH_ALEN];
    uint16_t ethertype;
};

struct IPHeader {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    in_addr saddr;
    in_addr daddr;
};

struct TCPHeader {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t doff_reserved;
    uint8_t flags;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};

struct TCPPacket {
    EthernetHeader ethernet_header;
    IPHeader ip_header;
    TCPHeader tcp_header;
    const char *payload;
    size_t payload_size;
};

uint16_t pcap_in_cksum(unsigned short *addr, int len);

void fillFields(const TCPPacket& tcpPacket, const std::string& outputFile) {
    std::fstream output(outputFile, std::ios::in | std::ios::out); // Открываем файл для чтения и записи

    if (!output) {
        std::cerr << "Не удалось открыть файл tcp_result.cpp\n";
        return;
    }

    std::string line;
    std::streampos lastPos = 0;

    while (std::getline(output, line)) {
        lastPos = output.tellg();  // Запоминаем текущую позицию в файле

        // Ищем строки, в которых нужно заполнить поля
        if (line.find("{") != std::string::npos) {
            output.seekp(lastPos);  // Возвращаемся на последнюю позицию
            output << "{";
            for (int i = 0; i < ETH_ALEN; ++i) {
                output << static_cast<int>(tcpPacket.ethernet_header.dest_mac[i]);
                if (i < ETH_ALEN - 1) output << ", ";
            }
            output << "};\n";
        } else if (line.find("tcpPacket.ethernet_header.src_mac") != std::string::npos) {
            output.seekp(lastPos);  // Возвращаемся на последнюю позицию
            output << "    tcpPacket.ethernet_header.src_mac = {";
            for (int i = 0; i < ETH_ALEN; ++i) {
                output << static_cast<int>(tcpPacket.ethernet_header.src_mac[i]);
                if (i < ETH_ALEN - 1) output << ", ";
            }
            output << "};\n";
        }
        // Добавьте аналогичные блоки для других полей
    }

    output.close();
}

void fillPacket(TCPPacket& tcpPacket) {
    // Заполняем IP-заголовок
    tcpPacket.ip_header.tot_len = htons(sizeof(IPHeader) + sizeof(TCPHeader) + tcpPacket.payload_size);
    tcpPacket.ip_header.check = htons(pcap_in_cksum(reinterpret_cast<unsigned short *>(&tcpPacket.ip_header), sizeof(IPHeader)));

    // Заполняем TCP-заголовок
    tcpPacket.tcp_header.check = htons(pcap_in_cksum(reinterpret_cast<unsigned short *>(&tcpPacket.tcp_header), sizeof(TCPHeader) + tcpPacket.payload_size));
}

void manager(const u_char *receivedPacket) {
    TCPPacket tcpPacket;
    std::memcpy(&tcpPacket, receivedPacket, sizeof(TCPPacket));

    // Копируем содержимое tcp_sample.cpp в tcp_result.cpp
    std::ifstream inputTemplate("src/tcp_sample.cpp");
    std::ofstream outputResult("src/tcp_result.cpp");

    if (!inputTemplate || !outputResult) {
        std::cerr << "Не удалось открыть файлы tcp_sample.cpp или tcp_result.cpp\n";
        return;
    }

    outputResult << inputTemplate.rdbuf();

    inputTemplate.close();
    outputResult.close();
    // Заполняем пустые поля в файла tcp_result.cpp
    fillPacket(tcpPacket);
    fillFields(tcpPacket, "src/tcp_result.cpp");

    std::cout << "Программа успешно выполнена\n";
}

// Функция для вычисления контрольной суммы
uint16_t pcap_in_cksum(unsigned short *addr, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;

    return answer;
}