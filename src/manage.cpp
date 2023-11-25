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
    std::ifstream input(outputFile);
    std::ofstream output(outputFile + "_temp");

    if (!input || !output) {
        std::cerr << "Не удалось открыть файл для чтения или записи\n";
        return;
    }

    std::string line;
    size_t pos;  // Позиция знака равно

    while (std::getline(input, line)) {
        // Ищем строки, в которых нужно заполнить поля
        if ((pos = line.find("dest_mac")) != std::string::npos) {
            pos = line.find('=');
            output << line.substr(0, pos + 1) << " {";
            for (int i = 0; i < ETH_ALEN; ++i) {
                output << static_cast<int>(tcpPacket.ethernet_header.dest_mac[i]);
                if (i < ETH_ALEN - 1) output << ", ";
            }
            output << "};\n";
        } else if ((pos = line.find("src_mac")) != std::string::npos) {
            pos = line.find('=');
            output << line.substr(0, pos + 1) << " {";
            for (int i = 0; i < ETH_ALEN; ++i) {
                output << static_cast<int>(tcpPacket.ethernet_header.src_mac[i]);
                if (i < ETH_ALEN - 1) output << ", ";
            }
            output << "};\n";
        } else if ((pos = line.find("ethertype")) != std::string::npos) {
            pos = line.find("( ");
            output  << line.substr(0, pos + 1) << static_cast<int>(tcpPacket.ethernet_header.ethertype);
            output << line.substr(pos + 1, pos + 2);
            output << ";\n";
            } else if ((pos = line.find("version_ihl")) != std::string::npos) {
            pos = line.find('=');
            output << line.substr(0, pos + 1) << static_cast<int>(tcpPacket.ip_header.version_ihl);
            output << line.substr(pos + 1, pos + 2);
            output << ";\n";
        } else if ((pos = line.find("tos")) != std::string::npos) {
            pos = line.find('=');
            output << line.substr(0, pos + 1) << static_cast<int>(tcpPacket.ip_header.tos);
            output << line.substr(pos + 1, pos + 2);
            output << ";\n";
        } else if ((pos = line.find("tot_len")) != std::string::npos) {
            pos = line.find('=');
            output << line.substr(0, pos + 1) << static_cast<int>(tcpPacket.ip_header.tot_len);
            output << line.substr(pos + 1, pos + 2);
            output << ";\n";
        } else if ((pos = line.find("id")) != std::string::npos) {
            pos = line.find('=');
            output << line.substr(0, pos + 1) << static_cast<int>(tcpPacket.ip_header.id);
            output << line.substr(pos + 1, pos + 2);
            output << ";\n";
        } else if ((pos = line.find("frag_off")) != std::string::npos) {
            pos = line.find('=');
            output << line.substr(0, pos + 1) << static_cast<int>(tcpPacket.ip_header.frag_off);
            output << line.substr(pos + 1, pos + 2);
            output << ";\n";
        } else if ((pos = line.find("ttl")) != std::string::npos) {
            pos = line.find('=');
            output << line.substr(0, pos + 1) << static_cast<int>(tcpPacket.ip_header.ttl);
            output << line.substr(pos + 1, pos + 2);
            output << ";\n";
        } else if ((pos = line.find("protocol")) != std::string::npos) {
            pos = line.find('=');
            output << line.substr(0, pos + 1) << static_cast<int>(tcpPacket.ip_header.protocol);
            output << line.substr(pos + 1, pos + 2);
            output << ";\n";
        } else if ((pos = line.find("check")) != std::string::npos) {
            pos = line.find('=');
            output << line.substr(0, pos + 1) << static_cast<int>(tcpPacket.ip_header.check);
            output << line.substr(pos + 1, pos + 2);
            output << ";\n";
        } else if ((pos = line.find("saddr")) != std::string::npos) {
            pos = line.find('=');
            output << line.substr(0, pos + 1) << " { .s_addr = " << tcpPacket.ip_header.saddr.s_addr << " };\n";
        } else if ((pos = line.find("daddr")) != std::string::npos) {
            pos = line.find('=');
            output << line.substr(0, pos + 1) << " { .s_addr = " << tcpPacket.ip_header.daddr.s_addr << " };\n";
        } else if ((pos = line.find("source")) != std::string::npos) {
            pos = line.find('=');
            output << line.substr(0, pos + 1) << static_cast<int>(tcpPacket.tcp_header.source);
            output << line.substr(pos + 1, pos + 2);
            output << ";\n";
        } else if ((pos = line.find("dest")) != std::string::npos) {
            pos = line.find('=');
            output << line.substr(0, pos + 1) << static_cast<int>(tcpPacket.tcp_header.dest);
            output << line.substr(pos + 1, pos + 2);
            output << ";\n";
        } else if ((pos = line.find("seq")) != std::string::npos) {
            pos = line.find('=');
            output << line.substr(0, pos + 1) << static_cast<int>(tcpPacket.tcp_header.seq);
            output << line.substr(pos + 1, pos + 2);
            output << ";\n";
        } else if ((pos = line.find("ack_seq")) != std::string::npos) {
            pos = line.find('=');
            output << line.substr(0, pos + 1) << static_cast<int>(tcpPacket.tcp_header.ack_seq);
            output << line.substr(pos + 1, pos + 2);
            output << ";\n";
        } else if ((pos = line.find("doff_reserved")) != std::string::npos) {
            pos = line.find('=');
            output << line.substr(0, pos + 1) << static_cast<int>(tcpPacket.tcp_header.doff_reserved);
            output << line.substr(pos + 1, pos + 2);
            output << ";\n";
        } else if ((pos = line.find("flags")) != std::string::npos) {
            pos = line.find('=');
            output << line.substr(0, pos + 1) << static_cast<int>(tcpPacket.tcp_header.flags);
            output << line.substr(pos + 1, pos + 2);
            output << ";\n";
        } else if ((pos = line.find("window")) != std::string::npos) {
            pos = line.find('=');
            output << line.substr(0, pos + 1) << static_cast<int>(tcpPacket.tcp_header.window);
            output << line.substr(pos + 1, pos + 2);
            output << ";\n";
        } else if ((pos = line.find("check")) != std::string::npos) {
            pos = line.find('=');
            output << line.substr(0, pos + 1) << static_cast<int>(tcpPacket.tcp_header.check);
            output << line.substr(pos + 1, pos + 2);
            output << ";\n";
        } else if ((pos = line.find("urg_ptr")) != std::string::npos) {
            pos = line.find('=');
            output << line.substr(0, pos + 1) << static_cast<int>(tcpPacket.tcp_header.urg_ptr);
            output << line.substr(pos + 1, pos + 2);
            output << ";\n";
        } else if ((pos = line.find("payload_size")) != std::string::npos) {
            pos = line.find('=');
            output << line.substr(0, pos + 1) << tcpPacket.payload_size;
            output << line.substr(pos + 1, pos + 2);
            output << ";\n";
        }
            // Добавьте аналогичные блоки для других полей

        else {
            output << line << '\n';
        }
    }

    input.close();
    output.close();

    std::remove(outputFile.c_str());
    std::rename((outputFile + "_temp").c_str(), outputFile.c_str());
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