#include <iostream>
#include <fstream>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <iomanip>
#include <cmath>

#define MAX_PACKET_LIFETIME 120 // Максимальное время жизни пакета в секундах
#define MAX_PACKET_SIZE 65535   // Максимальная длина пакета
#define SIZE_ETHERNET 14
#define SIZE_TCP 20
#define SIZE_IP 20
#define SIZE_ICMP 8
#define SIZE_UDP 8

typedef struct ip_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
} ip_address;

typedef struct ethernet_header
{
    u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
    u_short ether_type;
} ethernet_header;

typedef struct ip_header
{
    u_char ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char tos;            // Type of service
    u_short tlen;          // Total length
    u_short identification; // Identification
    u_short flags_fo;      // Flags (3 bits) + Fragment offset (13 bits)
    u_char ttl;            // Time to live
    u_char proto;          // Protocol
    u_short crc;           // Header checksum
    ip_address saddr;      // Source address
    ip_address daddr;      // Destination address
} ip_header;

typedef u_int32_t tcp_seq;

typedef struct tcp_header
{
    u_short sport; // Source port
    u_short dport; // Destination port
    tcp_seq th_seq;
    tcp_seq th_ack;
    u_char th_offx2;
    u_char th_flags;
    u_short th_win; /* window */
    u_short th_sum; /* checksum */
    u_short th_urp; /* urgent pointer */
} tcp_header;

uint16_t pcap_in_cksum(unsigned short *addr, int len);
std::string getValue(const std::string &line, const ethernet_header &eth, const ip_header &iph, const tcp_header &th);
int HEX_TO_DEC(const std::string &st);

std::string var = "int main() {\n}";

void fillFields(const ethernet_header &eth, const ip_header &iph, const tcp_header &th, const std::string &outputFile)
{
    std::ofstream output(outputFile, std::ios_base::app);

    if (!output)
    {
        std::cerr << "Не удалось открыть файл для записи\n";
        return;
    }
    char appData[350];

    std::sprintf(appData, "\tsend_tcp_packet({0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x},{0x%02x, 0x%02x, "
                          "0x%02x, 0x%02x, 0x%02x, 0x%02x}, 0x%02x, %02x, %02x, %02x, "
                          "%02x, %02x, %d, %d,%02x, %02x, %d, %d, %02x, %02x, %02x, %02x);\n",
                 eth.ether_dhost[0], eth.ether_dhost[1], eth.ether_dhost[2], eth.ether_dhost[3],
                 eth.ether_dhost[4], eth.ether_dhost[5], eth.ether_shost[0], eth.ether_shost[1],
                 eth.ether_shost[2], eth.ether_shost[3], eth.ether_shost[4], eth.ether_shost[5],
                 eth.ether_type, HEX_TO_DEC(std::to_string(iph.ver_ihl)),
                 HEX_TO_DEC(std::to_string(iph.tos)), ntohs(iph.tlen), HEX_TO_DEC(std::to_string(iph.identification)),
                 HEX_TO_DEC(std::to_string(iph.flags_fo)), iph.ttl, iph.proto, HEX_TO_DEC(std::to_string(ntohs(th.sport))),
                 HEX_TO_DEC(std::to_string(ntohs(th.dport))), HEX_TO_DEC(std::to_string(ntohs(th.th_seq))),
                 HEX_TO_DEC(std::to_string(ntohs(th.th_ack))), HEX_TO_DEC(std::to_string(th.th_offx2)), HEX_TO_DEC(std::to_string(th.th_flags)),
                 HEX_TO_DEC(std::to_string(th.th_win)), HEX_TO_DEC(std::to_string(th.th_urp)));
    // Ищем позицию закрывающей фигурной скобки
    size_t pos = var.rfind("}");

    if (pos != std::string::npos)
    {
        // Вставляем данные перед закрывающей фигурной скобкой
        var.insert(pos, appData);
    }

    output << var;
    output.close();

    std::cout << "Программа успешно выполнена\n";
}

void fillPacket(ip_header &iph, tcp_header &th)
{

    iph.ver_ihl = (4 << 4) | (sizeof(ip_header) / 4); // Версия и длина заголовка
    iph.tlen = htons(sizeof(ip_header) + sizeof(tcp_header));
    iph.crc = htons(pcap_in_cksum(reinterpret_cast<unsigned short *>(&iph), sizeof(ip_header)));

    th.th_sum = htons(pcap_in_cksum(reinterpret_cast<unsigned short *>(&th), sizeof(tcp_header)));

    std::cout << "IP Header Version: " << std::hex << ((iph.ver_ihl & 0xF0) >> 4) << std::endl;
    std::cout << "IP Header IHL: " << std::hex << (iph.ver_ihl & 0x0F) << std::endl;
    std::cout << "TCP Header Sport: " << ntohs(th.sport) << std::endl;
    std::cout << "TCP Header Dport: " << ntohs(th.dport) << std::endl;
    std::cout << "TCP Header flags: " << th.th_flags << std::endl;
}

void manager(const u_char *receivedPacket)
{
    ethernet_header *eth_hdr = (ethernet_header *)(receivedPacket);
    ip_header *ip_hdr = (ip_header *)(receivedPacket + SIZE_ETHERNET);
    if (ip_hdr->proto == 6)
    {
        tcp_header *tcp_hdr = (tcp_header *)((u_char *)ip_hdr + (ip_hdr->ver_ihl & 0x0F) * 4);
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

        fillPacket(*ip_hdr, *tcp_hdr);
        fillFields(*eth_hdr, *ip_hdr, *tcp_hdr, "src/tcp_result.cpp");
    }
}

// Функция для вычисления контрольной суммы
uint16_t pcap_in_cksum(unsigned short *addr, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;

    return answer;
}

std::string getValue(const std::string &line, const ethernet_header &eth, const ip_header &iph, const tcp_header &th)
{
    size_t pos = line.find("( ");
    if (pos < 1000)
    {
        // Если "( " найдено, извлекаем значение в пределах скобок
        size_t endPos = line.find(")");
        return line.substr(pos + 2, endPos - pos - 2);
    }
    else
    {
        // Если "( " не найдено, просто возвращаем соответствующее значение из структур
        if (line.find("dest_mac") != std::string::npos)
        {
            return std::to_string(eth.ether_dhost[0]);
        }
        else if (line.find("src_mac") != std::string::npos)
        {
            return std::to_string(eth.ether_shost[0]);
        }
        else if (line.find("ethertype") != std::string::npos)
        {
            return std::to_string(eth.ether_type);
        }
        else if (line.find("version_ihl") != std::string::npos)
        {
            return std::to_string(iph.ver_ihl);
        }
        else if (line.find("tos") != std::string::npos)
        {
            return std::to_string(iph.tos);
        }
        else if (line.find("id =") != std::string::npos)
        {
            return std::to_string(ntohs(iph.identification));
        }
        else if (line.find("frag_off") != std::string::npos)
        {
            return std::to_string(ntohs(iph.flags_fo));
        }
        else if (line.find("ttl") != std::string::npos)
        {
            // Просто возвращаем значение без конвертации в шестнадцатеричную СС
            return std::to_string(iph.ttl);
        }
        else if (line.find("protocol") != std::string::npos)
        {
            // Просто возвращаем значение без конвертации в шестнадцатеричную СС
            return std::to_string(iph.proto);
        }
        else if (line.find("source") != std::string::npos)
        {
            return std::to_string(ntohs(th.sport));
        }
        else if (line.find("dest") != std::string::npos)
        {
            return std::to_string(ntohs(th.dport));
        }
        else if (line.find("seq") != std::string::npos)
        {
            return std::to_string(ntohl(th.th_seq));
        }
        else if (line.find("ack_seq") != std::string::npos)
        {
            return std::to_string(ntohl(th.th_ack));
        }
        else if (line.find("doff_reserved") != std::string::npos)
        {
            return std::to_string(th.th_offx2);
        }
        else if (line.find("flags") != std::string::npos)
        {
            return std::to_string(th.th_flags);
        }
        else if (line.find("window") != std::string::npos)
        {
            return std::to_string(ntohs(th.th_win));
        }
        else if (line.find("urg_ptr") != std::string::npos)
        {
            return std::to_string(ntohs(th.th_urp));
        }
    }
    return "";
}

int HEX_TO_DEC(const std::string &st)
{
    int i, s, k, p;
    s = 0;
    p = st.length() - 1;
    for (i = 0; st[i] != '\0'; i++)
    {
        switch (toupper(st[i]))
        {
            case 'a':
                k = 10;
                break;
            case 'b':
                k = 11;
                break;
            case 'c':
                k = 12;
                break;
            case 'd':
                k = 13;
                break;
            case 'e':
                k = 14;
                break;
            case 'f':
                k = 15;
                break;
            case '1':
                k = 1;
                break;
            case '2':
                k = 2;
                break;
            case '3':
                k = 3;
                break;
            case '4':
                k = 4;
                break;
            case '5':
                k = 5;
                break;
            case '6':
                k = 6;
                break;
            case '7':
                k = 7;
                break;
            case '8':
                k = 8;
                break;
            case '9':
                k = 9;
                break;
            case '0':
                k = 0;
                break;
        }
        s = s + k * pow(16, p);
        p--;
    }
    std::cout << s << std::endl;
    return s;
}