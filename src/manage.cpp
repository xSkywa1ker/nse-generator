#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <cstring>
#include "NetworkStructures.h"



struct FullTCPPacket {
    EthernetHeader eth_header;
    IPHeader ip_header;
    TCPHeader tcp_header;
};

// Function to fill the packet with values based on the provided packet data
void fillPacket(FullTCPPacket& new_packet, const u_char* packetData) {
    // Assuming packetData contains Ethernet, IP, and TCP headers in order

    // Fill Ethernet header
    std::memcpy(new_packet.eth_header.dest_mac.data(), packetData, 6);
    std::memcpy(new_packet.eth_header.src_mac.data(), packetData + 6, 6);
    new_packet.eth_header.ethertype = (packetData[12] << 8) | packetData[13];

    // Fill IP header
    new_packet.ip_header.ip_vhl = packetData[14];
    new_packet.ip_header.ip_tos = packetData[15];
    new_packet.ip_header.ip_len = (packetData[16] << 8) | packetData[17];
    new_packet.ip_header.ip_id = (packetData[18] << 8) | packetData[19];
    new_packet.ip_header.ip_off = (packetData[20] << 8) | packetData[21];
    new_packet.ip_header.ip_ttl = packetData[22];
    new_packet.ip_header.ip_p = packetData[23];
    new_packet.ip_header.ip_sum = (packetData[24] << 8) | packetData[25];
    new_packet.ip_header.ip_src = (packetData[26] << 24) | (packetData[27] << 16) |
                                     (packetData[28] << 8) | packetData[29];
    new_packet.ip_header.ip_dst = (packetData[30] << 24) | (packetData[31] << 16) |
                                   (packetData[32] << 8) | packetData[33];

    // Fill TCP header
    new_packet.tcp_header.th_sport = (packetData[34] << 8) | packetData[35];
    new_packet.tcp_header.th_dport = (packetData[36] << 8) | packetData[37];
    new_packet.tcp_header.th_seq = (packetData[38] << 24) | (packetData[39] << 16) |
                                (packetData[40] << 8) | packetData[41];
    new_packet.tcp_header.th_ack = (packetData[42] << 24) | (packetData[43] << 16) |
                                (packetData[44] << 8) | packetData[45];
    new_packet.tcp_header.th_offx2 = packetData[46];
    new_packet.tcp_header.th_flags = packetData[47];
    new_packet.tcp_header.th_win = (packetData[48] << 8) | packetData[49];
    new_packet.tcp_header.th_sum = (packetData[50] << 8) | packetData[51];
    new_packet.tcp_header.th_urp = (packetData[52] << 8) | packetData[53];
}

// Function to write the filled packet back to Lua script
void writeLuaScript(const FullTCPPacket& packet, const std::string& outputFileName) {
    std::ifstream luaScriptTemplate("template.lua");
    std::ofstream luaScript(outputFileName);

    if (luaScriptTemplate.is_open() && luaScript.is_open()) {
        std::string line;
        while (std::getline(luaScriptTemplate, line)) {
            // Replace placeholders in the Lua script with actual values
            size_t pos;
            while ((pos = line.find("eth_dest_mac = {, , , , , }")) != std::string::npos) {
                line.replace(pos, 30, "eth_dest_mac = {" +
                                      std::to_string(packet.eth_header.dest_mac[0]) + ", " +
                                      std::to_string(packet.eth_header.dest_mac[1]) + ", " +
                                      std::to_string(packet.eth_header.dest_mac[2]) + ", " +
                                      std::to_string(packet.eth_header.dest_mac[3]) + ", " +
                                      std::to_string(packet.eth_header.dest_mac[4]) + ", " +
                                      std::to_string(packet.eth_header.dest_mac[5]) + "}");
            }
            while ((pos = line.find("eth_src_mac = {, , , , , }")) != std::string::npos) {
                line.replace(pos, 29, "eth_src_mac = {" +
                                      std::to_string(packet.eth_header.src_mac[0]) + ", " +
                                      std::to_string(packet.eth_header.src_mac[1]) + ", " +
                                      std::to_string(packet.eth_header.src_mac[2]) + ", " +
                                      std::to_string(packet.eth_header.src_mac[3]) + ", " +
                                      std::to_string(packet.eth_header.src_mac[4]) + ", " +
                                      std::to_string(packet.eth_header.src_mac[5]) + "}");
            }
            while ((pos = line.find("ethertype = ,")) != std::string::npos) {
                line.replace(pos, 14, "ethertype = " + std::to_string(packet.eth_header.ethertype));
            }

            // Similar replacements for other fields...

            luaScript << line << "\n";
        }

        luaScriptTemplate.close();
        luaScript.close();
    } else {
        std::cerr << "Unable to open Lua script files.\n";
    }
}

int manage(const std::vector<std::vector<unsigned char*>> allPackets) () {
    FullTCPPacket new_packet;

    for (int i=0; i< allTcpHeaders.size(); i++)
    {
        packet = allTcpHeaders[i];
        fillPacket(new_packet,packet);
    }
    writeLuaScript(new_packet, "results/TCP_Result.nse");

    return 0;
}
