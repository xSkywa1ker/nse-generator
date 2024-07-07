#ifndef LUA_SCRIPT_GENERATOR_MANAGE_H
#define LUA_SCRIPT_GENERATOR_MANAGE_H
#include "NetworkStructures.h"

std::string ReplaceField(std::string scriptContent, const std::string &fieldName, const std::string &newValue);

void analizer(const u_char *receivedPacket, bool is_scanner, int proto, const char* source_ip, const char* dest_ip);

void putMainIntoResult(const std::string &outputFile);

#endif //LUA_SCRIPT_GENERATOR_MANAGE_H
