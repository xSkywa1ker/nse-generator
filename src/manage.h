#ifndef LUA_SCRIPT_GENERATOR_MANAGE_H
#define LUA_SCRIPT_GENERATOR_MANAGE_H
#include "NetworkStructures.h"

std::string ReplaceField(std::string scriptContent, const std::string &fieldName, const std::string &newValue);

void manager(const u_char *receivedPacket, bool flag);

#endif //LUA_SCRIPT_GENERATOR_MANAGE_H
