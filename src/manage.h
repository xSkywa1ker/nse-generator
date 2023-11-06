#ifndef LUA_SCRIPT_GENERATOR_MANAGE_H
#define LUA_SCRIPT_GENERATOR_MANAGE_H

std::string ReplaceField(std::string scriptContent, const std::string &fieldName, const std::string &newValue);

int manager(char* newIPSrc, char* newIPDst, uint16_t newPortSrc, uint16_t newPortDst, uint8_t newFlags, uint32_t newSequence,
            uint32_t newAcknowledgment);

#endif //LUA_SCRIPT_GENERATOR_MANAGE_H

