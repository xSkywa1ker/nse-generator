#ifndef LUA_SCRIPT_GENERATOR_MANAGE_H
#define LUA_SCRIPT_GENERATOR_MANAGE_H

std::string ReplaceField(std::string scriptContent, const std::string &fieldName, const std::string &newValue);

int manager(std::string newIPSrc, std::string newIPDst, int newPortSrc, int newPortDst, int newFlags, int newSequence,
            int newAcknowledgment);

#endif //LUA_SCRIPT_GENERATOR_MANAGE_H

