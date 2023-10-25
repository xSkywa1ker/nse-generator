#include <iostream>
#include <fstream>
#include <string>
#include <regex>

std::string ReplaceField(std::string scriptContent, const std::string &fieldName, const std::string &newValue);

int main() {
    // Открываем файл Lua-скрипта для чтения
    std::ifstream luaScriptFile("samples/TCP_Sample.lua");

    if (!luaScriptFile.is_open()) {
        std::cerr << "Failed to open Lua script file." << std::endl;
        return 1;
    }

    // Читаем содержимое файла в строку
    std::string luaScriptContent;
    std::string line;
    while (std::getline(luaScriptFile, line)) {
        luaScriptContent += line + "\n";
    }
    luaScriptFile.close();

    // Здесь будут считанные из перехваченного трафика значения
    std::string newIPSrc = "New IP Source";
    std::string newIPDst = "New IP Destination";
    int newPortSrc = 54321;
    int newPortDst = 8080;
    int newFlags = 0x10;
    int newSequence = 54321;
    int newAcknowledgment = 12345;
    std::string newData = "New TCP Payload";

    // Заменяем поля структуры tcpHeader
    luaScriptContent = ReplaceField(luaScriptContent, "ip_src", newIPSrc);
    luaScriptContent = ReplaceField(luaScriptContent, "ip_dst", newIPDst);
    luaScriptContent = ReplaceField(luaScriptContent, "port_src", std::to_string(newPortSrc));
    luaScriptContent = ReplaceField(luaScriptContent, "port_dst", std::to_string(newPortDst));
    luaScriptContent = ReplaceField(luaScriptContent, "flags", std::to_string(newFlags));
    luaScriptContent = ReplaceField(luaScriptContent, "sequence", std::to_string(newSequence));
    luaScriptContent = ReplaceField(luaScriptContent, "acknowledgment", std::to_string(newAcknowledgment));
    luaScriptContent = ReplaceField(luaScriptContent, "data", newData);

    // Открываем файл Lua-скрипта для записи (перезаписи)
    std::ofstream modifiedLuaScriptFile("results/TCP_Result.lua");

    if (!modifiedLuaScriptFile.is_open()) {
        std::cerr << "Failed to open Lua script file for writing." << std::endl;
        return 1;
    }

    // Записываем измененное содержимое обратно в файл
    modifiedLuaScriptFile << luaScriptContent;
    modifiedLuaScriptFile.close();

    std::cout << "Lua script has been modified and saved." << std::endl;

    return 0;
}

// Функция для замены значения поля в строке Lua-скрипта
std::string ReplaceField(std::string scriptContent, const std::string &fieldName, const std::string &newValue) {
    std::regex pattern(fieldName + "\\s*=\\s*\"([^\"]*)\"|" + fieldName + "\\s*=\\s*([^,}]*)");
    std::smatch match;

    // Создаем временную копию, чтобы избежать зацикливания
    std::string tempContent = scriptContent;

    while (std::regex_search(tempContent, match, pattern)) {
        std::string fieldValue;
        if (match[1].str().empty()) {
            fieldValue = match[2].str();
        } else {
            fieldValue = match[1].str();
        }
        if (fieldValue != newValue) {
            // Заменяем только если не совпадает со значением newValue
            scriptContent.replace(match.position(), match.length(), fieldName + " = " + newValue);
        }
        tempContent = match.suffix();
    }

    return scriptContent;
}

