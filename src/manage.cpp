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
    std::string newIPSrc = "127.0.0.1";
    std::string newIPDst = "127.0.0.1";
    int newPortSrc = 54321;
    int newPortDst = 8080;
    int newFlags = 0x02;
    int newSequence = 54321;
    int newAcknowledgment = 12345;
    std::string newData = "Hello, TCP";

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
    std::string target = fieldName + " = ";

    size_t pos = scriptContent.find(target);

    while (pos != std::string::npos) {
        size_t startPos = pos + target.length();

        // Определяем конец текущей строки
        size_t endPos = scriptContent.find('\n', startPos);
        if (endPos == std::string::npos) {
            endPos = scriptContent.length();
        }

        // Вырезаем и заменяем значение
        std::string oldValue = scriptContent.substr(startPos, endPos - startPos);
        if (fieldName == "ip_src" || fieldName == "ip_dst" || fieldName == "data") {
            scriptContent.replace(startPos, endPos - startPos, "\"" + newValue + "\",");
        } else {
            scriptContent.replace(startPos, endPos - startPos, newValue + ",");
        }

        // Поиск следующего вхождения
        pos = scriptContent.find(target, endPos);
    }

    return scriptContent;
}
