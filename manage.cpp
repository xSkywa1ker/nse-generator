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
    std::vector<std::pair<size_t, std::string>> replacements;

    // Создаем строку для поиска паттерна
    std::string pattern = fieldName + "\\s*=\\s*[^,]*";

    std::regex reg(pattern);
    std::sregex_iterator iter(scriptContent.begin(), scriptContent.end(), reg);
    std::sregex_iterator end;

    while (iter != end) {
        std::string match = iter->str();
        std::size_t equalsPos = match.find('=');
        if (equalsPos != std::string::npos) {
            std::string field = match.substr(0, equalsPos);
            // Убеждаемся, что это поле соответствует имени, иначе игнорируем
            if (field.find(fieldName) != std::string::npos) {
                std::string currentFieldValue = match.substr(equalsPos + 1);
                // Проверяем, была ли замена уже выполнена
                if (currentFieldValue != newValue) {
                    // Сохраняем информацию о замене
                    replacements.push_back({ iter->position() + equalsPos + 1, newValue });
                }
            }
        }
        ++iter;
    }

    // Собираем исходный скрипт
    for (auto it = replacements.rbegin(); it != replacements.rend(); ++it) {
        scriptContent.replace(it->first, it->second.length(), it->second);
    }

    return scriptContent;
}





