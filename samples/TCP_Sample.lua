local packet = require("packet")
local stdnse = require("stdnse")

-- Функция для установки флагов в TCP-пакете на основе последовательности
local function set_tcp_flags(tcpPacket, flags)
    local flag_map = {
        URG = 0x20,
        ACK = 0x10,
        PSH = 0x08,
        RST = 0x04,
        SYN = 0x02,
        FIN = 0x01
    }

    -- Проходим по каждому флагу в последовательности и устанавливаем/снимаем его
    for flag, value in pairs(flag_map) do
        if flags:sub(flag, flag) == "1" then
            tcpPacket:tcp_flags_set(value)
        else
            tcpPacket:tcp_flags_clear(value)
        end
    end
end

-- Принимаем последовательность из нулей и единиц
local flags_sequence = "101010"

-- Создаем новый TCP-пакет
local tcpPacket = packet.Packet:new()

-- Устанавливаем значения полей TCP-заголовка
tcpPacket:ip_dport(80)
tcpPacket:ip_sport(12345)

-- Устанавливаем флаги на основе последовательности
set_tcp_flags(tcpPacket, flags_sequence)

-- Создаем данные для TCP-пакета (полезная нагрузка)
local payload = "This is a TCP packet payload."
tcpPacket:payload(payload)

-- Сборка пакета
tcpPacket:eth_build()
tcpPacket:ip_build()
tcpPacket:tcp_build()

-- Выводим собранный пакет
local packetData = tcpPacket:get_packet()
stdnse.print("Сформированный TCP-пакет: %s", stdnse.tohex(packetData))