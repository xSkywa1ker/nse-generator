local packet = require("packet")
local stdnse = require("stdnse")

-- Создаем структуру для хранения параметров TCP-заголовка
local tcpHeader = {
    ip_src = "192.168.1.2",        -- IP-адрес отправителя
    ip_dst = "192.168.1.1",        -- IP-адрес назначения
    port_src = 12345,             -- Порт отправителя
    port_dst = 80,                -- Порт назначения
    flags = 0x02,                 -- Флаги TCP
    sequence = 12345,             -- Номер последовательности
    acknowledgment = 0,           -- Подтверждение
    data = "This is a custom TCP packet." -- Полезная нагрузка
}

-- Функция для создания TCP-пакета на основе переданных параметров
local function build_tcp_packet(tcpHeader)
    local tcpPacket = packet.Packet:new()

    -- Устанавливаем значения полей TCP-пакета из структуры
    tcpPacket:ip_saddr(tcpHeader.ip_src)
    tcpPacket:ip_daddr(tcpHeader.ip_dst)
    tcpPacket:ip_sport(tcpHeader.port_src)
    tcpPacket:ip_dport(tcpHeader.port_dst)
    tcpPacket:tcp_flags_set(tcpHeader.flags)
    tcpPacket:tcp_seq(tcpHeader.sequence)
    tcpPacket:tcp_ack(tcpHeader.acknowledgment)
    tcpPacket:payload(tcpHeader.data)

    -- Сборка пакета
    tcpPacket:eth_build()
    tcpPacket:ip_build()
    tcpPacket:tcp_build()

    return tcpPacket
end

-- Используем функцию для создания TCP-пакета
local tcpPacket = build_tcp_packet(tcpHeader)

-- Выводим собранный пакет
local packetData = tcpPacket:get_packet()
stdnse.print("Сформированный TCP-пакет: %s", stdnse.tohex(packetData))
