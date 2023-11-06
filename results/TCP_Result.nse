local packet = require("packet")
local stdnse = require("stdnse")

-- Создаем структуру для хранения параметров TCP-заголовка
local tcpHeader = {
    ip_src = "169.254.74.46",
    ip_dst = "169.254.74.46",
    port_src = 52900,
    port_dst = 139,
    flags = 20,
    sequence = 2861104898,
    acknowledgment = 927254732,
    data = "Hello tcp",
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
