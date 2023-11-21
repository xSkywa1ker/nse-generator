local socket = require("socket")

function ip_to_binary(ip)
    local parts = {}
    for part in ip:gmatch("%d+") do
        parts[#parts + 1] = string.char(tonumber(part))
    end
    return table.concat(parts)
end

function calculate_ip_checksum(ipPacket)
    local header = ipPacket
    local sum = 0
    local numShorts = #header // 2

    for i = 1, numShorts do
        local part = header:byte(i * 2 - 1) * 256 + header:byte(i * 2)
        sum = sum + part
    end

    while sum > 0xFFFF do
        sum = (sum & 0xFFFF) + (sum >> 16)
    end

    return string.char(0xFF - sum)
end

function tohex(data)
    local hex = ""
    for i = 1, #data do
        hex = hex .. string.format("%02X", data:byte(i))
    end
    return hex
end

-- Определение функции для отправки пакета
function send_packet(eth_src, eth_dst, ethertype, ip_ver_ihl, ip_tos, ip_len, ip_id, ip_flags_frag, ip_ttl, ip_proto, ip_csum, ip_src, ip_dst, tcp_sport, tcp_dport, tcp_seq, tcp_ack, tcp_data)
    local client = assert(socket.tcp())
    client:connect(ip_src, tcp_dport)
    client:send(eth_src .. eth_dst .. ethertype .. ip_ver_ihl .. ip_tos .. ip_len .. ip_id .. ip_flags_frag .. ip_ttl .. ip_proto .. ip_csum .. ip_src .. ip_dst .. tcp_sport .. tcp_dport .. tcp_seq .. tcp_ack .. tcp_data)
    client:close()
end

-- Определение функции для построения TCP-пакета
function build_and_send_tcp_packet(tcpHeader)
    local tcpPacket = {
        eth = {
            src = "\x00\x00\x00\x00\x00\x00", -- Замените на ваш MAC-адрес
            dst = "\x00\x00\x00\x00\x00\x00", -- Замените на MAC-адрес назначения
            ethertype = "\x08\x00" -- IPv4
        },
        ip = {
            ver_ihl = "\x45", -- IPv4 и заголовок длиной 20 байт
            tos = "\x00",
            len = "\x00\x00", -- Будет заполнено автоматически
            id = "\x00\x00", -- Будет заполнено автоматически
            flags_frag = "\x00\x00", -- Будет заполнено автоматически
            ttl = "\x40", -- TTL (64)
            proto = "\x06", -- TCP
            csum = "\x00\x00", -- Будет заполнено автоматически
            src = ip_to_binary(tcpHeader.ip_src), -- Исходный IP-адрес
            dst = ip_to_binary(tcpHeader.ip_dst) -- IP-адрес назначения
        },
        tcp = {
            sport = tcpHeader.port_src, -- Исходный порт
            dport = tcpHeader.port_dst, -- Порт назначения
            seq = tcpHeader.sequence, -- Последовательность
            ack = tcpHeader.acknowledgment, -- Подтверждение
            data = tcpHeader.data
        }
    }

    -- Рассчитываем и устанавливаем длину IP-пакета
    local ip_len = #tcpPacket.ip + #tcpPacket.tcp.data
    tcpPacket.ip.len = string.pack(">I2", ip_len)

    -- Рассчитываем и устанавливаем контрольную сумму IP-пакета
    tcpPacket.ip.csum = calculate_ip_checksum(tcpPacket.ip)

    -- Преобразуем данные в формат HEX
    local eth_src = tcpPacket.eth.src
    local eth_dst = tcpPacket.eth.dst
    local ethertype = tcpPacket.eth.ethertype
    local ip_ver_ihl = tcpPacket.ip.ver_ihl
    local ip_tos = tcpPacket.ip.tos
    local ip_len = tcpPacket.ip.len
    local ip_id = tcpPacket.ip.id
    local ip_flags_frag = tcpPacket.ip.flags_frag
    local ip_ttl = tcpPacket.ip.ttl
    local ip_proto = tcpPacket.ip.proto
    local ip_csum = tcpPacket.ip.csum
    local ip_src = tcpPacket.ip.src
    local ip_dst = tcpPacket.ip.dst
    local tcp_sport = string.pack(">I2", tcpPacket.tcp.sport)
    local tcp_dport = string.pack(">I2", tcpPacket.tcp.dport)
    local tcp_seq = string.pack(">I4", tcpPacket.tcp.seq)
    local tcp_ack = string.pack(">I4", tcpPacket.tcp.ack)
    local tcp_data = tcpPacket.tcp.data

    -- Отправляем пакет
    send_packet(eth_src, eth_dst, ethertype, ip_ver_ihl, ip_tos, ip_len, ip_id, ip_flags_frag, ip_ttl, ip_proto, ip_csum, ip_src, ip_dst, tcp_sport, tcp_dport, tcp_seq, tcp_ack, tcp_data)
end

-- Вызываем функцию для каждого TCP-пакета
-- TCP packet 1
local tcpHeader1 = {
    ip_src = "",
    ip_dst = "",
    port_src = ,
    port_dst = ,
    sequence = ,
    acknowledgment = ,
    data = ""
}
build_and_send_tcp_packet(tcpHeader1)

build_and_send_tcp_packet(tcpHeader2)

-- Добавьте вызовы build_and_send_tcp_packet для остальных пакетов

print("Packets sent successfully.")
