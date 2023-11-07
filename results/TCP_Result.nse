local socket = require("socket")

-- Функция для конвертации IP-адресов в бинарный формат
local function ip_to_binary(ip)
    local parts = {}
    for part in ip:gmatch("%d+") do
        parts[#parts + 1] = string.char(tonumber(part))
    end
    return table.concat(parts)
end

-- Функция для вычисления контрольной суммы IP-пакета
local function calculate_ip_checksum(ipPacket)
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

-- Функция для преобразования данных в шестнадцатеричное представление
local function tohex(data)
    local hex = ""
    for i = 1, #data do
        hex = hex .. string.format("%02X", data:byte(i))
    end
    return hex
end

-- Создаем структуру для хранения параметров TCP-заголовка
local tcpHeader = {
    ip_src = "169.254.74.46",
    ip_dst = "169.254.74.46",
    port_src = 52900,
    port_dst = 139,
    sequence = 2861104898,
    acknowledgment = 927254732,
    data = "Hello tcp",
}

-- Функция для создания TCP-пакета на основе переданных параметров
local function build_tcp_packet(tcpHeader)
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
            data = "Hello tcp",
        }
    }

    -- Рассчитываем и устанавливаем длину IP-пакета
    local ip_len = #tcpPacket.ip + #tcpPacket.tcp.data
    tcpPacket.ip.len = string.pack(">I2", ip_len)

    -- Рассчитываем и устанавливаем контрольную сумму IP-пакета
    tcpPacket.ip.csum = calculate_ip_checksum(tcpPacket.ip)

    return tcpPacket
end

-- Используем функцию для создания TCP-пакета
local tcpPacket = build_tcp_packet(tcpHeader)

-- Создаем и отправляем сокет с использованием luasocket
local client = assert(socket.tcp())
client:connect(tcpHeader.ip_src, tcpHeader.port_dst)
client:send(tcpPacket.eth.src .. tcpPacket.eth.dst .. tcpPacket.eth.ethertype .. tcpPacket.ip.ver_ihl .. tcpPacket.ip.tos .. tcpPacket.ip.len .. tcpPacket.ip.id .. tcpPacket.ip.flags_frag .. tcpPacket.ip.ttl .. tcpPacket.ip.proto .. tcpPacket.ip.csum .. tcpPacket.ip.src .. tcpPacket.ip.dst .. tcpPacket.tcp.sport .. tcpPacket.tcp.dport .. tcpPacket.tcp.seq .. tcpPacket.tcp.ack .. tcpPacket.tcp.data)
client:close()
