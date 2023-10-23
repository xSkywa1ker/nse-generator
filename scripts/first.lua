-- Подключение библиотеки LuaSocket
socket = require("socket")

-- Указываем параметры для генерации TCP-пакета
local src_ip = "127.0.0.1"
local src_port = 50000
local dst_ip = "127.0.0.1"
local dst_port = 12345
local seq_num = 1001
local ack_num = 0
local flags = 2  -- Например, флаг SYN для установки соединения
local window_size = 8192
local data = "Hello, TCP!"

-- Создаем TCP-сокет
local tcp = assert(socket.tcp())

-- Устанавливаем соединение с целевой системой
assert(tcp:connect(dst_ip, dst_port))

-- Собираем TCP-пакет
local packet = string.pack(">I4I4I4I4I2I2I2s", src_port, dst_port, seq_num, ack_num, flags, window_size, 0, data)

-- Отправляем пакет
assert(tcp:send(packet))

-- Закрываем соединение
tcp:close()
