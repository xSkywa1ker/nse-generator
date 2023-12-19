# Запуск проекта
## Установка языка и зависимостей
### Установка Lua
1. Установка пакета
```bash
sudo apt install lua5.3
```

2. Скомпилировать Lua
```bash
sudo apt install build-essential libreadline-dev
```
3. Cкомпилировать и установить последнюю версию
```bash
mkdir lua_build
cd lua_build
curl -R -O http://www.lua.org/ftp/lua-5.3.5.tar.gz
tar -zxf lua-5.3.5.tar.gz
cd lua-5.3.5
make linux test
sudo make install
```
### Установка зависимостей
1. Установка lua-socket
```bash
sudo apt update
sudo apt install lua-socket
```

## Запуск управляющей программы
В программе можем указать любые данные для полей TCP пакета и по шаблону получим
программу выдающую lua-скрипт, генерирующий такой пакет.
1. Компиляция файла
```bash
g++ -o main main.cpp src/traffic_parser.cpp src/manage.cpp -lpcap
```
2. Запуск
```bash
./main IP-сканер IP-жертва
```
Для примера IP-сканер: 192.168.3.12 IP-жертва: 192.168.3.10

## Запуск сформированного подпрограммной подсистемы генерации трафика
1. Компиляция файла
```bash
g++ -o test src/tcp_result.cpp
```
2. Запуск
```bash
sudo ./test
```


### Запуск  nse скрипта:
```bash
lua script.nse
```

### Тестировочный трафик:
1. discover.pcapng (**Проверка 139 порта**)
2. vulnerability.pcapng (**Уязвимость нахождения MAC-адреса**)
