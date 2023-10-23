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