# Используем базовый образ Debian с зеркалом в США
FROM debian:bullseye

# Заменяем зеркало на американское
RUN sed -i 's/deb.debian.org/us.debian.org/' /etc/apt/sources.list

# Установка зависимостей, если необходимо (например, libpcap)
RUN apt-get update && apt-get install -y g++ libpcap-dev

# Создание рабочей директории
WORKDIR /usr/src/app

# Копирование исходных файлов проекта в контейнер
COPY . .

# Компиляция main.cpp и traffic_parser.cpp
RUN g++ -o main main.cpp src/traffic_parser.cpp src/manage.cpp -lpcap

# Запуск main.cpp
CMD ["./main", "169.254.74.46", "169.254.34.130"]
