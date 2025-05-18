#!/bin/bash

# === СКРИПТ АВТОНАСТРОЙКИ NGINX + SSL + КЕШ + ПРОКСИ + UFW ===
# Автор: t.me/bydni_IT
# Требования: Ubuntu 20.04+/22.04+, root-доступ, домен, открытые порты 80/443
# Описание: Устанавливает Nginx, настраивает обратный прокси с опциональным кэшированием,
#           генерирует SSL через Certbot, создает пользователя admin, настраивает UFW.

# Проверка, что скрипт запущен от root
if [[ $EUID -ne 0 ]]; then
   echo "Ошибка: Скрипт должен быть запущен с правами root (sudo)." 
   exit 1
fi

# Обновление системы и установка необходимых пакетов
echo "Обновляем систему и устанавливаем необходимые пакеты..."
apt update && apt upgrade -y
apt install -y nginx certbot python3-certbot-nginx ufw curl

# Запрос домена у пользователя
read -p "Введите ваш домен (например, example.com): " DOMAIN
if [[ -z "$DOMAIN" ]]; then
    echo "Ошибка: Домен не указан."
    exit 1
fi

# Запрос IP-адреса для прокси
read -p "Введите IP-адрес сервера, куда проксировать запросы (например, 192.168.1.1): " PROXY_IP
if [[ -z "$PROXY_IP" ]]; then
    echo "Ошибка: IP-адрес не указан."
    exit 1
fi

# Проверка доступности IP
if ! ping -c 1 "$PROXY_IP" &> /dev/null; then
    echo "Предупреждение: IP $PROXY_IP недоступен. Продолжить? (y/n)"
    read -r CONTINUE
    if [[ "$CONTINUE" != "y" ]]; then
        exit 1
    fi
fi

# Запрос выбора типа конфигурации
echo "Выберите тип конфигурации Nginx:"
echo "1) С кэшированием (рекомендуется для статического контента)"
echo "2) Без кэширования (простая конфигурация)"
read -p "Введите номер (1 или 2): " CONFIG_TYPE
if [[ "$CONFIG_TYPE" != "1" && "$CONFIG_TYPE" != "2" ]]; then
    echo "Ошибка: Неверный выбор. Используется конфигурация с кэшированием по умолчанию."
    CONFIG_TYPE=1
fi

# Создание пользователя admin
echo "Создаем пользователя admin..."
ADMIN_PASSWORD=$(openssl rand -base64 12)
useradd -m -s /bin/bash admin
echo "admin:$ADMIN_PASSWORD" | chpasswd
echo "Пользователь admin создан!"
echo "Пароль: $ADMIN_PASSWORD"
echo "!!! Сохраните пароль в надежном месте !!!"

# Настройка UFW (брандмауэр)
echo "Настраиваем UFW..."
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 22/tcp
ufw --force enable
echo "UFW настроен: разрешены порты 80, 443, 22."

# Установка и настройка SSL через Certbot
echo "Устанавливаем SSL-сертификат для $DOMAIN..."
certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --email admin@"$DOMAIN" || {
    echo "Ошибка при установке SSL. Проверьте, что домен направлен на этот сервер."
    exit 1
}

# Создание директорий для логов и кэша (если выбрано кэширование)
mkdir -p /var/log/nginx
if [[ "$CONFIG_TYPE" == "1" ]]; then
    mkdir -p /var/cache/nginx
fi

# Создание дефолтного nginx.conf
cat > /etc/nginx/nginx.conf << 'EOF'
# Основной конфигурационный файл Nginx
# Автор: t.me/bydni_IT

user www-data; # Пользователь, от которого работает Nginx
worker_processes auto; # Автоматическое определение числа рабочих процессов
pid /run/nginx.pid; # Путь к файлу PID
error_log /var/log/nginx/error.log; # Путь к логу ошибок

events {
    worker_connections 768; # Максимальное число соединений на процесс
    # multi_accept on; # (закомментировано) Принимать несколько соединений за раз
}

http {
    # Кастомный формат логов для лучшего анализа
    log_format custom '$remote_addr - $http_x_forwarded_for - $time_local - $request';

    # Основные настройки производительности
    sendfile on; # Ускорение передачи файлов
    tcp_nopush on; # Оптимизация отправки данных
    types_hash_max_size 2048; # Размер хэш-таблицы для типов MIME
    include /etc/nginx/mime.types; # Подключение MIME-типов
    default_type application/octet-stream; # Тип по умолчанию

    # Настройки обработки запросов
    large_client_header_buffers 4 16k; # Буферы для больших заголовков
    client_max_body_size 50M; # Максимальный размер тела запроса

    # Настройки SSL
    ssl_protocols TLSv1.2 TLSv1.3; # Поддерживаемые протоколы SSL
    ssl_prefer_server_ciphers on; # Предпочтение серверных шифров

    # Настройки Gzip-сжатия
    gzip on; # Включение сжатия
    gzip_vary on; # Добавление заголовка Vary
    gzip_proxied any; # Сжатие для всех проксированных ответов
    gzip_comp_level 6; # Уровень сжатия
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript image/svg+xml; # Типы для сжатия

    # Подключение конфигураций виртуальных хостов
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

# Создание конфигурации сайта
NGINX_CONF="/etc/nginx/sites-available/$DOMAIN"
if [[ "$CONFIG_TYPE" == "1" ]]; then
    # Конфигурация с кэшированием
    cat > "$NGINX_CONF" << EOF
# Конфигурация Nginx с кэшированием для $DOMAIN
# Автор: t.me/bydni_IT

# Карта для определения кэшируемого контента
map \$sent_http_content_type \$cacheable {
    ~^image/ 1; # Кэшировать изображения
    ~^text/css 1; # Кэшировать CSS
    ~^application/javascript 1; # Кэшировать JavaScript
    ~^application/json 1; # Кэшировать JSON
    ~^image/svg\+xml 1; # Кэшировать SVG
    default 0; # Не кэшировать остальное
}

# Сервер для HTTP (редирект на HTTPS)
server {
    listen 80; # Прослушивание порта 80
    server_name $DOMAIN; # Имя домена
    return 301 https://\$host\$request_uri; # Перенаправление на HTTPS
}

# Сервер для HTTPS
server {
    listen 443 ssl http2; # Прослушивание порта 443 с поддержкой HTTP/2
    server_name $DOMAIN; # Имя домена

    # Путь к SSL-сертификатам
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;

    # Настройки SSL для безопасности
    ssl_protocols TLSv1.2 TLSv1.3; # Поддерживаемые протоколы
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256'; # Шифры
    ssl_prefer_server_ciphers on; # Предпочтение серверных шифров
    ssl_session_cache shared:SSL:10m; # Кэш сессий
    ssl_session_timeout 1h; # Время жизни сессии

    # Заголовки безопасности
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always; # HSTS
    add_header X-Content-Type-Options nosniff; # Защита от MIME-сниффинга
    add_header X-Frame-Options SAMEORIGIN; # Защита от кликджекинга
    add_header X-XSS-Protection "1; mode=block"; # Защита от XSS
    add_header Referrer-Policy "strict-origin-when-cross-origin"; # Политика реферера

    # Настройки Gzip
    gzip on; # Включение сжатия
    gzip_proxied any; # Сжатие для всех ответов
    gzip_comp_level 5; # Уровень сжатия
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript image/svg+xml; # Типы для сжатия
    gzip_vary on; # Добавление заголовка Vary
    gzip_min_length 1000; # Минимальная длина для сжатия

    # Настройка real_ip (для работы за прокси, например, Cloudflare)
    set_real_ip_from 0.0.0.0/0; # Диапазон доверенных IP (замените при необходимости)
    real_ip_header X-Forwarded-For; # Заголовок для IP
    real_ip_recursive on; # Рекурсивное определение IP

    # Логирование
    access_log /var/log/nginx/$DOMAIN.log custom; # Путь к логу с кастомным форматом

    # Настройки кэширования
    proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=STATIC:50m inactive=10m; # Путь и параметры кэша

    # Основной блок проксирования
    location / {
        proxy_pass http://$PROXY_IP; # Адрес проксируемого сервера
        proxy_set_header Host $DOMAIN; # Передача имени хоста
        proxy_set_header X-Real-IP \$remote_addr; # Передача реального IP
        proxy_set_header X-Forwarded-For \$remote_addr; # Передача IP для прокси
        proxy_set_header CF-Connecting-IP \$remote_addr; # Для Cloudflare (если используется)

        # Настройки SSL для прокси
        proxy_ssl_server_name on; # Передача имени сервера в SSL
        proxy_ssl_verify off; # Отключение проверки сертификата (включите при необходимости)
        proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt; # Доверенные сертификаты

        # DNS-резолверы
        resolver 1.1.1.1 8.8.8.8 valid=300s; # Публичные DNS
        proxy_redirect off; # Отключение редиректов

        # HTTP-версия и заголовки
        proxy_http_version 1.1; # Использование HTTP/1.1
        proxy_set_header Connection ""; # Очистка заголовка Connection

        # Настройки кэширования
        proxy_cache STATIC; # Использование зоны кэша
        proxy_cache_valid 200 302 10m; # Время кэширования успешных ответов
        proxy_cache_valid 404 1m; # Время кэширования ошибок
        proxy_cache_use_stale error timeout updating; # Использование устаревшего кэша при ошибках
        proxy_cache_bypass \$cacheable 0; # Условие обхода кэша
        proxy_no_cache \$cacheable 0; # Условие запрета кэширования
        add_header X-Proxy-Cache \$upstream_cache_status; # Заголовок статуса кэша
    }
}
EOF
else
    # Конфигурация без кэширования
    cat > "$NGINX_CONF" << EOF
# Простая конфигурация Nginx без кэширования для $DOMAIN
# Автор: t.me/bydni_IT

# Сервер для HTTP (редирект на HTTPS)
server {
    listen 80; # Прослушивание порта 80
    server_name $DOMAIN; # Имя домена
    return 301 https://\$host\$request_uri; # Перенаправление на HTTPS
}

# Сервер для HTTPS
server {
    listen 443 ssl http2; # Прослушивание порта 443 с поддержкой HTTP/2
    server_name $DOMAIN; # Имя домена

    # Путь к SSL-сертификатам
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;

    # Настройки SSL для безопасности
    ssl_protocols TLSv1.2 TLSv1.3; # Поддерживаемые протоколы
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256'; # Шифры
    ssl_prefer_server_ciphers on; # Предпочтение серверных шифров
    ssl_session_cache shared:SSL:10m; # Кэш сессий
    ssl_session_timeout 1h; # Время жизни сессии

    # Заголовки безопасности
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always; # HSTS
    add_header X-Content-Type-Options nosniff; # Защита от MIME-сниффинга
    add_header X-Frame-Options SAMEORIGIN; # Защита от кликджекинга
    add_header X-XSS-Protection "1; mode=block"; # Защита от XSS
    add_header Referrer-Policy "strict-origin-when-cross-origin"; # Политика реферера

    # Настройки Gzip
    gzip on; # Включение сжатия
    gzip_proxied any; # Сжатие для всех ответов
    gzip_comp_level 5; # Уровень сжатия
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript image/svg+xml; # Типы для сжатия
    gzip_vary on; # Добавление заголовка Vary
    gzip_min_length 1000; # Минимальная длина для сжатия

    # Настройка real_ip (для работы за прокси, например, Cloudflare)
    set_real_ip_from 0.0.0.0/0; # Диапазон доверенных IP (замените при необходимости)
    real_ip_header X-Forwarded-For; # Заголовок для IP
    real_ip_recursive on; # Рекурсивное определение IP

    # Логирование
    access_log /var/log/nginx/$DOMAIN.log custom; # Путь к логу с кастомным форматом

    # Основной блок проксирования
    location / {
        proxy_pass http://$PROXY_IP; # Адрес проксируемого сервера
        proxy_set_header Host $DOMAIN; # Передача имени хоста
        proxy_set_header X-Real-IP \$remote_addr; # Передача реального IP
        proxy_set_header X-Forwarded-For \$remote_addr; # Передача IP для прокси
        proxy_set_header CF-Connecting-IP \$remote_addr; # Для Cloudflare (если используется)

        # HTTP-версия и заголовки
        proxy_http_version 1.1; # Использование HTTP/1.1
        proxy_set_header Connection ""; # Очистка заголовка Connection
    }
}
EOF
fi

# Активация конфигурации
ln -sf /etc/nginx/sites-available/"$DOMAIN" /etc/nginx/sites-enabled/"$DOMAIN"

# Проверка и перезапуск Nginx
echo "Проверяем конфигурацию Nginx..."
if nginx -t; then
    echo "Конфигурация верна. Перезапускаем Nginx..."
    systemctl restart nginx
else
    echo "Ошибка в конфигурации Nginx. Проверьте /etc/nginx/sites-available/$DOMAIN"
    exit 1
fi

# Вывод финальной информации
echo "============================================================="
echo "Настройка завершена!"
echo "Домен: $DOMAIN"
echo "Прокси: http://$PROXY_IP"
echo "Пользователь: admin"
echo "Пароль: $ADMIN_PASSWORD"
echo "!!! Сохраните пароль в надежном месте !!!"
echo "Логи: /var/log/nginx/$DOMAIN.log"
if [[ "$CONFIG_TYPE" == "1" ]]; then
    echo "Кэш: /var/cache/nginx"
fi
echo "Конфигурация: /etc/nginx/sites-available/$DOMAIN"
echo "Автор скрипта: t.me/bydni_IT"
echo "============================================================="
