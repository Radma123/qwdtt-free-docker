#!/bin/bash

# Скрипт для перенаправления трафика от клиентов WireGuard (интерфейс wdtt0, который создает server.go)
# в локальный SOCKS5 прокси. 
# Использует redsocks для прозрачного проксирования TCP трафика.

WG_IFACE="wdtt0"
SOCKS_IP="127.0.0.1"
SOCKS_PORT="1080"
REDSOCKS_PORT="12345"

if [ "$EUID" -ne 0 ]; then
  echo "Пожалуйста, запустите скрипт с правами root (sudo)."
  exit 1
fi

echo "Обновление пакетов и установка redsocks и iptables-persistent..."
apt-get update
apt-get install -y redsocks iptables iptables-persistent

echo "Настройка конфигурации redsocks..."
cat > /etc/redsocks.conf <<EOF
base {
    log_debug = off;
    log_info = on;
    log = "file:/var/log/redsocks.log";
    daemon = on;
    user = redsocks;
    group = redsocks;
    redirector = iptables;
}
redsocks {
    local_ip = 0.0.0.0;
    local_port = $REDSOCKS_PORT;
    ip = $SOCKS_IP;
    port = $SOCKS_PORT;
    type = socks5;
}
EOF

echo "Перезапуск сервиса redsocks..."
systemctl restart redsocks
systemctl enable redsocks

echo "Включение маршрутизации IP..."
sysctl -w net.ipv4.ip_forward=1

echo "Настройка правил iptables для перенаправления трафика с $WG_IFACE на redsocks..."

# Очистка старых правил
iptables -t nat -F REDSOCKS 2>/dev/null || true
iptables -t nat -X REDSOCKS 2>/dev/null || true

# Создание новой цепочки REDSOCKS
iptables -t nat -N REDSOCKS

# Исключаем локальные и зарезервированные адреса из проксирования
iptables -t nat -A REDSOCKS -d 0.0.0.0/8 -j RETURN
iptables -t nat -A REDSOCKS -d 10.0.0.0/8 -j RETURN
iptables -t nat -A REDSOCKS -d 127.0.0.0/8 -j RETURN
iptables -t nat -A REDSOCKS -d 169.254.0.0/16 -j RETURN
iptables -t nat -A REDSOCKS -d 172.16.0.0/12 -j RETURN
iptables -t nat -A REDSOCKS -d 192.168.0.0/16 -j RETURN
iptables -t nat -A REDSOCKS -d 224.0.0.0/4 -j RETURN
iptables -t nat -A REDSOCKS -d 240.0.0.0/4 -j RETURN

# Все остальные TCP-запросы перенаправляем на порт redsocks
iptables -t nat -A REDSOCKS -p tcp -j REDIRECT --to-ports $REDSOCKS_PORT

# Применяем цепочку ко всему входящему трафику из интерфейса WireGuard
iptables -t nat -A PREROUTING -i $WG_IFACE -p tcp -j REDSOCKS

# Блокируем доступ к порту redsocks из внешнего мира (разрешаем только с интерфейса WireGuard)
iptables -D INPUT -p tcp --dport $REDSOCKS_PORT ! -i $WG_IFACE -j DROP 2>/dev/null || true
iptables -A INPUT -p tcp --dport $REDSOCKS_PORT ! -i $WG_IFACE -j DROP

# Сохранение правил iptables, чтобы они оставались после перезагрузки
netfilter-persistent save

echo "======================================================"
echo "Готово! Трафик с интерфейса $WG_IFACE теперь перенаправляется"
echo "на локальный SOCKS5 прокси по адресу $SOCKS_IP:$SOCKS_PORT через redsocks."
echo "Примечание: Redsocks проксирует только TCP трафик."
echo "Для отключения перенаправления используйте команды:"
echo "sudo iptables -t nat -D PREROUTING -i $WG_IFACE -p tcp -j REDSOCKS"
echo "sudo systemctl stop redsocks"
echo "======================================================"
