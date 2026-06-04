#!/bin/bash

# Скрипт для удаления правил перенаправления трафика и остановки redsocks

WG_IFACE="wdtt0"

if [ "$EUID" -ne 0 ]; then
  echo "Пожалуйста, запустите скрипт с правами root (sudo)."
  exit 1
fi

echo "Удаление правила из PREROUTING..."
iptables -t nat -D PREROUTING -i $WG_IFACE -p tcp -j REDSOCKS 2>/dev/null || true

echo "Очистка и удаление цепочки REDSOCKS..."
iptables -t nat -F REDSOCKS 2>/dev/null || true
iptables -t nat -X REDSOCKS 2>/dev/null || true

echo "Сохранение текущих правил iptables (для фиксации изменений после перезагрузки)..."
# Если netfilter-persistent установлен, используем его, иначе пропускаем
if command -v netfilter-persistent &> /dev/null; then
    netfilter-persistent save
else
    echo "netfilter-persistent не найден, правила могут не сохраниться при перезагрузке."
fi

echo "Остановка сервиса redsocks..."
systemctl stop redsocks 2>/dev/null || true
systemctl disable redsocks 2>/dev/null || true

echo "======================================================"
echo "Готово! Правила перенаправления трафика для $WG_IFACE успешно удалены."
echo "Проксирование через redsocks остановлено."
echo "======================================================"
