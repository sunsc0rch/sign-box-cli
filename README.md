# proxyctl

CLI-обёртка над [sing-box](https://github.com/SagerNet/sing-box) для управления прокси на удалённом сервере через SSH. Аналог Throne/Nekoray, но без GUI — только командная строка.

## Возможности

- Загрузка прокси из текстовых файлов с URI (`vless://`, `vmess://`, `ss://`, `trojan://`, `hysteria2://`)
- Библиотека прокси с фильтрацией по протоколу и стране
- Переключение активного прокси одной командой
- Режим SOCKS5/HTTP (порты 7890/7891/7892), TUN (прозрачный прокси) и System Proxy (GNOME + `/etc/environment`)
- Bypass-роутинг: внутренний трафик напрямую, зарубежный через прокси (geoip + geosite rule-sets)
- Настраиваемый DNS-сервер (plain, DoT, DoH)
- Clash API для подключения веб-дашбордов (Yacd, Metacubex)
- Тест задержки (TCP) и end-to-end проверка через прокси
- Единый Python-файл — деплой через `scp`

## Требования

- Python 3.8+ (на сервере)
- Ubuntu 20.04+ с systemd
- `requests` (опционально, для `test-active`)

## Установка

```bash
# Скопировать скрипт на сервер
scp proxyctl.py user@server:/usr/local/bin/proxyctl
ssh user@server 'chmod +x /usr/local/bin/proxyctl'

# Установить sing-box и настроить systemd
ssh user@server 'sudo proxyctl install'
```

`proxyctl install` скачивает последний релиз sing-box с GitHub, устанавливает его в `/usr/local/bin/sing-box` и создаёт службу systemd.

## Использование

### Добавить прокси

```bash
# Из файла (по одному URI на строку)
proxyctl add proxies.txt

# Одиночный URI
proxyctl add "vless://uuid@host:443?security=reality&...#tag"
```

### Просмотр библиотеки

```bash
proxyctl list                     # таблица: ID | протокол | страна | тег | хост
proxyctl list --protocol vless    # фильтр по протоколу
proxyctl list --country RU        # фильтр по стране (из флага в теге)
proxyctl show 3                   # полные параметры прокси #3
```

### Активация

```bash
proxyctl use 5                         # переключиться на прокси #5 (system proxy включается автоматически)
proxyctl use 5 --mode tun              # то же, но в TUN-режиме
proxyctl use 5 --bypass ru             # bypass: трафик в RU напрямую, остальное через прокси
proxyctl use 5 --bypass ru,cn          # несколько стран
proxyctl use 5 --bypass off            # выключить bypass
proxyctl use 5 --dns 8.8.8.8          # свой DNS-сервер
proxyctl use 5 --dns tls://1.1.1.1    # DNS over TLS
proxyctl use 5 --dns off               # вернуть DNS по умолчанию
proxyctl use 5 --clash-api on         # включить Clash API на :9090
proxyctl use 5 --clash-api off        # выключить
proxyctl status                        # активный прокси + все настройки
```

Флаги `--bypass`, `--dns`, `--clash-api` **сохраняются в state** — при следующем `proxyctl use <id>` они наследуются автоматически.

### Тестирование

```bash
proxyctl test 3                   # TCP-задержка до сервера прокси #3
proxyctl test-all                 # таблица задержек для всех прокси
proxyctl test-all --timeout 3     # с кастомным таймаутом
proxyctl test-active              # HTTP-запрос через активный прокси
```

### Bypass-роутинг

Маршрутизирует трафик по стране: внутренний — напрямую, зарубежный — через прокси. Использует бинарные rule-sets от SagerNet (geoip + geosite), которые sing-box скачивает и обновляет автоматически раз в сутки.

```bash
proxyctl use 5 --bypass ru        # RU-трафик напрямую
proxyctl use 5 --bypass ru,cn     # RU и CN напрямую
proxyctl use 5 --bypass off       # весь трафик через прокси
```

### DNS

```bash
proxyctl use 5 --dns 8.8.8.8          # Google DNS
proxyctl use 5 --dns tls://1.1.1.1    # Cloudflare DoT
proxyctl use 5 --dns https://dns.google/dns-query  # DoH
proxyctl use 5 --dns off               # DNS по умолчанию (системный)
```

### Clash API

Включает REST API, совместимый с Clash-клиентами. Позволяет подключить веб-дашборд для мониторинга трафика и управления прокси в реальном времени.

```bash
proxyctl use 5 --clash-api on    # включить API на 127.0.0.1:9090
proxyctl use 5 --clash-api off   # выключить
```

Дашборды: [Yacd](https://yacd.haishan.me/?hostname=127.0.0.1&port=9090), [Metacubex](https://metacubex.github.io/metacubex/?hostname=127.0.0.1&port=9090)

### System Proxy

Автоматически настраивает системный прокси при `proxyctl use` и снимает при `proxyctl stop`. Работает через два механизма одновременно:

- **GNOME gsettings** — браузеры (Chrome, Firefox) и GTK-приложения подхватывают сразу
- **/etc/environment** — переменные `http_proxy`/`HTTP_PROXY` для новых терминальных сессий и CLI-инструментов

```bash
proxyctl sysproxy on              # включить вручную
proxyctl sysproxy off             # выключить вручную
proxyctl sysproxy status          # текущее состояние (GNOME + /etc/environment)
```

### Управление службой

```bash
proxyctl start
proxyctl stop                     # останавливает прокси и снимает system proxy
proxyctl restart
proxyctl logs                     # последние 50 строк из journald
```

### TUN-режим

```bash
proxyctl tun on                   # включить прозрачный прокси (требует root)
proxyctl tun off                  # выключить, вернуться в SOCKS/HTTP
```

### Удаление прокси

```bash
proxyctl remove 3                 # удалить прокси #3
proxyctl remove 1 2 5             # удалить несколько
proxyctl remove --all             # очистить всю библиотеку
proxyctl remove --protocol vmess  # удалить все VMess
proxyctl remove --country RU      # удалить все прокси с флагом RU
```

## Форматы URI

```
vless://UUID@host:port?params#tag
vmess://BASE64_JSON
trojan://password@host:port?params#tag
ss://BASE64@host:port#tag
ss://METHOD:PASSWORD@host:port#tag
hysteria2://password@host:port?params#tag
```

Страна определяется автоматически из флага-эмодзи в теге (`🇷🇺 RUS`, `🇹🇷 TUR`, и т.д.).

## Структура файлов на сервере

```
~/.config/proxyctl/
├── proxies.json      # библиотека прокси
└── state.json        # активный прокси и режим

/etc/sing-box/
└── active.json       # текущий конфиг sing-box

/usr/local/bin/
├── sing-box          # бинарник sing-box
└── proxyctl          # этот скрипт
```

## Порты

| Порт | Тип |
|------|-----|
| 7890 | HTTP proxy |
| 7891 | SOCKS5 proxy |
| 7892 | Mixed (HTTP + SOCKS5) |
| tun0 | TUN-устройство (только в TUN-режиме) |

## Разработка

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

100 тестов покрывают парсеры URI, библиотеку прокси, генератор конфигов (bypass/DNS/Clash API), CLI-команды и system proxy.
