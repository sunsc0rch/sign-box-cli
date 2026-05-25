# proxyctl

Инструмент управления прокси на базе [sing-box](https://github.com/SagerNet/sing-box) для удалённого сервера. Интерактивный TUI-интерфейс в терминале + полный набор CLI-команд. Работает по SSH без GUI.

## Возможности

- **Интерактивный TUI** — запускается командой `proxyctl`, навигация клавишами
- Загрузка прокси из текстовых файлов с URI (`vless://`, `vmess://`, `ss://`, `trojan://`, `hysteria2://`)
- Библиотека прокси с фильтрацией по протоколу и стране
- Режим SOCKS5/HTTP (порты 7890/7891/7892), TUN (прозрачный прокси) и System Proxy (GNOME + `/etc/environment`)
- Bypass-роутинг: внутренний трафик напрямую, зарубежный через прокси (geoip + geosite rule-sets)
- Настраиваемый DNS-сервер (plain, DoT, DoH) — по умолчанию `tls://1.1.1.1`
- uTLS fingerprint (chrome, firefox, safari) для обхода TLS-детектирования — по умолчанию `chrome`
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

### Интерактивный TUI

Запуск без аргументов открывает полноэкранный интерфейс с навигацией по клавишам. Работает в любом терминале и по SSH.

```bash
proxyctl
```

```
 proxyctl  |  sing-box: active  |  mode: socks  |  3 proxies
──────────────────────────────────────────────────────────────────────
●   227  vless    RU  +++RUS Timeweb             195.209.82.149:443   23ms
▶   228  vmess    DE  Berlin proxy               1.2.3.4:443            --
    229  ss       NL  Amsterdam node             5.6.7.8:8080          41ms
──────────────────────────────────────────────────────────────────────
 ↑↓/jk: navigate   U/Enter: use   T: test   D: delete   Q: quit
```

| Клавиша | Действие |
|---------|----------|
| `↑` `↓` / `j` `k` | навигация по списку |
| `Page Up` / `Page Down` | листать постранично |
| `Space` | отметить/снять прокси для удаления (курсор переходит вниз) |
| `U` / `Enter` | активировать выбранный прокси |
| `T` | проверить latency выбранного (TCP-тест, не блокирует UI) |
| `A` | протестировать все прокси параллельно — показывает live-прогресс |
| `F` | удалить все прокси с результатом FAIL (требует предварительного `A` или `T`) |
| `D` | удалить — если есть отмеченные, удаляет все сразу; иначе только текущий |
| `Esc` | сбросить выделение (если есть отметки) или выйти |
| `Q` | выйти |

`●` — активный прокси (зелёный), `▶` — курсор, `*` — отмечен для удаления (жёлтый). При наличии отмеченных элементов шапка показывает их количество, футер меняется на подсказки режима выделения. При активации TUI временно сворачивается, показывает вывод команды, и возвращается по Enter.

Типичный воркфлоу очистки: `A` → ждём результатов → `F` → подтвердить `F`.

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
proxyctl use 5 --dns off               # вернуть DNS по умолчанию (системный)
proxyctl use 5 --utls chrome           # uTLS fingerprint: chrome / firefox / safari / random
proxyctl use 5 --utls off             # выключить uTLS
proxyctl use 5 --clash-api on         # включить Clash API на :9090
proxyctl use 5 --clash-api off        # выключить
proxyctl status                        # активный прокси + все настройки
```

Флаги `--bypass`, `--dns`, `--utls`, `--clash-api` **сохраняются в state** — при следующем `proxyctl use <id>` они наследуются автоматически.

По умолчанию при первом запуске: `dns=tls://1.1.1.1`, `utls=chrome`, `sysproxy=on`.

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

### uTLS

Подменяет TLS fingerprint на браузерный, скрывая от DPI и прокси-бэкендов, что соединение установлено не браузером. Особенно важно для прокси через Cloudflare Workers и CDN-фронтенды.

```bash
proxyctl use 5 --utls chrome    # Chrome fingerprint (по умолчанию)
proxyctl use 5 --utls firefox   # Firefox fingerprint
proxyctl use 5 --utls safari    # Safari fingerprint
proxyctl use 5 --utls random    # случайный при каждом подключении
proxyctl use 5 --utls off       # отключить
```

Если URI содержит параметр `fp=` (например `fp=chrome`), он имеет приоритет над глобальным флагом. При включённом `--utls` для VLESS автоматически добавляется `packet_encoding: xudp`.

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
proxyctl remove 1 2 5             # удалить несколько по ID
proxyctl remove 1-5               # удалить диапазон (с 1 по 5 включительно)
proxyctl remove 1-5 8 10          # диапазон + отдельные ID
proxyctl remove --all             # очистить всю библиотеку
proxyctl remove --protocol vmess  # удалить все VMess
proxyctl remove --country RU      # удалить все прокси с флагом RU
```

В TUI: пометить нужные прокси клавишей `Space`, затем `D` для удаления всех отмеченных сразу.

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

114 тестов покрывают парсеры URI, библиотеку прокси, генератор конфигов (bypass/DNS/uTLS/Clash API), CLI-команды и system proxy.
