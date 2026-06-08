#!/usr/bin/env python3
import json, socket, sys

CONFIG = '/etc/sing-box/active.json'
DNS_EXCLUDES = ['8.8.8.8/32', '8.8.4.4/32', '1.1.1.1/32', '1.0.0.1/32']

def is_ip(s):
    for af in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(af, s)
            return True
        except:
            pass
    return False

try:
    with open(CONFIG) as f:
        d = json.load(f)
except Exception as e:
    print(f'[tun-patch] cannot read config: {e}', file=sys.stderr)
    sys.exit(0)

changed = False

# Get proxy server IP (to ensure it's excluded from TUN)
proxy_ip = None
for o in d.get('outbounds', []):
    if o.get('type') in ('vless', 'shadowsocks', 'trojan', 'vmess', 'hysteria2') and o.get('server'):
        host = o['server']
        if is_ip(host):
            proxy_ip = host
        else:
            try:
                proxy_ip = socket.gethostbyname(host)
                print(f'[tun-patch] resolved proxy {host} -> {proxy_ip}')
            except:
                pass
        break

for inb in d.get('inbounds', []):
    if inb.get('type') != 'tun':
        continue
    # stack = gvisor
    if inb.get('stack') != 'gvisor':
        inb['stack'] = 'gvisor'
        changed = True
    inb.pop('mtu', None)

    # Fix exclude list
    excludes = inb.get('route_exclude_address', [])
    new_excludes = []
    for e in excludes:
        host = e.split('/')[0]
        if is_ip(host):
            new_excludes.append(e)
        else:
            try:
                ip = socket.gethostbyname(host)
                new_excludes.append(ip + '/32')
                changed = True
                print(f'[tun-patch] resolved {host} -> {ip}')
            except:
                print(f'[tun-patch] WARNING: skip unresolvable {e}')
                changed = True

    for dns in DNS_EXCLUDES:
        if dns not in new_excludes:
            new_excludes.append(dns)
            changed = True

    if proxy_ip and f'{proxy_ip}/32' not in new_excludes:
        new_excludes.append(f'{proxy_ip}/32')
        changed = True

    inb['route_exclude_address'] = new_excludes

route = d.setdefault('route', {})
if not route.get('auto_detect_interface'):
    route['auto_detect_interface'] = True
    changed = True

if changed:
    with open(CONFIG, 'w') as f:
        json.dump(d, f, indent=2, ensure_ascii=False)
    print('[tun-patch] config patched OK')
else:
    print('[tun-patch] config already correct')
