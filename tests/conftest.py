import pytest
from pathlib import Path

VLESS_REALITY = (
    "vless://50b95deb-6394-46c5-b88a-583e5b3ca7ee@fastcon-tgg.harknmav.fun:443"
    "?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality"
    "&sni=ads.x5.ru&fp=chrome&pbk=PGccrEdFmBaB1rQFJqM-a9jJ1pFsxhUP2sD9KTw5Oz4"
    "&sid=f69d7af2d5fc5e0c#⬜\U0001f1f7\U0001f1fa RUS vless-reality"
)

VLESS_WS = (
    "vless://ce069292-c8bf-40dd-a6b1-87818a1e64e9@195.245.241.135:443"
    "?sni=gogo.wknm.dpdns.org&type=ws&host=gogo.wknm.dpdns.org"
    "&path=/fp%3Dchrome&security=tls#\U0001f1f7\U0001f1fa RUS vless-ws"
)

VLESS_TLS_TCP = (
    "vless://75807638-6f19-0fa0-ae08-38492ee85c88@eu.active-engine.ru:52006"
    "?allowInsecure=1&encryption=none&flow=xtls-rprx-vision&security=tls"
    "&sni=eu.active-engine.ru&type=tcp#\U0001f1f9\U0001f1f7 TUR vless-tls"
)

SS_B64 = (
    "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp1c09qQVFYbXlScWNZOGFSQVZGZ2hueVJS"
    "@83.166.250.6:51287#SS_test"
)

TROJAN = "trojan://mypassword@1.2.3.4:443?sni=example.com&allowInsecure=1#trojan-test"

HYSTERIA2 = "hysteria2://mypassword@1.2.3.4:443?sni=example.com&insecure=1#hy2-test"


@pytest.fixture
def tmp_library(tmp_path, monkeypatch):
    """ProxyLibrary backed by a temp file."""
    import proxyctl
    lib_path = tmp_path / "proxies.json"
    monkeypatch.setattr(proxyctl, "PROXIES_FILE", lib_path)
    monkeypatch.setattr(proxyctl, "STATE_FILE", tmp_path / "state.json")
    monkeypatch.setattr(proxyctl, "CONFIG_DIR", tmp_path)
    return lib_path
