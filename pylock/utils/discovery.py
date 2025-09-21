import socket
import json
from pathlib import Path

DISCOVERY_PORT = 9999
CACHE_FILE = Path.home() / ".audit_server_url"


def discover_server(timeout: int = 60) -> str | None:
    """
    Слушает UDP broadcast и ждёт сообщение HI от сервера.
    Если найден — сохраняет в ~/.audit_server_url и возвращает URL.
    """

    # если уже кэшировали сервер
    if CACHE_FILE.exists():
        url = CACHE_FILE.read_text().strip()
        if url:
            print(f"[AGENT] Использую сохранённый сервер: {url}")
            return url

    print(f"[AGENT] Сервер не найден, слушаю UDP {DISCOVERY_PORT}...")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", DISCOVERY_PORT))
    sock.settimeout(timeout)

    try:
        while True:
            data, addr = sock.recvfrom(4096)
            print(f"[AGENT][DEBUG] Получено сообщение от {addr}: {data!r}")
            try:
                msg = json.loads(data.decode())
                print(f"[AGENT][DEBUG] Декодировано: {msg}")
                if msg.get("service") == "audit" and "url" in msg:
                    url = msg["url"]

                    # если сервер изменился — обновим кэш
                    if not CACHE_FILE.exists() or CACHE_FILE.read_text().strip() != url:
                        CACHE_FILE.write_text(url)

                    print(f"[AGENT] Найден сервер {url} от {addr[0]}")
                    return url
            except json.JSONDecodeError:
                print("[AGENT][DEBUG] Не удалось распарсить JSON")
                continue
    except socket.timeout:
        print("[AGENT] Сервер не найден (timeout)")
        return None
