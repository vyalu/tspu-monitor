#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ТСПУ-монитор — веб-сервис.
Постоянно проверяет доступность ресурсов из сети, где запущен, определяет тип
блокировки (DNS / IP / SNI / TCP 16-20 / заглушка / белые списки), замечает замедление,
проблемы HTTP/3 и ECH и отдаёт веб-интерфейс.

Только стандартная библиотека Python 3.10+.
Переменные окружения:
  PORT        — порт веб-интерфейса (по умолчанию 8080)
  DATA_DIR    — где хранить настройки и историю (по умолчанию /data)
  BASIC_AUTH  — "логин:пароль", если нужен вход по паролю (по умолчанию без пароля)
  ALT_DNS     — альтернативный DNS для сверки (по умолчанию Яндекс DNS)
  GLOBALPING_TOKEN — токен Globalping, если бесплатного лимита не хватит (необязательно)
"""
import base64
import csv
import datetime as dt
import hashlib
import hmac
import http.cookies
import io
import ipaddress
import json
import os
import random
import re
import secrets
import shutil
import socket
import sqlite3
import ssl
import struct
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import quic

DATA_DIR = os.environ.get("DATA_DIR", "/data")
PORT = int(os.environ.get("PORT", "8080"))
AUTH = os.environ.get("BASIC_AUTH", "").strip()
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
try:
    VERSION = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "VERSION")).read().strip()
except OSError:
    VERSION = "dev"
ALT_DNS = os.environ.get("ALT_DNS", "77.88.8.8")
ALT_DNS_NAME = os.environ.get("ALT_DNS_NAME", "Яндекс DNS" if ALT_DNS.startswith("77.88.8.") else f"DNS {ALT_DNS}")
GLOBALPING_TOKEN = os.environ.get("GLOBALPING_TOKEN", "").strip()
DEFAULT_USER, DEFAULT_PASS = "admin", "admin"   # создаются при первом запуске, меняются в настройках
PBKDF2_ITER = 200_000
SESSION_TTL = 7 * 86400          # вход действует 7 дней
COOKIE = "tspu_session"
LOGIN_MAX_FAILS, LOGIN_WINDOW = 5, 600   # 5 неудачных попыток → пауза 10 минут
IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
DIAG_GAP = 120         # ручной запуск: не чаще раза в 2 минуты на ресурс
DIAG_GAP_ALERT = 600   # по тревоге: не чаще раза в 10 минут на ресурс (если ресурс «мигает»)
GP_PER_HOUR = 20       # Globalping: не больше 20 замеров в час (≈140 узлов, бесплатный лимит больше)

MAX_READ = 64 * 1024
STALL_MIN, STALL_MAX = 10_000, 30_000
SPARK_HOURS, SPARK_BUCKETS = 6, 36
KEEP_DAYS = 35

# Контрольные сайты: разные компании и разные сети (AS), чтобы сбой одного не путал вывод.
# Российские — те, что обычно попадают в белые списки; зарубежные — те, что в обычное время
# открываются из России без обходов.
CONTROLS = [
    ("c-ya", "ru", "Яндекс", "https://ya.ru/"),
    ("c-gu", "ru", "Госуслуги", "https://www.gosuslugi.ru/"),
    ("c-vk", "ru", "VK", "https://vk.com/"),
    ("c-sb", "ru", "Сбербанк", "https://www.sberbank.ru/"),
    ("c-oz", "ru", "Ozon", "https://www.ozon.ru/"),
    ("c-wb", "ru", "Wildberries", "https://www.wildberries.ru/"),
    ("c-go", "foreign", "Google", "https://www.google.com/"),
    ("c-cf", "foreign", "Cloudflare", "https://www.cloudflare.com/"),
    ("c-gh", "foreign", "GitHub", "https://github.com/"),
    ("c-ms", "foreign", "Microsoft", "https://www.microsoft.com/"),
    ("c-ap", "foreign", "Apple", "https://www.apple.com/"),
    ("c-py", "foreign", "Python.org", "https://www.python.org/"),
]
# Голосование большинством: «работают» — не меньше 75 %, «лежат» — работают не больше 25 %
MOSTLY_UP, MOSTLY_DOWN = 0.75, 0.25

PENDING, OK, SMALL, DNS, DNS_SPOOF, IP, REFUSED, SNI, CERT, S1620, STALL, ERR, DENIED, HTTP_ERR, STUB = (
    "PENDING", "OK", "OK_SMALL", "DNS", "DNS_SPOOF", "IP_BLOCK", "REFUSED", "SNI_BLOCK",
    "FAKE_CERT", "TCP_16_20", "STALL", "ERROR", "HTTP_DENIED", "HTTP_ERROR", "HTTP_STUB")
LABELS = {
    PENDING: "проверяется…", OK: "работает", SMALL: "работает",
    DNS: "не резолвится DNS", DNS_SPOOF: "адрес из вашего DNS не работает, другой работает", IP: "нет соединения: блок по IP / белый список",
    REFUSED: "соединение отклонено", SNI: "обрыв на TLS: блок по SNI",
    CERT: "подменённый сертификат (заглушка?)", S1620: "замирает после ~16–20 КБ: TCP 16-20",
    STALL: "данные перестали идти", ERR: "ошибка",
    DENIED: "сервер отказал в доступе (HTTP 403/451)", HTTP_ERR: "сервер ответил ошибкой HTTP",
    STUB: "заглушка о блокировке вместо сайта",
}
# Предупреждения: сайт открывается, но что-то не так. Тревогу не поднимают.
WARN_ECH, WARN_QUIC, WARN_SLOW, WARN_CHANGED = "ECH", "QUIC", "SLOW", "CHANGED"
WARN_NAMES = {WARN_ECH: "сайт публикует ECH", WARN_QUIC: "HTTP/3 (QUIC) не проходит",
              WARN_SLOW: "замедление", WARN_CHANGED: "ответ не похож на обычный"}
EXTRA_TTL = 1800       # запись HTTPS в DNS (ECH, h3) перечитываем раз в 30 минут
QUIC_TTL = 600         # QUIC проверяем не чаще раза в 10 минут на адрес
SPEED_MIN_BYTES = 24 * 1024   # скорость считаем, только если после первого куска пришло столько данных
# Заглушки провайдеров и РКН: перенаправление на страницу блокировки или её текст в ответе
STUB_URL_RE = re.compile(r"(?i)(zapret|blocked|blocklist|restrict|eais|rkn\.gov|warning\.rt\.ru|/block\b)")
STUB_MAX = 48 * 1024   # страницы-заглушки маленькие; большие страницы с этими словами — обычные статьи
MAX_REDIRECTS = 5
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")
GOOD = {OK, SMALL}

now_ms = lambda: int(time.time() * 1000)


def log(*a):
    print(dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), *a, flush=True)


# ---------------------------------------------------------------- проверка
def parse_url(s):
    """Домен или URL → проверка HTTPS/HTTP; голый IP или IP:порт (или tcp://…) → проверка TCP-соединения."""
    s = (s or "").strip()
    if not s or s.startswith("#"):
        return None
    if "://" not in s:
        s = ("tcp://" if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?/?$", s) else "https://") + s
    try:
        u = urllib.parse.urlsplit(s)
        port = u.port
    except ValueError:
        return None
    if not u.hostname or u.scheme not in ("http", "https", "tcp"):
        return None
    if u.scheme == "tcp":
        port = port or 443
        return dict(url=f"tcp://{u.hostname.lower()}:{port}", scheme="tcp", host=u.hostname.lower(), port=port, path="/")
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    url = urllib.parse.urlunsplit((u.scheme, u.netloc.lower(), u.path or "/", u.query, ""))
    return dict(url=url, scheme=u.scheme, host=u.hostname.lower(),
                port=port or (443 if u.scheme == "https" else 80), path=path)


def is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
    except ValueError:
        return False


def dns_records(host, qtype=1, server=None, timeout=3):
    """Простой DNS-запрос напрямую к указанному серверу (UDP/53) → [(тип, rdata)]. [] — имени нет."""
    server = server or ALT_DNS
    qid = random.randint(0, 0xFFFF)
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for part in host.encode("idna").split(b"."):
        if part:
            q += bytes([len(part)]) + part
    q += b"\x00" + struct.pack(">HH", qtype, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(q, (server, 53))
        data, _ = s.recvfrom(4096)
    finally:
        s.close()
    rid, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    if rid != qid:
        raise OSError("неверный ответ DNS")
    rcode = flags & 0xF
    if rcode == 3:
        return []
    if rcode != 0:
        raise OSError(f"DNS rcode {rcode}")

    def skip(off):
        while True:
            ln = data[off]
            if ln == 0:
                return off + 1
            if ln & 0xC0 == 0xC0:
                return off + 2
            off += ln + 1

    off = 12
    for _ in range(qd):
        off = skip(off) + 4
    out = []
    for _ in range(an):
        off = skip(off)
        typ, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        out.append((typ, data[off:off + rdlen]))
        off += rdlen
    return out


def dns_query(host, server=None, timeout=3):
    """Адреса IPv4 (запись A) от указанного DNS. [] — имени нет."""
    return [socket.inet_ntoa(r) for typ, r in dns_records(host, 1, server, timeout) if typ == 1 and len(r) == 4]


def system_dns():
    """Первый DNS-сервер системы (в Docker — встроенный 127.0.0.11), иначе альтернативный."""
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                p = line.split()
                if len(p) >= 2 and p[0] == "nameserver" and IP_RE.match(p[1]):
                    return p[1]
    except OSError:
        pass
    return ALT_DNS


def dns_https(host):
    """Запись HTTPS (тип 65): какие протоколы объявлены (alpn) и опубликован ли ключ ECH."""
    info = dict(alpn=[], ech=False)
    for server in (system_dns(), ALT_DNS):
        try:
            recs = dns_records(host, 65, server)
            break
        except Exception:
            recs = None
    for typ, r in recs or []:
        if typ != 65 or len(r) < 3 or r[:2] == b"\x00\x00":   # приоритет 0 — псевдоним, параметров нет
            continue
        off = 2
        while off < len(r) and r[off]:
            off += r[off] + 1
        off += 1
        while off + 4 <= len(r):
            key, ln = struct.unpack(">HH", r[off:off + 4])
            val = r[off + 4:off + 4 + ln]
            off += 4 + ln
            if key == 1:      # alpn
                i = 0
                while i < len(val):
                    info["alpn"].append(val[i + 1:i + 1 + val[i]].decode("ascii", "replace"))
                    i += 1 + val[i]
            elif key == 5:    # ech
                info["ech"] = True
    return info


def alt_resolve(host):
    """Адреса через альтернативный DNS; None — если сам DNS не ответил."""
    try:
        return dns_query(host)
    except Exception:
        return None


def probe(t, ip, timeout, t0=None):
    """Шаги 2–4: TCP, TLS (здесь виден SNI), загрузка данных — к конкретному IP."""
    t0 = t0 or time.monotonic()
    res = dict(status=ERR, detail="", ms=None)
    try:
        sock = socket.create_connection((ip, t["port"]), timeout=timeout)
    except socket.timeout:
        res.update(status=IP, detail=f"{ip}: таймаут TCP-соединения")
        return res
    except ConnectionRefusedError:
        res.update(status=REFUSED, detail=f"{ip}:{t['port']}")
        return res
    except OSError as e:
        res.update(status=IP, detail=f"{ip}: {e}")
        return res

    if t["scheme"] == "tcp":
        sock.close()
        res.update(status=OK, ms=int((time.monotonic() - t0) * 1000), detail="TCP-соединение установлено")
        return res

    if t["scheme"] == "https":
        try:
            sock.settimeout(timeout)
            ctx = ssl.create_default_context()
            by_ip = bool(IP_RE.match(t["host"]))
            if by_ip:   # по голому IP имени сайта нет: SNI не отправляется, сертификат по имени не сверить
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=None if by_ip else t["host"])
        except ssl.SSLCertVerificationError as e:
            sock.close()
            res.update(status=CERT, detail=str(e)[:160])
            return res
        except (socket.timeout, ConnectionResetError, ssl.SSLError, OSError) as e:
            sock.close()
            res.update(status=SNI, detail=f"{type(e).__name__}: {str(e)[:110]}")
            return res

    req = (f"GET {t['path']} HTTP/1.1\r\nHost: {t['host']}\r\n"
           f"User-Agent: {BROWSER_UA}\r\n"
           "Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\nAccept-Language: ru-RU,ru;q=0.9,en;q=0.8\r\n"
           "Accept-Encoding: identity\r\nConnection: close\r\n\r\n")
    got, broke, head = 0, None, b""
    t_first = first_len = None
    try:
        sock.settimeout(timeout)
        sock.sendall(req.encode())
        while got < MAX_READ:
            chunk = sock.recv(16384)
            if not chunk:
                break
            if t_first is None:
                t_first, first_len = time.monotonic(), len(chunk)
            if len(head) < 16384:
                head += chunk[:16384 - len(head)]
            got += len(chunk)
    except socket.timeout:
        broke = "таймаут"
    except (ConnectionResetError, ssl.SSLError, OSError) as e:
        broke = type(e).__name__
    finally:
        try:
            sock.close()
        except Exception:
            pass

    res["ms"] = int((time.monotonic() - t0) * 1000)
    hdr = head.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
    m = re.match(r"HTTP/\d(?:\.\d)? (\d{3})", hdr)
    res["http"] = int(m.group(1)) if m else None
    loc = re.search(r"(?im)^location:[ \t]*(\S+)", hdr)
    res["location"] = loc.group(1).strip() if loc else None
    res["altsvc_h3"] = bool(re.search(r"(?im)^alt-svc:.*\bh3(?:-\d+)?=", hdr))
    res["size"] = got
    if not broke and t_first is not None and got - first_len >= SPEED_MIN_BYTES:
        res["kbps"] = round((got - first_len) * 8 / max(time.monotonic() - t_first, 0.001) / 1000)
    body = head.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in head else b""
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        text = body.decode("cp1251", "replace")
    m = re.search(r"(?is)<title[^>]*>(.*?)</title>", text)
    res["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else None
    stub = stub_reason(t, res, text.lower(), got)
    if stub and not (broke and got == 0):
        res.update(status=STUB, detail=stub)
        return res
    if broke:
        if got == 0:
            res.update(status=STALL, detail=f"нет ответа после соединения ({broke})")
        elif STALL_MIN <= got <= STALL_MAX:
            res.update(status=S1620, detail=f"получено {got // 1024} КБ, потом {broke}")
        else:
            res.update(status=STALL, detail=f"получено {got // 1024} КБ, потом {broke}")
    elif got >= STALL_MIN:
        res.update(status=OK)
    else:
        res.update(status=SMALL, detail=f"ответ всего {max(1, got // 1024)} КБ — TCP 16-20 по нему не проверить, укажите адрес большого файла")
    return res


def stub_reason(t, res, low, got):
    """Признаки страницы блокировки. Возвращает пояснение или None."""
    loc = res.get("location")
    if loc and 300 <= (res.get("http") or 0) < 400:
        try:
            lh = (urllib.parse.urlsplit(loc).hostname or "").lower()
        except ValueError:
            lh = ""
        same = not lh or lh == t["host"] or lh.endswith("." + t["host"]) or t["host"].endswith("." + lh)
        if not same and STUB_URL_RE.search(loc):
            return f"перенаправление на страницу блокировки: {loc[:120]}"
    if got <= STUB_MAX and low:
        rkn = "rkn.gov.ru" in low or "роскомнадзор" in low or "149-фз" in low or "единый реестр" in low
        limited = any(w in low for w in ("ограничен", "заблокирован", "блокировк", "запрещ"))
        if rkn and limited:
            title = f": «{res['title']}»" if res.get("title") else ""
            return f"в ответе текст о блокировке по решению РКН{title}"
    return None


def http_verdict(res):
    """Код ответа сервера → статус. Вызывается только когда данные пришли без обрыва."""
    code = res.get("http")
    if code in (403, 451):
        why = "недоступно по юридическим причинам" if code == 451 else "возможна геоблокировка или защита от ботов"
        res.update(status=DENIED, detail=f"HTTP {code}: {why}")
    elif code in (404, 410):
        res.update(status=HTTP_ERR, detail=f"HTTP {code}: страница не найдена — проверьте адрес")
    elif code and code >= 500:
        res.update(status=HTTP_ERR, detail=f"HTTP {code}: ошибка на стороне сервера")
    return res


_extra_cache, _extra_lock = {}, threading.Lock()


def _cached(key, ttl, fn):
    with _extra_lock:
        hit = _extra_cache.get(key)
        if hit and time.time() - hit[0] < ttl:
            return hit[1]
    val = fn()
    with _extra_lock:
        _extra_cache[key] = (time.time(), val)
        if len(_extra_cache) > 2000:
            _extra_cache.clear()
    return val


def extras(t, res, opts):
    """Дополнительные проверки рабочего сайта: ECH и HTTP/3. Дают предупреждения, не тревогу."""
    warn = []
    info = _cached(("https", t["host"]), EXTRA_TTL, lambda: dns_https(t["host"]))
    if opts.get("ech") and info["ech"]:
        warn.append(dict(code=WARN_ECH, text="сайт публикует ECH (шифрованное имя): браузер с ECH может "
                                             "не открыть его, хотя у монитора проверка проходит"))
    h3 = res.get("altsvc_h3") or "h3" in info["alpn"]
    res["h3"] = None
    if opts.get("quic") and h3 and res.get("ip"):
        def run():
            try:
                return quic.probe(res["ip"], t["host"], t["port"], timeout=3)
            except OSError:
                return None
        ok = _cached(("quic", t["host"], res["ip"], t["port"]), QUIC_TTL, run)
        if ok is not None:
            res["h3"] = "ok" if ok else "fail"
        if ok is False:
            warn.append(dict(code=WARN_QUIC, text="HTTP/3 (QUIC, UDP 443) не проходит: браузер откатится на обычное "
                                                  "соединение, первая загрузка может тормозить"))
    res["warn"] = warn
    return res


def check(t, timeout, opts=None):
    """Полная проверка ресурса пользователя: как check_one, но идём по перенаправлениям
    до конечной страницы (как браузер) и учитываем код ответа сервера."""
    opts = opts or {}
    t0 = time.monotonic()
    res = check_one(t, timeout)
    if t.get("group") not in (None, "user") or t["scheme"] == "tcp" or res["status"] not in GOOD:
        return res
    chain = []
    cur, seen = t, {t["url"]}
    while 300 <= (res.get("http") or 0) < 400 and res.get("location") and len(chain) < MAX_REDIRECTS:
        base = f"{cur['scheme']}://{cur['host']}" + (f":{cur['port']}" if cur["port"] not in (80, 443) else "") + cur["path"]
        nxt = parse_url(urllib.parse.urljoin(base, res["location"]))
        if not nxt or nxt["scheme"] == "tcp" or nxt["url"] in seen:
            break
        seen.add(nxt["url"])
        chain.append(nxt["host"] + (f":{nxt['port']}" if nxt["port"] not in (80, 443) else "")
                     + (nxt["path"] if nxt["path"] != "/" else ""))
        cur = dict(nxt, group=t.get("group"))
        res = check_one(cur, timeout)
        if res["status"] not in GOOD:
            break
    if res["status"] in GOOD:
        http_verdict(res)
    if res["status"] in GOOD and 300 <= (res.get("http") or 0) < 400:
        res.update(status=HTTP_ERR, detail="перенаправления зациклились или их больше " + str(MAX_REDIRECTS))
    if res["status"] in GOOD and cur["scheme"] == "https":
        try:
            extras(cur, res, opts)
        except Exception as e:
            log("доп. проверки", cur["host"], e)
    if chain:
        res["ms"] = int((time.monotonic() - t0) * 1000) if res.get("ms") is not None else None
        via = "после перенаправления на " + " → ".join(chain)
        res["detail"] = (via + (": " + res["detail"] if res.get("detail") else "")) if res["status"] not in GOOD \
            else (via + (" · " + res["detail"] if res.get("detail") else ""))
    return res


def check_one(t, timeout):
    """Проверка одного адреса: системный DNS → probe; при сбое сверяемся с альтернативным DNS."""
    t0 = time.monotonic()
    try:
        ip = socket.getaddrinfo(t["host"], t["port"], socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    except (socket.gaierror, UnicodeError) as e:
        alt = alt_resolve(t["host"])
        detail = f"системный DNS: {e}"
        if alt:
            r2 = probe(t, alt[0], timeout)
            detail += f"; {ALT_DNS_NAME} даёт {alt[0]}" + (" — по нему сайт открывается" if r2["status"] in GOOD else "")
        elif alt == []:
            detail += f"; {ALT_DNS_NAME} тоже не знает такого имени"
        return dict(status=DNS, detail=detail, ms=None)

    res = probe(t, ip, timeout, t0)
    res["ip"] = ip
    if res["status"] in GOOD or is_private(ip) or IP_RE.match(t["host"]):
        return res
    alt = alt_resolve(t["host"])
    if alt and ip not in alt:
        r2 = probe(t, alt[0], timeout)
        if r2["status"] in GOOD:
            return dict(status=DNS_SPOOF, ms=r2["ms"],
                        detail=f"системный DNS даёт {ip} — не работает; {ALT_DNS_NAME} даёт {alt[0]} — работает")
        res["detail"] = (res["detail"] + f" · {ALT_DNS_NAME} даёт другой адрес ({alt[0]}), он тоже не работает").strip(" ·")
    return res


# ---------------------------------------------------------------- диагностика
HOST_RE = re.compile(r"^[a-z0-9.-]{1,253}$")


def traceroute(ip, port, mode):
    """mode: tcp (SYN на порт сайта) или icmp. Возвращает разобранные узлы и сырой вывод."""
    exe = shutil.which("traceroute")
    if not exe:
        return dict(ok=False, error="traceroute не установлен")
    if not re.fullmatch(r"[0-9.]+", ip):
        return dict(ok=False, error="неверный адрес")
    args = [exe, "-n", "-q", "1", "-w", "2", "-m", "20"]
    args += ["-T", "-p", str(int(port))] if mode == "tcp" else ["-I"]
    args.append(ip)
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return dict(ok=False, error="трассировка не уложилась в 2 минуты")
    except OSError as e:
        return dict(ok=False, error=str(e))
    hops = []
    for line in out.stdout.splitlines()[1:]:
        m = re.match(r"\s*(\d+)\s+(\S+)(?:\s+([\d.]+)\s*ms)?", line)
        if m:
            hops.append(dict(n=int(m.group(1)), ip=None if m.group(2) == "*" else m.group(2),
                             ms=float(m.group(3)) if m.group(3) else None))
    if not hops:
        return dict(ok=False, error=(out.stderr or out.stdout or "нет вывода").strip()[:300])
    last = next((h for h in reversed(hops) if h["ip"]), None)
    return dict(ok=True, reached=any(h["ip"] == ip for h in hops), last=last, hops=hops,
                raw=(out.stdout + out.stderr)[-4000:])


def _gp_request(method, url, body=None, timeout=15):
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body else None,
                                 headers={"Content-Type": "application/json", "Accept": "application/json",
                                          "User-Agent": "tspu-monitor"})
    if GLOBALPING_TOKEN:
        req.add_header("Authorization", "Bearer " + GLOBALPING_TOKEN)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def globalping(host, port, scheme):
    """HTTP-проверка с узлов Globalping: 4 в России, 3 за рубежом."""
    body = {
        "type": "http", "target": host,
        "locations": [{"country": "RU", "limit": 4}, {"country": "DE", "limit": 1},
                      {"country": "NL", "limit": 1}, {"country": "FI", "limit": 1}],
        "measurementOptions": {"protocol": "HTTPS" if scheme == "https" else "HTTP", "port": int(port),
                               "request": {"method": "HEAD", "path": "/"}},
    }
    try:
        m = _gp_request("POST", "https://api.globalping.io/v1/measurements", body)
        mid = m["id"]
        for _ in range(45):
            time.sleep(1)
            r = _gp_request("GET", f"https://api.globalping.io/v1/measurements/{urllib.parse.quote(mid)}")
            if r.get("status") != "in-progress":
                break
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read().decode()).get("error", {}).get("message", "")
        except Exception:
            msg = ""
        return dict(ok=False, error=f"Globalping ответил {e.code}{': ' + msg if msg else ''}")
    except Exception as e:
        return dict(ok=False, error=f"Globalping недоступен: {type(e).__name__}: {str(e)[:120]}")
    probes = []
    for it in r.get("results", []):
        p, res = it.get("probe", {}), it.get("result", {})
        code = res.get("statusCode")
        ok = res.get("status") == "finished" and code is not None
        raw = (res.get("rawOutput") or "").strip()
        err = "" if ok else (raw.splitlines()[-1] if raw else (res.get("status") or "ошибка"))[:160]
        probes.append(dict(country=p.get("country", ""), city=p.get("city", ""), network=p.get("network", ""),
                           asn=p.get("asn"), ok=ok, code=code,
                           ms=(res.get("timings") or {}).get("total"), error=err))
    ru = [p for p in probes if p["country"] == "RU"]
    fo = [p for p in probes if p["country"] != "RU"]
    return dict(ok=True, id=mid, probes=probes,
                ru_ok=sum(p["ok"] for p in ru), ru_total=len(ru),
                fo_ok=sum(p["ok"] for p in fo), fo_total=len(fo))


def diag_summary(gp, tr_tcp, tr_icmp, mode=None):
    parts = []
    if gp and gp.get("ok") and (gp["ru_total"] or gp["fo_total"]):
        ru, fo = (gp["ru_ok"], gp["ru_total"]), (gp["fo_ok"], gp["fo_total"])
        tot_ok, tot = ru[0] + fo[0], ru[1] + fo[1]
        if tot_ok == 0:
            v = "не открывается ни из одной точки — похоже, проблема на стороне сервера"
        elif ru[1] and ru[0] == ru[1]:
            v = "с других российских узлов открывается — ограничение на пути из офиса (ваш провайдер / ТСПУ)"
        elif ru[1] and ru[0] == 0:
            v = "ни с одного российского узла не открывается, из-за рубежа открывается — блокировка на уровне страны или сервер не пускает российские IP"
        elif ru[1]:
            v = "с части российских узлов не открывается — ограничение не везде"
        else:
            v = "российских точек для проверки не нашлось"
        parts.append(f"{v} (Россия {ru[0]}/{ru[1]}, за рубежом {fo[0]}/{fo[1]})")
    elif gp and not gp.get("ok"):
        if mode in ("whitelist", "nonet") and "недоступен" in gp.get("error", ""):
            parts.append("проверка из других сетей невозможна: в режиме " +
                         ("белых списков" if mode == "whitelist" else "без интернета") +
                         " внешний сервис недоступен, вывод — по контрольным сайтам")
        else:
            parts.append(gp.get("error", "проверка из других сетей не удалась"))
    if tr_tcp and tr_tcp.get("ok"):
        if tr_tcp["reached"]:
            parts.append("TCP-трассировка дошла до сервера")
        elif tr_tcp.get("last"):
            parts.append(f"TCP-трассировка обрывается после узла {tr_tcp['last']['n']} ({tr_tcp['last']['ip']})")
        else:
            parts.append("TCP-трассировка: ни один узел не ответил")
        if tr_icmp and tr_icmp.get("ok") and tr_icmp["reached"] and not tr_tcp["reached"]:
            parts.append("ICMP при этом доходит — режется именно TCP")
    return "; ".join(parts) or "нет данных"


# ---------------------------------------------------------------- состояние
class Monitor:
    def __init__(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        self.cfg_path = os.path.join(DATA_DIR, "config.json")
        self.lock = threading.RLock()
        self.wake = threading.Event()
        self.db_lock = threading.Lock()
        self.db = sqlite3.connect(os.path.join(DATA_DIR, "history.db"), check_same_thread=False)
        self.db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS checks(tid TEXT, t INTEGER, status TEXT, ms INTEGER);
            CREATE INDEX IF NOT EXISTS checks_tid_t ON checks(tid, t);
            CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY, tid TEXT, start INTEGER,
                                                 end INTEGER, status TEXT, detail TEXT);
            CREATE INDEX IF NOT EXISTS inc_tid ON incidents(tid, start);
            CREATE TABLE IF NOT EXISTS events(t INTEGER, kind TEXT, host TEXT, text TEXT);
            CREATE TABLE IF NOT EXISTS diags(id INTEGER PRIMARY KEY, tid TEXT, t INTEGER, reason TEXT, data TEXT);
            CREATE TABLE IF NOT EXISTS sessions(h TEXT PRIMARY KEY, user TEXT, exp INTEGER);
            CREATE INDEX IF NOT EXISTS diags_tid ON diags(tid, t);
        """)
        self.settings = dict(interval=30, confirm=2, timeout=7, sound=True, popup=True, controls=True,
                             diag_trace=True, diag_global=True,
                             quic=True, ech=True, slow_kbps=300, changed=True)
        self.diag_running = set()
        self.diag_last = {}
        self.gp_times = []
        self.running = True
        self.user = []
        self.ctl = [self._target(cid, g, n, parse_url(u)) for cid, g, n, u in CONTROLS]
        self.checked_at = None
        self.next_at = None
        self.mode = None   # whitelist / nonet / None
        self._need_save = False
        self.auth = None
        self._load()
        if self._need_save:
            self.save()
            log(f"Создана учётная запись по умолчанию: {DEFAULT_USER} / {DEFAULT_PASS} — смените пароль в настройках")
        self._db("DELETE FROM sessions WHERE exp<?", (int(time.time()),))
        self.login_fails = {}

    # --- цели
    def _target(self, tid, group, name, p):
        return dict(p, id=tid, group=group, name=name, status=PENDING, detail="", ms=None,
                    since=now_ms(), fails=0, alerted=False, down_since=None, incident=None,
                    warn=[], wseen={}, h3=None, kbps=None, base=None, cand=0)

    def active(self):
        return self.user + (self.ctl if self.settings["controls"] else [])

    def find(self, tid):
        for t in self.user + self.ctl:
            if t["id"] == tid:
                return t
        return None

    # --- сохранение
    def _load(self):
        try:
            with open(self.cfg_path, encoding="utf-8") as f:
                d = json.load(f)
        except Exception:
            d = {}
        self.settings.update({k: v for k, v in d.get("settings", {}).items() if k in self.settings})
        a = d.get("auth") or {}
        if all(isinstance(a.get(k), str) and a.get(k) for k in ("user", "salt", "hash")):
            self.auth = a
        else:
            self._set_auth(DEFAULT_USER, DEFAULT_PASS, default=True)
            self._need_save = True
        self.running = d.get("running", True)
        for it in d.get("targets", []):
            p = parse_url(it.get("url"))
            if p:
                self.user.append(self._target(it["id"], "user", it.get("name") or self._default_name(p), p))
        # незакрытые инциденты: продолжаем их после перезапуска
        with self.db_lock:
            rows = self.db.execute("SELECT id, tid, start, status, detail FROM incidents WHERE end IS NULL").fetchall()
        for iid, tid, start, status, detail in rows:
            t = self.find(tid)
            if t:
                t.update(status=status, detail=detail or "", since=start, down_since=start,
                         alerted=True, incident=iid, fails=self.settings["confirm"])
            else:
                self._db("UPDATE incidents SET end=? WHERE id=?", (now_ms(), iid))

    def save(self):
        d = dict(settings=self.settings, running=self.running, auth=self.auth,
                 targets=[dict(id=t["id"], name=t["name"], url=t["url"]) for t in self.user])
        tmp = self.cfg_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.cfg_path)

    def _db(self, sql, args=(), many=False):
        with self.db_lock:
            cur = self.db.executemany(sql, args) if many else self.db.execute(sql, args)
            self.db.commit()
            return cur

    def event(self, kind, host, text, t=None):
        self._db("INSERT INTO events VALUES(?,?,?,?)", (t or now_ms(), kind, host, text))

    # --- учётная запись
    @staticmethod
    def _hash_pw(pw, salt):
        return hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ITER).hex()

    def _set_auth(self, user, pw, default=False):
        salt = secrets.token_hex(16)
        self.auth = dict(user=user, salt=salt, hash=self._hash_pw(pw, salt), default=default)

    def verify(self, user, pw):
        a = self.auth
        ok_user = hmac.compare_digest(str(user).encode("utf-8"), a["user"].encode("utf-8"))
        ok_pw = hmac.compare_digest(self._hash_pw(str(pw), a["salt"]), a["hash"])
        return ok_user and ok_pw

    def change_credentials(self, user, pw):
        with self.lock:
            self._set_auth(user, pw, default=False)
            self.save()
        self._db("DELETE FROM sessions")          # все прежние входы становятся недействительны
        self.event("info", "", f"изменены данные для входа (логин {user})")

    def new_session(self, user):
        tok = secrets.token_urlsafe(32)
        self._db("INSERT INTO sessions VALUES(?,?,?)",
                 (hashlib.sha256(tok.encode()).hexdigest(), user, int(time.time()) + SESSION_TTL))
        return tok

    def session_user(self, tok):
        if not tok or len(tok) > 200:
            return None
        h = hashlib.sha256(tok.encode()).hexdigest()
        with self.db_lock:
            row = self.db.execute("SELECT user, exp FROM sessions WHERE h=?", (h,)).fetchone()
        if not row:
            return None
        if row[1] < time.time() or row[0] != self.auth["user"]:
            self._db("DELETE FROM sessions WHERE h=?", (h,))
            return None
        return row[0]

    def drop_session(self, tok):
        if tok:
            self._db("DELETE FROM sessions WHERE h=?", (hashlib.sha256(tok.encode()).hexdigest(),))

    @staticmethod
    def _default_name(p):
        if p["scheme"] == "tcp":
            return f"{p['host']}:{p['port']}"
        return p["host"] + (p["path"] if p["path"] != "/" else "")

    # --- цикл проверок
    def loop(self):
        pool = ThreadPoolExecutor(max_workers=24)
        last_purge = 0
        while True:
            if not self.running:
                self.next_at = None
                self.wake.wait(1)
                self.wake.clear()
                continue
            with self.lock:
                snap = [dict(t) for t in self.active()]
                timeout = self.settings["timeout"]
                opts = dict(quic=self.settings["quic"], ech=self.settings["ech"])
            try:
                results = list(pool.map(lambda t: (t["id"], check(t, timeout, opts)), snap))
                self.apply(results)
            except Exception as e:
                log("ошибка цикла проверок:", e)
            if time.time() - last_purge > 3600:
                cut = now_ms() - KEEP_DAYS * 86400_000
                self._db("DELETE FROM checks WHERE t<?", (cut,))
                self._db("DELETE FROM events WHERE t<?", (cut,))
                self._db("DELETE FROM diags WHERE t<?", (cut,))
                last_purge = time.time()
            interval = self.settings["interval"]
            self.next_at = time.time() + interval
            self.wake.wait(interval)
            self.wake.clear()

    def apply(self, results):
        t_now = now_ms()
        rows = []
        with self.lock:
            confirm = self.settings["confirm"]
            for tid, r in results:
                t = self.find(tid)
                if not t:
                    continue
                good = r["status"] in GOOD
                was_good = t["status"] in GOOD
                if t["status"] == PENDING or good != was_good:
                    t["since"] = t_now
                t.update(status=r["status"], detail=r["detail"], ms=r["ms"],
                         h3=r.get("h3"), kbps=r.get("kbps") if good else None)
                rows.append((tid, t_now, r["status"], r["ms"]))
                if t["group"] == "user":
                    self._warnings(t, r, good, confirm, t_now)

                if good:
                    if t["alerted"] and t["group"] == "user":
                        mins = round((t_now - (t["down_since"] or t_now)) / 60000)
                        d = f"{mins} мин" if mins >= 1 else "меньше минуты"
                        self.event("good", t["host"], f"снова доступен (был недоступен {d})", t_now)
                        log("ВОССТАНОВЛЕН", t["host"])
                    if t["incident"]:
                        self._db("UPDATE incidents SET end=? WHERE id=?", (t_now, t["incident"]))
                    t.update(fails=0, alerted=False, down_since=None, incident=None)
                else:
                    t["fails"] += 1
                    if t["fails"] == 1:
                        t["down_since"] = t_now
                    if t["fails"] >= confirm and not t["alerted"]:
                        t["alerted"] = True
                        t["since"] = t["down_since"]
                        if t["group"] == "user":
                            self.event("bad", t["host"], f"недоступен — {LABELS[t['status']]}", t_now)
                            cur = self._db("INSERT INTO incidents(tid,start,end,status,detail) VALUES(?,?,NULL,?,?)",
                                           (t["id"], t["down_since"], t["status"], t["detail"]))
                            t["incident"] = cur.lastrowid
                            log("СБОЙ", t["host"], LABELS[t["status"]], t["detail"])
                            self.start_diag(t["id"], "тревога")
            self.checked_at = t_now
            self._update_mode(t_now)
        if rows:
            self._db("INSERT INTO checks VALUES(?,?,?,?)", rows, many=True)

    def _warnings(self, t, r, good, confirm, t_now):
        """Предупреждения по рабочему сайту: показываем после `confirm` проверок подряд, пишем в журнал."""
        found = {w["code"]: w["text"] for w in (r.get("warn") or [])} if good else {}
        s = self.settings
        kb = r.get("kbps")
        if good and s["slow_kbps"] and kb is not None and kb < s["slow_kbps"]:
            found[WARN_SLOW] = (f"загрузка идёт со скоростью ≈{kb} кбит/с (порог {s['slow_kbps']}) — "
                                "похоже на замедление")
        if good and s["changed"] and t["scheme"] != "tcp":
            ch = self._baseline(t, r)
            if ch:
                found[WARN_CHANGED] = ch
        seen = t["wseen"]
        for code in list(seen):
            if code not in found:
                del seen[code]
        for code in found:
            seen[code] = seen.get(code, 0) + 1
        need = {WARN_ECH: 1}     # ECH — свойство сайта, его не нужно подтверждать
        shown = [dict(code=c, text=x) for c, x in found.items() if seen[c] >= need.get(c, confirm)]
        before = {w["code"] for w in t["warn"]}
        after = {w["code"] for w in shown}
        if good or not t["warn"]:          # во время сбоя прежние предупреждения не трогаем
            for w in shown:
                if w["code"] not in before:
                    self.event("warn", t["host"], "предупреждение: " + w["text"], t_now)
            for w in t["warn"]:
                if w["code"] not in after:
                    self.event("info", t["host"], "предупреждение снято: " + WARN_NAMES[w["code"]], t_now)
            t["warn"] = shown

    @staticmethod
    def _baseline(t, r):
        """Сверка с обычным ответом сайта (как у OONI, только эталон — свои же прошлые проверки):
        заметно другой заголовок страницы и в разы меньший объём — значит, отдают не то."""
        title, size = r.get("title"), r.get("size") or 0
        b = t["base"]
        if not b or (b["n"] < 5 and b["title"] != title):
            t["base"], t["cand"] = dict(title=title, size=size, n=1), 0
            return None
        if b["title"] == title:
            b["n"] += 1
            b["size"] = round(b["size"] * 0.8 + size * 0.2)
            t["cand"] = 0
            return None
        t["cand"] += 1
        if t["cand"] >= 20:               # новый вид держится 20 проверок — сайт, видимо, обновили
            t["base"], t["cand"] = dict(title=title, size=size, n=5), 0
            return None
        if b["size"] and size < b["size"] * 0.5:
            was = f"«{b['title']}»" if b["title"] else "без заголовка"
            now = f"«{title}»" if title else "без заголовка"
            return (f"ответ не похож на обычный: заголовок {now} вместо {was}, "
                    f"{max(1, size // 1024)} КБ вместо ≈{max(1, b['size'] // 1024)} КБ")
        return None

    def _update_mode(self, t_now):
        if not self.settings["controls"]:
            self.mode = None
            return
        g = {}
        for t in self.ctl:
            if t["status"] != PENDING:
                g.setdefault(t["group"], []).append(t["status"] in GOOD)
        ru, fo = g.get("ru", []), g.get("foreign", [])
        mode = None
        if ru and fo:
            r, f = sum(ru) / len(ru), sum(fo) / len(fo)
            if r <= MOSTLY_DOWN and f <= MOSTLY_DOWN:
                mode = "nonet"
            elif r >= MOSTLY_UP and f <= MOSTLY_DOWN:
                mode = "whitelist"
        if mode != self.mode:
            if mode == "whitelist":
                self.event("warn", "", "похоже на режим белых списков: российские сайты работают, зарубежные нет", t_now)
            elif mode == "nonet":
                self.event("net", "", "нет связи даже с российскими сайтами", t_now)
            elif self.mode is not None:
                self.event("info", "", "связь с контрольными сайтами восстановлена", t_now)
            self.mode = mode

    # --- диагностика
    def start_diag(self, tid, reason):
        with self.lock:
            t = self.find(tid)
            if not t or t["group"] != "user":
                return False, "ресурс не найден"
            if not (self.settings["diag_trace"] or self.settings["diag_global"]):
                return False, "диагностика выключена в настройках"
            if tid in self.diag_running:
                return False, "диагностика уже идёт"
            gap = DIAG_GAP_ALERT if reason == "тревога" else DIAG_GAP
            if time.time() - self.diag_last.get(tid, 0) < gap:
                return False, ("по этому ресурсу диагностика уже была в последние 10 минут" if reason == "тревога"
                               else "не чаще раза в 2 минуты")
            self.diag_running.add(tid)
            self.diag_last[tid] = time.time()
            snap = dict(t)
            opts = dict(trace=self.settings["diag_trace"], glob=self.settings["diag_global"])
        threading.Thread(target=self._run_diag, args=(snap, reason, opts), daemon=True).start()
        return True, ""

    def _run_diag(self, t, reason, opts):
        t_start = now_ms()
        out = dict(host=t["host"], port=t["port"], reason=reason, status=t["status"], started=t_start)
        try:
            ip = None
            try:
                ip = socket.getaddrinfo(t["host"], t["port"], socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
            except Exception:
                alt = alt_resolve(t["host"])
                ip = alt[0] if alt else None
            out["ip"] = ip
            alt = alt_resolve(t["host"])
            out["dns"] = dict(system=ip, alt=alt, alt_name=ALT_DNS_NAME)
            private = bool(ip and is_private(ip))
            out["private"] = private
            jobs = {}
            with ThreadPoolExecutor(max_workers=3) as ex:
                if opts["trace"] and ip:
                    jobs["trace_tcp"] = ex.submit(traceroute, ip, t["port"], "tcp")
                    jobs["trace_icmp"] = ex.submit(traceroute, ip, t["port"], "icmp")
                if opts["glob"] and t["scheme"] == "tcp":
                    out["global"] = dict(ok=False, error="для проверки TCP-адреса внешний сервис не используется")
                elif opts["glob"] and not private and HOST_RE.match(t["host"]):
                    if self._gp_allow():
                        jobs["global"] = ex.submit(globalping, t["host"], t["port"], t["scheme"])
                    else:
                        out["global"] = dict(ok=False, error=f"пропущено: лимит {GP_PER_HOUR} проверок из других сетей в час исчерпан")
                for k, f in jobs.items():
                    try:
                        out[k] = f.result()
                    except Exception as e:
                        out[k] = dict(ok=False, error=str(e)[:200])
            if opts["glob"] and private:
                out["global"] = dict(ok=False, error="внутренний адрес — во внешний сервис не отправляется")
        except Exception as e:
            out["error"] = str(e)[:200]
        out["finished"] = now_ms()
        out["mode"] = self.mode
        out["summary"] = diag_summary(out.get("global"), out.get("trace_tcp"), out.get("trace_icmp"), self.mode)
        self._db("INSERT INTO diags(tid,t,reason,data) VALUES(?,?,?,?)",
                 (t["id"], t_start, reason, json.dumps(out, ensure_ascii=False)))
        self.event("info", t["host"], "диагностика: " + out["summary"])
        log("ДИАГНОСТИКА", t["host"], out["summary"])
        with self.lock:
            self.diag_running.discard(t["id"])

    def _gp_allow(self):
        with self.lock:
            now = time.time()
            self.gp_times = [x for x in self.gp_times if now - x < 3600]
            if len(self.gp_times) >= GP_PER_HOUR:
                return False
            self.gp_times.append(now)
            return True

    def diags(self, tid, limit=5):
        with self.db_lock:
            rows = self.db.execute("SELECT t, reason, data FROM diags WHERE tid=? ORDER BY t DESC LIMIT ?",
                                   (tid, limit)).fetchall()
        res = []
        for t, reason, data in rows:
            try:
                d = json.loads(data)
            except Exception:
                d = {}
            d.update(t=t, reason=reason)
            res.append(d)
        return dict(running=tid in self.diag_running, items=res)

    # --- выдача
    def spark(self, tid, t_now):
        start = t_now - SPARK_HOURS * 3600_000
        step = SPARK_HOURS * 3600_000 // SPARK_BUCKETS
        with self.db_lock:
            rows = self.db.execute("SELECT t, status, ms FROM checks WHERE tid=? AND t>=? ORDER BY t",
                                   (tid, start)).fetchall()
        buckets = [None] * SPARK_BUCKETS
        for t, status, ms in rows:
            i = min(SPARK_BUCKETS - 1, (t - start) // step)
            b = buckets[i] or dict(ms=[], bad=False)
            if status in GOOD:
                if ms is not None:
                    b["ms"].append(ms)
            else:
                b["bad"] = True
            buckets[i] = b
        out = []
        for b in buckets:
            if b is None:
                continue
            out.append(None if b["bad"] else (round(sum(b["ms"]) / len(b["ms"])) if b["ms"] else 0))
        return out

    def state(self):
        t_now = now_ms()
        with self.lock:
            targets = []
            for t in self.active():
                targets.append(dict(id=t["id"], group=t["group"], name=t["name"], host=t["host"],
                                    url=t["url"], status=t["status"], label=LABELS[t["status"]],
                                    detail=t["detail"], ms=t["ms"], since=t["since"], fails=t["fails"],
                                    alerted=t["alerted"], diag_running=t["id"] in self.diag_running,
                                    warn=t["warn"], h3=t["h3"], kbps=t["kbps"],
                                    spark=self.spark(t["id"], t_now) if t["group"] == "user" else []))
            next_in = max(0, round(self.next_at - time.time())) if (self.running and self.next_at) else None
            st = dict(version=VERSION, running=self.running, checked_at=self.checked_at, next_in=next_in, now=t_now,
                      settings=self.settings, targets=targets)
        with self.db_lock:
            ev = self.db.execute("SELECT t, kind, host, text FROM events ORDER BY t DESC LIMIT 150").fetchall()
        st["events"] = [dict(t=t, kind=k, host=h, text=x) for t, k, h, x in ev]
        return st

    def history(self, tid, rng):
        now = dt.datetime.now()
        midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
        start = midnight - dt.timedelta(days=6 if rng == "week" else 0)
        end = midnight + dt.timedelta(days=1)
        a, b = int(start.timestamp() * 1000), int(end.timestamp() * 1000)
        with self.db_lock:
            rows = self.db.execute(
                "SELECT start, end, status, detail FROM incidents WHERE tid=? AND start<? AND (end IS NULL OR end>?) ORDER BY start",
                (tid, b, a)).fetchall()
            first = self.db.execute("SELECT MIN(t) FROM checks WHERE tid=?", (tid,)).fetchone()[0]
            checks = self.db.execute("SELECT t, status FROM checks WHERE tid=? AND t>=? AND t<? ORDER BY t",
                                     (tid, a, b)).fetchall()
        incidents = [dict(start=s, end=e, status=st, label=LABELS.get(st, st), detail=d or "", alerted=True, checks=None)
                     for s, e, st, d in rows]

        # Кратковременные сбои: неудачные проверки подряд, которые не дотянули до тревоги
        def covered(t):
            return any(i["start"] <= t and (i["end"] is None or t < i["end"]) for i in incidents)
        blips, run = [], None
        for t, st in checks:
            if st in GOOD:
                if run:
                    run["end"] = t
                    if not covered(run["start"]):
                        blips.append(run)
                    run = None
            elif run is None:
                run = dict(start=t, end=None, status=st, label=LABELS.get(st, st), detail="", alerted=False, checks=1)
            else:
                run["checks"] += 1
        if run and not covered(run["start"]):
            blips.append(run)

        allx = sorted(incidents + blips, key=lambda x: x["start"])
        return {"from": a, "to": b, "now": now_ms(), "first_check": first, "incidents": allx}

    # --- действия
    def add(self, links):
        added = []
        with self.lock:
            have = {t["url"] for t in self.user}
            for s in links:
                p = parse_url(s)
                if not p or p["url"] in have:
                    continue
                t = self._target("u" + uuid.uuid4().hex[:8], "user", self._default_name(p), p)
                self.user.append(t)
                have.add(p["url"])
                added.append(t["host"])
            if added:
                self.save()
        for h in added:
            self.event("info", h, "добавлен в мониторинг")
        if added:
            self.wake.set()
        return added

    def remove(self, tid):
        with self.lock:
            t = next((x for x in self.user if x["id"] == tid), None)
            if not t:
                return False
            self.user.remove(t)
            if t["incident"]:
                self._db("UPDATE incidents SET end=? WHERE id=?", (now_ms(), t["incident"]))
            self.save()
        self.event("info", t["host"], "удалён из мониторинга")
        return True

    def rename(self, tid, name):
        with self.lock:
            t = next((x for x in self.user if x["id"] == tid), None)
            if not t:
                return False
            t["name"] = (name or "").strip()[:80] or self._default_name(t)
            self.save()
        return True

    def set_settings(self, d):
        clamp = lambda v, lo, hi, df: max(lo, min(hi, int(v))) if str(v).lstrip("-").isdigit() else df
        with self.lock:
            s = self.settings
            if "interval" in d: s["interval"] = clamp(d["interval"], 5, 3600, s["interval"])
            if "confirm" in d: s["confirm"] = clamp(d["confirm"], 1, 20, s["confirm"])
            if "timeout" in d: s["timeout"] = clamp(d["timeout"], 2, 30, s["timeout"])
            if "slow_kbps" in d: s["slow_kbps"] = clamp(d["slow_kbps"], 0, 1_000_000, s["slow_kbps"])
            for k in ("sound", "popup", "controls", "diag_trace", "diag_global", "quic", "ech", "changed"):
                if k in d:
                    s[k] = bool(d[k])
            self.save()
        self.wake.set()

    def toggle(self):
        with self.lock:
            self.running = not self.running
            self.save()
        self.event("info", "", "мониторинг запущен" if self.running else "мониторинг приостановлен")
        self.wake.set()


MON = None


# ---------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    server_version = "tspu-monitor"

    def log_message(self, fmt, *args):
        pass

    def _auth_ok(self):
        if not AUTH:
            return True
        h = self.headers.get("Authorization", "")
        if h.startswith("Basic "):
            try:
                if base64.b64decode(h[6:]).decode("utf-8") == AUTH:
                    return True
            except Exception:
                pass
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="TSPU monitor", charset="UTF-8"')
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _token(self):
        try:
            c = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
            m = c.get(COOKIE)
            return m.value if m else None
        except http.cookies.CookieError:
            return None

    def _user(self):
        return MON.session_user(self._token())

    def _cookie(self, tok, max_age):
        secure = "; Secure" if self.headers.get("X-Forwarded-Proto", "").lower() == "https" else ""
        return f"{COOKIE}={tok}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}"

    def _route(self):
        u = urllib.parse.urlsplit(self.path)
        p = u.path
        i = p.find("/api/")      # работает и за прокси с подпутём
        return (p[i:] if i >= 0 else p), urllib.parse.parse_qs(u.query)

    def do_GET(self):
        if not self._auth_ok():
            return
        path, q = self._route()
        if path == "/api/state":
            st = MON.state()
            u = self._user()
            st["auth"] = dict(user=u, default_password=bool(u and MON.auth.get("default")))
            return self._send(200, st)
        if path in ("/api/history", "/api/history.csv"):
            tid = (q.get("id") or [""])[0]
            rng = (q.get("range") or ["day"])[0]
            t = MON.find(tid)
            if not t:
                return self._send(404, {"error": "not found"})
            h = MON.history(tid, rng)
            if path.endswith(".csv"):
                buf = io.StringIO()
                w = csv.writer(buf, delimiter=";")
                w.writerow(["ресурс", "начало", "конец", "длительность, с", "тревога", "код", "тип блокировки", "подробности"])
                fmt = lambda ms: dt.datetime.fromtimestamp(ms / 1000).strftime("%d.%m.%Y %H:%M:%S")
                for it in h["incidents"]:
                    e = it["end"] or h["now"]
                    kind = "да" if it["alerted"] else f"нет, кратковременный ({it['checks']} пров.)"
                    w.writerow([t["host"], fmt(it["start"]), fmt(it["end"]) if it["end"] else "продолжается",
                                round((e - it["start"]) / 1000), kind, it["status"], it["label"], it["detail"]])
                fn = f"incidents_{t['host']}_{rng}.csv"
                return self._send(200, "﻿" + buf.getvalue(), "text/csv; charset=utf-8",
                                  {"Content-Disposition": f'attachment; filename="{fn}"'})
            return self._send(200, h)
        if path == "/api/diag":
            tid = (q.get("id") or [""])[0]
            if not MON.find(tid):
                return self._send(404, {"error": "not found"})
            return self._send(200, MON.diags(tid))
        if path in ("/", "/index.html") or not path.startswith("/api/"):
            fp = os.path.join(STATIC_DIR, "index.html")
            with open(fp, "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._auth_ok():
            return
        path, _ = self._route()
        try:
            n = int(self.headers.get("Content-Length") or 0)
            data = json.loads(self.rfile.read(n) or b"{}") if n else {}
        except Exception:
            return self._send(400, {"error": "bad json"})
        if not isinstance(data, dict):
            return self._send(400, {"error": "bad json"})
        # защита от CSRF: такой заголовок может поставить только наша страница, а не чужой сайт или форма
        if self.headers.get("X-TSPU") != "1":
            return self._send(403, {"error": "forbidden"})

        if path == "/api/login":
            ip = self.client_address[0]
            now = time.time()
            fails = [x for x in MON.login_fails.get(ip, []) if now - x < LOGIN_WINDOW]
            MON.login_fails[ip] = fails
            if len(fails) >= LOGIN_MAX_FAILS:
                return self._send(429, {"error": "Слишком много неудачных попыток. Подождите 10 минут."})
            if MON.verify(str(data.get("user", "")), str(data.get("password", ""))):
                MON.login_fails.pop(ip, None)
                tok = MON.new_session(MON.auth["user"])
                log("ВХОД", MON.auth["user"], "с", ip)
                return self._send(200, {"ok": True, "user": MON.auth["user"], "default_password": bool(MON.auth.get("default"))},
                                  extra={"Set-Cookie": self._cookie(tok, SESSION_TTL)})
            fails.append(now)
            log("НЕУДАЧНЫЙ ВХОД с", ip)
            time.sleep(0.7)
            return self._send(401, {"error": "Неверный логин или пароль"})
        if path == "/api/logout":
            MON.drop_session(self._token())
            return self._send(200, {"ok": True}, extra={"Set-Cookie": self._cookie("", 0)})
        if path == "/api/check":
            MON.wake.set()
            return self._send(200, {"ok": True})

        # всё ниже меняет настройки или список — только после входа
        user = self._user()
        if not user:
            return self._send(401, {"error": "auth"})
        if path == "/api/password":
            if not MON.verify(user, str(data.get("old", ""))):
                return self._send(400, {"error": "Текущий пароль указан неверно"})
            new_user = str(data.get("user") or user).strip()
            new_pw = str(data.get("new", ""))
            if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,32}", new_user):
                return self._send(400, {"error": "Логин: латиница, цифры и символы _ . @ -, до 32 знаков"})
            if len(new_pw) < 8:
                return self._send(400, {"error": "Новый пароль — не короче 8 символов"})
            if new_pw == DEFAULT_PASS:
                return self._send(400, {"error": "Новый пароль совпадает с паролем по умолчанию"})
            MON.change_credentials(new_user, new_pw)
            tok = MON.new_session(new_user)
            return self._send(200, {"ok": True, "user": new_user}, extra={"Set-Cookie": self._cookie(tok, SESSION_TTL)})
        if path == "/api/toggle":
            MON.toggle()
            return self._send(200, {"ok": True, "running": MON.running})
        if path == "/api/add":
            links = data.get("links") or []
            if isinstance(links, str):
                links = links.splitlines()
            return self._send(200, {"ok": True, "added": MON.add([str(x) for x in links][:200])})
        if path == "/api/remove":
            return self._send(200, {"ok": MON.remove(str(data.get("id", "")))})
        if path == "/api/rename":
            return self._send(200, {"ok": MON.rename(str(data.get("id", "")), str(data.get("name", "")))})
        if path == "/api/diagnose":
            ok, why = MON.start_diag(str(data.get("id", "")), "вручную")
            return self._send(200, {"ok": ok, "reason": why})
        if path == "/api/settings":
            MON.set_settings(data)
            return self._send(200, {"ok": True, "settings": MON.settings})
        return self._send(404, {"error": "not found"})


def main():
    global MON
    MON = Monitor()
    threading.Thread(target=MON.loop, daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    srv.daemon_threads = True
    log(f"ТСПУ-монитор v{VERSION} запущен: http://0.0.0.0:{PORT}  (данные: {DATA_DIR}, пароль: {'да' if AUTH else 'нет'})")
    srv.serve_forever()


if __name__ == "__main__":
    main()
