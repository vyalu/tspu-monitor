#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Демо-стенд для скриншотов README.

Запускает настоящий сервер монитора, но вместо реальных проверок сети отвечает
по сценарию, а историю заполняет выдуманными данными. Все адреса и данные
придуманы: домены *.example.ru и адрес 203.0.113.10 (диапазон для документации).

    python3 tests/demo/demo_server.py            # http://127.0.0.1:8099
    echo fail > /tmp/tspu-demo/scenario          # ok | fail | whitelist
"""
import json
import os
import random
import sys
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEMO = os.environ.get("DEMO_DIR", os.path.join(tempfile.gettempdir(), "tspu-demo"))
os.makedirs(DEMO, exist_ok=True)
for f in ("config.json", "history.db", "history.db-wal", "history.db-shm"):
    try:
        os.remove(os.path.join(DEMO, f))
    except FileNotFoundError:
        pass
os.environ["DATA_DIR"] = DEMO
SCEN = os.path.join(DEMO, "scenario")
if not os.path.exists(SCEN):
    open(SCEN, "w").write("ok")

sys.path.insert(0, os.path.join(ROOT, "app"))
import server  # noqa: E402

random.seed(7)

TARGETS = [  # (адрес, имя, базовый отклик, мс)
    ("https://crm.example.ru/", "CRM", 340),
    ("https://push.example-cloud.com/", "Push-сервер CRM", 290),
    ("https://mail.example.ru/owa", "Почта", 410),
    ("https://1c.example.ru/", "1С", 380),
    ("203.0.113.10:443", "Сервер сертификатов", 45),
]
BASE = {}

server.CONTROLS = [
    ("c-ya", "ru", "Яндекс", "https://ya.example/"),
    ("c-gu", "ru", "Госуслуги", "https://gu.example/"),
    ("c-vk", "ru", "VK", "https://vk.example/"),
    ("c-sb", "ru", "Сбербанк", "https://sb.example/"),
    ("c-go", "foreign", "Google", "https://go.example/"),
    ("c-cf", "foreign", "Cloudflare", "https://cf.example/"),
    ("c-gh", "foreign", "GitHub", "https://gh.example/"),
    ("c-ms", "foreign", "Microsoft", "https://ms.example/"),
]
CTL_MS = {"c-ya": 120, "c-gu": 230, "c-vk": 140, "c-sb": 260, "c-go": 95, "c-cf": 80, "c-gh": 150, "c-ms": 170}


def scenario():
    try:
        return open(SCEN).read().strip() or "ok"
    except OSError:
        return "ok"


def fake_check(t, timeout, opts=None):
    sc = scenario()
    jitter = lambda b: int(b * random.uniform(0.85, 1.2))
    if t["group"] != "user":
        if sc == "whitelist" and t["group"] == "foreign":
            return dict(status="IP_BLOCK", detail="таймаут TCP-соединения", ms=None)
        return dict(status="OK", detail="", ms=jitter(CTL_MS.get(t["id"], 150)))
    host = t["host"]
    if sc == "fail" and host == "crm.example.ru":
        return dict(status="SNI_BLOCK", detail="ConnectionResetError: [Errno 104] Connection reset by peer", ms=None)
    if sc == "whitelist" and host in ("push.example-cloud.com", "mail.example.ru"):
        return dict(status="IP_BLOCK", detail="таймаут TCP-соединения", ms=None)
    if t["scheme"] == "tcp":
        return dict(status="OK", detail="TCP-соединение установлено", ms=jitter(BASE.get(host, 50)))
    r = dict(status="OK", detail="", ms=jitter(BASE.get(host, 300)), kbps=jitter(8000), warn=[])
    if host == "push.example-cloud.com":
        r.update(h3="fail", warn=[dict(code="QUIC", text="HTTP/3 (QUIC, UDP 443) не проходит: браузер откатится "
                                                        "на обычное соединение, первая загрузка может тормозить")])
    elif host == "crm.example.ru":
        r["h3"] = "ok"
    return r


def fake_globalping(host, port, scheme):
    probes = [
        dict(country="RU", city="Москва", network="Провайдер А", asn=64501, ok=True, code=200, ms=118, error=""),
        dict(country="RU", city="Санкт-Петербург", network="Провайдер Б", asn=64502, ok=True, code=200, ms=134, error=""),
        dict(country="RU", city="Екатеринбург", network="Провайдер В", asn=64503, ok=True, code=200, ms=161, error=""),
        dict(country="RU", city="Новосибирск", network="Провайдер Г", asn=64504, ok=True, code=200, ms=187, error=""),
        dict(country="DE", city="Франкфурт", network="Хостинг Д", asn=64505, ok=True, code=200, ms=74, error=""),
        dict(country="NL", city="Амстердам", network="Хостинг Е", asn=64506, ok=True, code=200, ms=81, error=""),
        dict(country="FI", city="Хельсинки", network="Хостинг Ж", asn=64507, ok=True, code=200, ms=69, error=""),
    ]
    return dict(ok=True, id="demo", probes=probes, ru_ok=4, ru_total=4, fo_ok=3, fo_total=3)


def fake_trace(ip, port, mode):
    hops = [dict(n=1, ip="192.0.2.1", ms=0.6), dict(n=2, ip="198.51.100.1", ms=2.1),
            dict(n=3, ip="198.51.100.17", ms=4.8)]
    if mode == "tcp":
        hops += [dict(n=4, ip=None, ms=None), dict(n=5, ip=None, ms=None)]
        reached = False
    else:
        hops += [dict(n=4, ip="198.51.100.40", ms=7.2), dict(n=5, ip=ip, ms=9.4)]
        reached = True
    raw = f"traceroute to {ip} ({ip}), 20 hops max\n" + "\n".join(
        f" {h['n']}  {h['ip'] or '*'}" + (f"  {h['ms']} ms" if h["ms"] else "") for h in hops)
    last = next((h for h in reversed(hops) if h["ip"]), None)
    return dict(ok=True, reached=reached, last=last, hops=hops, raw=raw)


server.check = fake_check
server.globalping = fake_globalping
server.traceroute = fake_trace
server.alt_resolve = lambda host: ["203.0.113.20"]
server.socket.getaddrinfo = lambda *a, **k: [(2, 1, 6, "", ("203.0.113.20", 443))]


def seed(mon):
    now = server.now_ms()
    mon.settings.update(interval=30, confirm=2, timeout=7, controls=True)
    added = []
    for url, name, base in TARGETS:
        mon.add([url])
        t = mon.user[-1]
        mon.rename(t["id"], name)
        BASE[t["host"]] = base
        added.append((t, base))

    # история проверок за 7 дней: каждые 5 минут, с выдуманными сбоями
    outages = {  # host: [(начало, длительность) в минутах назад]
        "crm.example.ru": [(60 * 24 * 2 + 300, 34), (60 * 24 * 5 + 130, 18), (190, 22)],
        "push.example-cloud.com": [(60 * 24 + 420, 55), (60 * 24 * 4 + 600, 41), (100, 6)],
        "mail.example.ru": [(60 * 24 * 3 + 200, 27)],
    }
    rows, incidents = [], []
    for t, base in added:
        for start, dur in outages.get(t["host"], []):
            a = now - start * 60_000
            incidents.append((t["id"], a, a + dur * 60_000, "IP_BLOCK" if t["host"] != "crm.example.ru" else "SNI_BLOCK",
                              "демо-данные", dur >= 10))
        for k in range(0, 7 * 24 * 12):
            ts = now - k * 5 * 60_000
            down = any(now - s * 60_000 <= ts < now - (s - d) * 60_000 for s, d in outages.get(t["host"], []))
            if down:
                rows.append((t["id"], ts, "SNI_BLOCK" if t["host"] == "crm.example.ru" else "IP_BLOCK", None))
            else:
                wave = 1 + 0.12 * ((k // 9) % 5)
                rows.append((t["id"], ts, "OK", int(base * wave * random.uniform(0.85, 1.15))))
    mon._db("INSERT INTO checks VALUES(?,?,?,?)", rows, many=True)
    for tid, a, b, st, det, alerted in incidents:
        if alerted:
            mon._db("INSERT INTO incidents(tid,start,end,status,detail) VALUES(?,?,?,?,?)", (tid, a, b, st, det))

    host_of = {t["id"]: t["host"] for t, _ in added}
    ev = []
    for tid, a, b, st, det, alerted in sorted(incidents, key=lambda x: x[1]):
        if not alerted:
            continue
        ev.append((a, "bad", host_of[tid], "недоступен — " + server.LABELS[st]))
        ev.append((b, "good", host_of[tid], f"снова доступен (был недоступен {round((b - a) / 60000)} мин)"))
    ev.append((now - 60 * 24 * 60_000 + 425 * 60_000, "info", "push.example-cloud.com",
               "диагностика: с других российских узлов открывается — ограничение на пути из офиса (ваш провайдер / ТСПУ) (Россия 4/4, за рубежом 3/3); TCP-трассировка обрывается после узла 3 (198.51.100.17); ICMP при этом доходит — режется именно TCP"))
    mon._db("DELETE FROM events")
    mon._db("INSERT INTO events VALUES(?,?,?,?)", ev, many=True)

    crm = next(t for t, _ in added if t["host"] == "crm.example.ru")
    d = dict(host=crm["host"], port=443, reason="тревога", status="SNI_BLOCK", started=now - 190 * 60_000,
             ip="203.0.113.20", dns=dict(system="203.0.113.20", alt=["203.0.113.20"], alt_name="Яндекс DNS"),
             private=False, **{"global": fake_globalping("", 443, "https")},
             trace_tcp=fake_trace("203.0.113.20", 443, "tcp"), trace_icmp=fake_trace("203.0.113.20", 443, "icmp"),
             finished=now - 189 * 60_000, mode=None)
    d["summary"] = server.diag_summary(d["global"], d["trace_tcp"], d["trace_icmp"])
    mon._db("INSERT INTO diags(tid,t,reason,data) VALUES(?,?,?,?)",
            (crm["id"], now - 190 * 60_000, "тревога", json.dumps(d, ensure_ascii=False)))
    mon.diag_last = {t["id"]: time.time() for t, _ in added}   # не запускать новую диагностику
    mon.auth["default"] = False
    mon.save()


def main():
    port = int(os.environ.get("PORT", "8099"))
    server.MON = mon = server.Monitor()
    seed(mon)
    threading.Thread(target=mon.loop, daemon=True).start()
    srv = ThreadingHTTPServer(("127.0.0.1", port), server.Handler)
    srv.daemon_threads = True
    print(f"Демо: http://127.0.0.1:{port}  (сценарий: {SCEN})", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
