# Docker Hub из России недоступен, поэтому берём тот же официальный образ с зеркала Google
FROM mirror.gcr.io/library/python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080 \
    DATA_DIR=/data \
    TZ=Europe/Moscow

# ca-certificates — проверка TLS-сертификатов; tzdata — местное время в истории;
# traceroute — диагностика маршрута. Право на сырые сокеты (cap_net_raw) выдаём только
# программе traceroute, а не всему приложению: сервис работает под обычным пользователем.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tzdata traceroute libcap2-bin \
 && setcap cap_net_raw+ep "$(readlink -f "$(command -v traceroute)")" \
 && apt-get purge -y libcap2-bin && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home /app monitor \
 && mkdir -p /data && chown monitor /data

WORKDIR /app
COPY app/ /app/
USER monitor

EXPOSE 8080
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,os,base64; r=urllib.request.Request('http://127.0.0.1:%s/api/state'%os.environ.get('PORT','8080')); a=os.environ.get('BASIC_AUTH'); a and r.add_header('Authorization','Basic '+base64.b64encode(a.encode()).decode()); urllib.request.urlopen(r,timeout=4)" || exit 1

CMD ["python", "/app/server.py"]
