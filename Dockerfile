FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY app/ws_dump_server.py /app/ws_dump_server.py
COPY app/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# 18080 = TLS/WebSocket adoption+control channel (camera "inform" connection)
# 7550  = plain-TCP extendedFlv media ingest (camera pushes video/audio here)
# 7551  = plain-TCP clean FLV output (go2rtc/Frigate pulls from here)
EXPOSE 18080 7550 7551

ENTRYPOINT ["/app/entrypoint.sh"]
