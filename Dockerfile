FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY app/ws_dump_server.py /app/ws_dump_server.py
COPY app/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# 18080     = TLS/WebSocket adoption+control channel (camera "inform" connection)
# 18081     = status web interface (adopted cameras, online state, delete)
# 7550-7559 = plain-TCP extendedFlv media ingest, one port per adopted camera
# 7650-7659 = plain-TCP clean FLV output, one port per adopted camera
#             (go2rtc/Frigate pull from here)
# The ranges are unbounded in the app; these EXPOSE lines just cover the
# first ten cameras, and are documentation only under host networking.
EXPOSE 18080 18081 7550-7559 7650-7659

# Persisted MAC -> port-index map, so cameras keep stable ports across restarts.
VOLUME ["/data"]
ENV STATE_FILE=/data/cameras.json

ENTRYPOINT ["/app/entrypoint.sh"]
