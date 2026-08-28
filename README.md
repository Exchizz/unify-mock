# unifi-controller

A minimal, stdlib-only Python mock UniFi Protect controller for adopting a
standalone UniFi camera (tested against a UVC G6 Turret) **without** an
actual UniFi Protect NVR/console, and re-serving its video as clean FLV for
direct consumption by go2rtc/Frigate — no ffmpeg, no mediamtx, no RTSP
relay in between.

## Why this exists

UniFi cameras normally only stream to a UniFi Protect controller: they
authenticate over a TLS+WebSocket "inform" channel, get adopted, then push
their video/audio over a second plain-TCP connection using a
UniFi-proprietary variant of FLV ("extendedFlv" — regular FLV tags with an
extra 16-byte timing trailer appended after each one). This project
re-implements just enough of that protocol to:

1. Accept the camera's TLS/WebSocket control connection and complete
   adoption (hello / arm / authToken handshake).
2. Tell the camera to push its media stream to *this* host.
3. Accept that raw extendedFlv push, strip the non-standard trailer/tag
   types, and re-broadcast it as genuine FLV.
4. Serve that clean FLV stream on a plain TCP port that go2rtc (or
   anything else that understands FLV) can pull directly via
   `tcp://<host>:<port>`.

## Architecture

```
UniFi camera                     this container                    go2rtc / Frigate
------------                     ---------------                    -----------------
TLS+WS "inform"  ───────────►  :18080  control/adoption logic
                                (hello, arm, authToken, adopt,
                                 ChangeDeviceSettings, LED off, ...)

raw TCP extendedFlv  ────────►  :7550  strip 16-byte trailer,
                                drop non-standard tag types,
                                recompute PreviousTagSize,
                                cache codec config tags
                                        │
                                        ▼
                                 in-memory broadcaster
                                        │
                                        ▼
                                clean FLV byte stream ──────────►  :7551  pulled via
                                                                    tcp://<host>:7551
```

### Control channel (port 18080, TLS + WebSocket)

The camera connects here first (`GET /camera/1.0/ws`) to perform its
"inform" handshake. This process:
- Terminates TLS (self-signed cert, generated on first start — see
  [TLS certificate](#tls-certificate) below).
- Completes the WebSocket upgrade.
- Implements just enough of the JSON message protocol (`hello`, arm/
  authToken exchange, `Adopt`, `ChangeDeviceSettings`,
  `ChangeSoundLedSettings`) to satisfy the camera's adoption flow and tell
  it where to push media (`CONTROLLER_IP:MEDIA_PORT`).
- Also sends a `ChangeSoundLedSettings` message shortly after adoption to
  turn off the camera's status LED.

### Media ingest (port 7550, plain TCP)

Once adopted, the camera opens a second, unencrypted TCP connection here
and pushes its video/audio as "extendedFlv": standard FLV tags, each
followed by an extra 16-byte UniFi-specific timing trailer, plus an
occasional non-standard tag type the camera emits that a normal FLV
demuxer can't parse. This process:
- Strips the 16-byte trailer.
- Drops non-standard tag types (keeping only audio/video/script tags).
- Recomputes each tag's `PreviousTagSize` field (since dropped tags would
  otherwise break the chain).
- Caches the one-time codec config tags — the AMF `onMetaData` tag, the
  AVC sequence header, and the AAC sequence header — since the camera only
  sends these once near the start of the stream. Without replaying them to
  new consumers, downstream demuxers (like go2rtc) can connect fine but
  detect zero media tracks.
- Broadcasts the resulting clean FLV byte stream to every connected
  consumer.

### FLV output (port 7551, plain TCP)

Any client connecting here becomes a broadcast consumer: it immediately
receives the cached FLV header + cached codec config tags, followed by the
live tag stream. go2rtc can be pointed straight at this with a plain
`tcp://` stream source (no query strings or ffmpeg needed):

```yaml
streams:
  cam_yard: tcp://<this-host>:7551
```

## Configuration (environment variables)

| Variable          | Default                          | Description                                                              |
|-------------------|-----------------------------------|---------------------------------------------------------------------------|
| `CONTROLLER_HOST` | *(required)*                      | Address the camera can resolve/reach — this host's LAN IP, or a hostname if the camera has working DNS. Told to the camera as its media-push destination. `CONTROLLER_IP` is accepted as a deprecated alias. |
| `LISTEN_HOST`     | `0.0.0.0`                          | Bind address for the TLS/WebSocket control channel.                       |
| `LISTEN_PORT`     | `18080`                            | Port for the TLS/WebSocket control channel.                               |
| `MEDIA_HOST`      | `0.0.0.0`                          | Bind address for the extendedFlv media ingest.                            |
| `MEDIA_PORT`      | `7550`                             | Port for the extendedFlv media ingest.                                    |
| `FLV_HOST`        | `0.0.0.0`                          | Bind address for the clean-FLV consumer output.                           |
| `FLV_PORT`        | `7551`                             | Port for the clean-FLV consumer output (point go2rtc here).               |
| `DEVICE_TIMEZONE` | `CET-1CEST,M3.5.0,M10.5.0/3`       | POSIX TZ string sent in `ChangeDeviceSettings`. Note: on the tested camera this field is reporting-only and does not actually change the camera's clock — see [Known limitations](#known-limitations). |
| `CERT_DIR`        | directory containing the script    | Directory to read/write `cert.pem`/`key.pem`.                             |

Logs go to the container's standard streams: informational output on
stdout, errors on stderr. Use `docker logs` (or your log driver) to read
them — there is no log file.

At startup the container validates that `CONTROLLER_HOST` resolves *from
inside the container* (`socket.getaddrinfo`) and refuses to start if it
doesn't. This is a sanity check only — the camera does its own DNS
resolution independently, so a hostname must also resolve from the
camera's network. Most UniFi cameras sit on an isolated LAN/VLAN without
a working resolver, so a plain LAN IP is usually the safer choice; only
use a hostname if you know the camera can resolve it.

## TLS certificate

The camera doesn't appear to validate the control channel's TLS
certificate against a CA, so any valid self-signed cert works. On first
container start, `entrypoint.sh` generates a self-signed cert/key into
`CERT_DIR` (default `/certs`) if one isn't already present there. Mount a
volume at `/certs` (see `docker-compose.yml`) to persist it across
restarts.

## Running

### Docker Compose

```bash
# edit CONTROLLER_HOST in docker-compose.yml to this host's LAN IP (or a
# hostname the camera can resolve) first
docker compose up -d --build
```

`network_mode: host` is used deliberately: the camera initiates both the
control connection and the raw media push directly to this host's IP, and
go2rtc/Frigate typically pull the FLV output from the same host — bridge
networking would need extra NAT/hairpin configuration for the
camera-initiated connections.

### Camera adoption

Point the camera at this controller the same way you would a real UniFi
Protect console/inform URL (adjust to your adoption tooling), e.g.:

```
ubnt_ipc_cli -T=ubnt_avclient -r=1 -x='response/statusCode' \
  -m='{"functionName":"Adopt","hosts":["https://<this-host>:18080/inform"],"protocol":"wss"}'
```

## Known limitations

- `ChangeDeviceSettings`'s `timezone` field appears to be **camera → 
  controller reporting only** on the tested firmware (UVC G6 Turret
  5.0.83) — sending it does not change the camera's on-screen clock. The
  camera's actual timezone lives in its own persistent config
  (`/etc/persistent/system.cfg`, key `system.timezone`) and requires
  camera-side shell access (`ubnt_system_cfg write system.timezone <TZ>`)
  plus a reboot to take effect.
- `ChangeSoundLedSettings` is implemented as a best-effort controller→
  camera setter based on `unifi-cam-proxy`'s protocol implementation, but
  has not been exhaustively verified across camera models/firmware.
- Only tested against a single UVC G6 Turret. Other UniFi camera models
  may use a different adoption handshake or FLV tag layout.
