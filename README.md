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
2. Tell the camera to push its media stream to *this* host, on a port
   reserved for that specific camera.
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

raw TCP extendedFlv  ────────►  :7550+n  strip 16-byte trailer,
                                drop non-standard tag types,
                                recompute PreviousTagSize,
                                cache codec config tags
                                        │
                                        ▼
                                 in-memory broadcaster (one per camera)
                                        │
                                        ▼
                                clean FLV byte stream ──────────►  :7650+n  pulled via
                                                                   tcp://<host>:7650+n
```

Each adopted camera gets its **own pair of ports** (`n` is that camera's
registry index), so any number of cameras can stream at once. See
[Multiple cameras](#multiple-cameras).

### Control channel (port 18080, TLS + WebSocket)

The camera connects here first (`GET /camera/1.0/ws`) to perform its
"inform" handshake. This process:
- Terminates TLS (self-signed cert, generated on first start — see
  [TLS certificate](#tls-certificate) below).
- Completes the WebSocket upgrade.
- Implements just enough of the JSON message protocol (`hello`, arm/
  authToken exchange, `Adopt`, `ChangeDeviceSettings`,
  `ChangeSoundLedSettings`) to satisfy the camera's adoption flow and tell
  it where to push media (`CONTROLLER_HOST:<that camera's media port>`).
- Also sends a `ChangeSoundLedSettings` message shortly after adoption to
  turn off the camera's status LED.

### Media ingest (ports 7550+n, plain TCP)

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
- Broadcasts the resulting clean FLV byte stream to every consumer
  connected to *that camera's* FLV output port.

### FLV output (ports 7650+n, plain TCP)

Any client connecting here becomes a broadcast consumer: it immediately
receives the cached FLV header + cached codec config tags, followed by the
live tag stream. go2rtc can be pointed straight at this with a plain
`tcp://` stream source (no query strings or ffmpeg needed):

```yaml
streams:
  cam_yard: tcp://<this-host>:7650
```

## Multiple cameras

Any number of cameras can be adopted and streamed concurrently. Each one
gets its **own media-in and FLV-out port pair**, because FLV is a single
continuous muxed byte stream — two cameras writing into one port would
interleave their tags into unrecoverable garbage.

Cameras are keyed by **MAC address**, read from the camera's
`ubnt_avclient_hello` at adoption time. A registry maps MAC → index and
persists it to `STATE_FILE`, and the ports are derived as:

```
media port = MEDIA_PORT_BASE + index   (default 7550, 7551, 7552, ...)
flv port   = FLV_PORT_BASE   + index   (default 7650, 7651, 7652, ...)
```

Because the port a camera is told to dial is unique to it, the destination
port *is* the camera's identity — there is no source-IP guessing and no race
when two cameras adopt at the same time. The assignment is persisted, so a
camera keeps the same ports across restarts (important, since your go2rtc
config references them by number). Listeners for all known cameras are
started eagerly at boot, so go2rtc can reconnect before the camera
re-adopts.

### Finding a camera's FLV port

Both the registry allocation and each adoption log the mapping to stdout:

```
=== allocated camera 8CEDE15055EB index=0 media=7550 flv=7650 ===
=== camera 8CEDE15055EB (UVC G6 Turret) => media tcp://192.168.1.2:7550, flv tcp://0.0.0.0:7650 ===
```

You can also read `STATE_FILE` directly — it is a plain `{"<MAC>": <index>}`
JSON map.

### go2rtc with several cameras

```yaml
streams:
  cam_yard: tcp://<this-host>:7650      # 8CEDE15055EB, index 0
  cam_door: tcp://<this-host>:7651      # 8CEDE15055FF, index 1
  cam_shed: tcp://<this-host>:7652      # index 2
```

### Audio and video are one stream, not two

Audio and video are **not** separate streams needing separate ports. They
are interleaved FLV tag types 8 (audio) and 9 (video) inside a single muxed
stream, so one port per camera carries both. Splitting them would require a
real demuxer, and go2rtc expects them muxed anyway — hence "one port per
camera", not "one port per track".

Note that each camera is armed at up to 6 Mbit/s VBR, so total ingest
bandwidth scales linearly with the number of cameras.

## Configuration (environment variables)

| Variable          | Default                          | Description                                                              |
|-------------------|-----------------------------------|---------------------------------------------------------------------------|
| `CONTROLLER_HOST` | *(required)*                      | Address the camera can resolve/reach — this host's LAN IP, or a hostname if the camera has working DNS. Told to the camera as its media-push destination. `CONTROLLER_IP` is accepted as a deprecated alias. |
| `LISTEN_HOST`     | `0.0.0.0`                          | Bind address for the TLS/WebSocket control channel.                       |
| `LISTEN_PORT`     | `18080`                            | Port for the TLS/WebSocket control channel.                               |
| `MEDIA_HOST`      | `0.0.0.0`                          | Bind address for the extendedFlv media ingest.                            |
| `MEDIA_PORT_BASE` | `7550`                             | First port of the per-camera extendedFlv ingest range. `MEDIA_PORT` is accepted as a deprecated alias. |
| `FLV_HOST`        | `0.0.0.0`                          | Bind address for the clean-FLV consumer output.                           |
| `FLV_PORT_BASE`   | `7650`                             | First port of the per-camera clean-FLV output range (point go2rtc here). `FLV_PORT` is accepted as a deprecated alias. |
| `STATE_FILE`      | `cameras.json` next to the script  | Persisted MAC → index map that keeps each camera's ports stable across restarts. |
| `DEVICE_TIMEZONE` | `CET-1CEST,M3.5.0,M10.5.0/3`       | POSIX TZ string sent in `ChangeDeviceSettings`. Note: on the tested camera this field is reporting-only and does not actually change the camera's clock — see [Known limitations](#known-limitations). |
| `CERT_DIR`        | directory containing the script    | Directory to read/write `cert.pem`/`key.pem`.                             |

The two port bases are spaced far apart so the ranges cannot collide as the
camera count grows. If you override them, keep that gap wider than your
expected number of cameras.

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
camera-initiated connections. It also means the per-camera port ranges
(`7550+` and `7650+`) need no explicit publishing; on bridge networking you
would have to publish both ranges yourself.

A named volume is mounted at `/data` to persist `cameras.json`, the MAC →
port-index map. Remove it and cameras will be re-indexed on next adoption,
which can change their FLV ports.

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
- A camera whose `ubnt_avclient_hello` carries no usable MAC address cannot
  be assigned ports and will not be armed; the failure is logged to stderr
  rather than falling back to a shared port.
