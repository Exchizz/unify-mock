#!/usr/bin/env python3
"""TLS + minimal WebSocket server (Python 3.5 compatible, stdlib only).

Performs TLS termination, then completes the WebSocket handshake for the
UniFi camera's inform connection (GET /camera/1.0/ws), then decodes and
hex-dumps every WebSocket frame payload received afterwards.
"""

import base64
import datetime
import hashlib
import json
import os
import random
import select
import socket
import ssl
import struct
import sys
import threading
import time
import warnings
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, urlparse

HOST = os.environ.get("LISTEN_HOST", "0.0.0.0")
PORT = int(os.environ.get("LISTEN_PORT", "18080"))

# Media (extendedFlv) push destination the camera is told to dial, and where
# we hand it off to for RTSP restreaming. CONTROLLER_HOST must be an address
# the camera itself can resolve/reach — either this host's LAN IP, or a
# hostname (if the camera has working DNS, e.g. a local resolver, since
# these devices are usually LAN-isolated and can't reach public DNS/mDNS
# in every setup). CONTROLLER_IP is accepted as a deprecated alias.
CONTROLLER_HOST = os.environ.get("CONTROLLER_HOST") or os.environ.get("CONTROLLER_IP")
MEDIA_HOST = os.environ.get("MEDIA_HOST", "0.0.0.0")

# Every adopted camera gets its own pair of ports: one media-in and one
# FLV-out, derived from these bases plus the camera's registry index. The
# destination port the camera is told to dial therefore *is* its identity, so
# no source-IP heuristics are needed to correlate a media connection with the
# camera that opened it. MEDIA_PORT/FLV_PORT are accepted as deprecated
# aliases for the bases so existing single-camera setups keep working.
MEDIA_PORT_BASE = int(
    os.environ.get("MEDIA_PORT_BASE") or os.environ.get("MEDIA_PORT") or "7550")

# Cleaned/genuine FLV byte stream is served here for go2rtc (or any other
# consumer) to pull directly via `tcp://<this-host>:<flv port>` — no
# ffmpeg/mediamtx relay in between. The bases are spaced far apart so the two
# ranges cannot collide as the camera count grows.
FLV_OUTPUT_HOST = os.environ.get("FLV_HOST", "0.0.0.0")
FLV_PORT_BASE = int(
    os.environ.get("FLV_PORT_BASE") or os.environ.get("FLV_PORT") or "7650")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_DIR = os.environ.get("CERT_DIR", BASE_DIR)

# Persisted MAC -> index mapping, so a camera keeps the same ports across
# restarts (the go2rtc config references them by number).
STATE_FILE = os.environ.get("STATE_FILE", os.path.join(BASE_DIR, "cameras.json"))

# Status/management web interface: lists adopted cameras, whether each is
# streaming, the port go2rtc should pull from, and allows deleting cameras
# that are no longer in use.
WEB_HOST = os.environ.get("WEB_HOST", "0.0.0.0")
WEB_PORT = int(os.environ.get("WEB_PORT", "18081"))

# A camera counts as online only if it has forwarded a tag within this many
# seconds; a half-open TCP connection that has gone silent is not a live
# stream.
STREAM_IDLE_TIMEOUT = float(os.environ.get("STREAM_IDLE_TIMEOUT", "10"))
CERTFILE = os.path.join(CERT_DIR, "cert.pem")
KEYFILE = os.path.join(CERT_DIR, "key.pem")

WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

_log_lock = threading.Lock()

if not CONTROLLER_HOST:
    raise SystemExit(
        "CONTROLLER_HOST (or CONTROLLER_IP) environment variable is "
        "required: set it to this host's LAN IP or a hostname the camera "
        "can resolve (the address the camera will dial back for media "
        "push).")

try:
    socket.getaddrinfo(CONTROLLER_HOST, MEDIA_PORT_BASE)
except socket.gaierror as e:
    raise SystemExit(
        "CONTROLLER_HOST=%r does not resolve on this host (%s). The "
        "camera would fail to dial it back for media push." %
        (CONTROLLER_HOST, e))


def _emit(stream, msg):
    line = "%s %s\n" % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"), msg)
    with _log_lock:
        stream.write(line)
        stream.flush()


def log(msg):
    """Write an informational message to stdout, thread-safe and unbuffered."""
    _emit(sys.stdout, msg)


def log_err(msg):
    """Write an error message to stderr, thread-safe and unbuffered."""
    _emit(sys.stderr, msg)


def _normalize_mac(mac):
    """Reduce a MAC from the hello payload to bare uppercase hex, or None if
    it is missing/unparseable. Keys the camera registry."""
    if not isinstance(mac, str):
        return None
    cleaned = "".join(c for c in mac if c in "0123456789abcdefABCDEF").upper()
    if len(cleaned) != 12:
        return None
    return cleaned


def hexdump(data):
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join("%02x" % b for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append("%04x  %-47s  %s" % (i, hex_part, ascii_part))
    return "\n".join(lines)


def recv_until(sock, marker, maxlen=65536):
    buf = b""
    while marker not in buf and len(buf) < maxlen:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


def parse_http_headers(raw):
    head, _, rest = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    request_line = lines[0].decode("utf-8", errors="replace")
    headers = {}
    for line in lines[1:]:
        if b":" in line:
            k, _, v = line.partition(b":")
            headers[k.strip().lower().decode()] = v.strip().decode()
    return request_line, headers, rest


def ws_accept_key(client_key):
    sha1 = hashlib.sha1((client_key + WS_MAGIC).encode("utf-8")).digest()
    return base64.b64encode(sha1).decode("utf-8")


def read_ws_frame(sock, leftover):
    """Read one WS frame, returning (opcode, payload, remaining_leftover) or (None, None, leftover) on EOF."""
    def fill(n):
        nonlocal leftover
        while len(leftover) < n:
            chunk = sock.recv(4096)
            if not chunk:
                return False
            leftover += chunk
        return True

    if not fill(2):
        return None, None, leftover
    b0, b1 = leftover[0], leftover[1]
    leftover = leftover[2:]
    opcode = b0 & 0x0F
    masked = bool(b1 & 0x80)
    plen = b1 & 0x7F

    if plen == 126:
        if not fill(2):
            return None, None, leftover
        plen = struct.unpack("!H", leftover[:2])[0]
        leftover = leftover[2:]
    elif plen == 127:
        if not fill(8):
            return None, None, leftover
        plen = struct.unpack("!Q", leftover[:8])[0]
        leftover = leftover[8:]

    mask_key = b""
    if masked:
        if not fill(4):
            return None, None, leftover
        mask_key = leftover[:4]
        leftover = leftover[4:]

    if not fill(plen):
        return None, None, leftover
    payload = leftover[:plen]
    leftover = leftover[plen:]

    if masked:
        payload = bytes(payload[i] ^ mask_key[i % 4] for i in range(len(payload)))

    return opcode, payload, leftover


def send_ws_frame(sock, opcode, payload):
    """Send an unmasked WS frame (server-to-client frames are never masked)."""
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    b0 = 0x80 | (opcode & 0x0F)  # FIN=1
    plen = len(payload)
    if plen < 126:
        header = struct.pack("!BB", b0, plen)
    elif plen < 65536:
        header = struct.pack("!BBH", b0, 126, plen)
    else:
        header = struct.pack("!BBQ", b0, 127, plen)
    sock.sendall(header + payload)


def now_iso():
    now = datetime.datetime.utcnow()
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + "%03d+00:00" % (now.microsecond // 1000)


def now_ms():
    return int(time.time() * 1000)


def build_envelope(function_name, payload, in_response_to=None, response_expected=False):
    return {
        "from": "UniFiVideo",
        "to": "ubnt_avclient",
        "functionName": function_name,
        "messageId": random.randint(1, 2 ** 31 - 1),
        "inResponseTo": in_response_to if in_response_to is not None else 0,
        "payload": payload,
        "responseExpected": response_expected,
        "timeStamp": now_iso(),
    }


def build_arm_message(media_port, stream_name):
    """Build the ChangeVideoSettings message that arms video1 for h264 at
    highest quality, pushed as extendedFlv to this camera's own media
    receiver port (SPEC.md 3.1)."""
    stream_name = stream_name[:16]
    dest = "tcp://%s:%d?retryInterval=1&connectTimeout=5" % (CONTROLLER_HOST, media_port)
    payload = {
        "video": {
            "video1": {
                "fps": 30,
                "bitRateCbr": None,
                "bitRateVbrMin": 1000000,
                "bitRateVbrMax": 6000000,
                "enabled": True,
                "codec": "h264",
                "avSerializer": {
                    "type": "extendedFlv",
                    "parameters": {
                        "streamName": stream_name,
                        "withOpus": True,
                        "opusSampleRate": 24000,
                    },
                    "destinations": [dest],
                },
            }
        }
    }
    return build_envelope("ChangeVideoSettings", payload, response_expected=True)


# IANA timezone name sent in ChangeDeviceSettings, e.g. "Europe/Copenhagen".
#
# This MUST be an IANA/Olson name, not a POSIX TZ string. The camera resolves
# it against /usr/share/zoneinfo and symlinks /etc/localtime at it. A POSIX
# string such as "CET-1CEST,M3.5.0,M10.5.0/3" is silently rejected — the
# firmware splits it on "/" and logs "Not found relevant timezone 3".
# Verified on a UVC G6 Turret running 5.0.83.
DEVICE_TIMEZONE = os.environ.get("DEVICE_TIMEZONE", "Europe/Copenhagen")


def build_device_settings_message(camera_name):
    """Tell the camera its local timezone, so its OSD/overlay clock renders
    local time instead of defaulting to UTC.

    The camera's ubnt_ctlserver handles this in updateSettings(): it resolves
    the IANA name under /usr/share/zoneinfo, points /etc/localtime at it,
    writes system.timezone into its persistent config, and derives the
    mains-frequency anti-flicker mode for the region. /etc is tmpfs, but the
    symlink is recreated from the persistent config on every boot, so this
    only needs sending once at adoption.

    `persists` asks the camera to write the value to flash rather than only
    applying it to the running system."""
    payload = {
        "name": camera_name,
        "timezone": DEVICE_TIMEZONE,
        "persists": True,
    }
    return build_envelope("ChangeDeviceSettings", payload, response_expected=True)


def build_led_off_message():
    """Turn off the camera's status/face LED via ChangeSoundLedSettings
    (per unifi-cam-proxy base.py process_sound_led_settings)."""
    payload = {
        "ledFaceAlwaysOnWhenManaged": 0,
        "ledFaceEnabled": 0,
        "speakerEnabled": 1,
        "speakerVolume": 100,
        "systemSoundsEnabled": 1,
        "userLedBlinkPeriodMs": 0,
        "userLedColorFg": "blue",
        "userLedOnNoff": 0,
    }
    return build_envelope("ChangeSoundLedSettings", payload, response_expected=True)


def build_ack_response(msg):
    """Build a generic fallback ack reply for a message that expects a response
    but has no special-cased handler."""
    return {
        "from": msg.get("to", "UniFiVideo"),
        "to": msg.get("from", "ubnt_avclient"),
        "functionName": msg.get("functionName", ""),
        "inResponseTo": msg.get("messageId"),
        "responseExpected": False,
        "payload": {},
        "messageId": random.randint(1, 2 ** 31 - 1),
        "responseCode": 0,
    }


def _make_tls_context():
    """Build the server-side TLS context.

    ssl.wrap_socket() was removed in Python 3.12, so use SSLContext. The
    camera's client is old, so allow the widest set of protocols and ciphers
    the local OpenSSL will accept rather than the modern defaults."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = ssl.TLSVersion.TLSv1
    except (AttributeError, ValueError):
        pass
    try:
        ctx.set_ciphers("DEFAULT@SECLEVEL=0")
    except ssl.SSLError:
        try:
            ctx.set_ciphers("DEFAULT@SECLEVEL=1")
        except ssl.SSLError:
            pass
    return ctx


def handle(conn, addr):
    log("=== TCP connection from %s ===" % (addr,))
    tls_conn = None
    try:
        tls_conn = _make_tls_context().wrap_socket(conn, server_side=True)
        log("=== TLS handshake OK with %s (cipher=%s) ===" % (addr, tls_conn.cipher()))

        raw = recv_until(tls_conn, b"\r\n\r\n")
        if b"\r\n\r\n" not in raw:
            log_err("--- %s: no complete HTTP header received ---" % (addr,))
            return
        request_line, headers, leftover = parse_http_headers(raw)
        log("--- HTTP request from %s: %s ---" % (addr, request_line))
        for k, v in headers.items():
            log("    %s: %s" % (k, v))

        ws_key = headers.get("sec-websocket-key")
        if not ws_key:
            log_err("--- %s: not a websocket upgrade, no Sec-WebSocket-Key ---" % (addr,))
            return

        accept = ws_accept_key(ws_key)
        proto = headers.get("sec-websocket-protocol", "")
        resp_lines = [
            "HTTP/1.1 101 Switching Protocols",
            "Upgrade: websocket",
            "Connection: Upgrade",
            "Sec-WebSocket-Accept: %s" % accept,
        ]
        if proto:
            resp_lines.append("Sec-WebSocket-Protocol: %s" % proto)
        resp = ("\r\n".join(resp_lines) + "\r\n\r\n").encode("utf-8")
        tls_conn.sendall(resp)
        log("=== WS handshake sent to %s ===" % (addr,))

        camera_name = ["UVC G6 Turret"]  # mutable holder, updated from hello payload
        camera_cell = [None]  # resolved Camera for this connection, set at hello

        while True:
            opcode, payload, leftover = read_ws_frame(tls_conn, leftover)
            if opcode is None:
                log("--- %s: WS connection closed/EOF ---" % (addr,))
                break
            log("--- WS frame opcode=%d, %d bytes from %s ---" % (opcode, len(payload), addr))
            log(hexdump(payload))
            if opcode in (1, 2):
                try:
                    log("--- as text ---")
                    text = payload.decode("utf-8", errors="replace")
                    log(text)
                except Exception:
                    text = None

                if text:
                    try:
                        msg = json.loads(text)
                    except Exception:
                        msg = None

                    if isinstance(msg, dict):
                        fn = msg.get("functionName")

                        if fn == "ubnt_avclient_hello":
                            model = msg.get("payload", {}).get("model")
                            if model:
                                camera_name[0] = model
                            mac = msg.get("payload", {}).get("mac")
                            log("=== camera hello: adoptionCode=%r model=%r fw=%r mac=%r ==="
                                % (msg.get("payload", {}).get("adoptionCode"),
                                   model,
                                   msg.get("payload", {}).get("fwVersion"),
                                   mac))
                            mac = _normalize_mac(mac)
                            if mac:
                                camera = REGISTRY.get_or_create(mac)
                                camera.name = camera_name[0]
                                camera_cell[0] = camera
                                REGISTRY.touch(mac, ip=addr[0] if addr else None)
                                # Reconnect => any config tags we cached from
                                # the previous session are stale.
                                camera.flv.clear_config_tags()
                                log("=== camera %s (%s) => media tcp://%s:%d, flv tcp://%s:%d ===" %
                                    (mac, camera.name, CONTROLLER_HOST, camera.media_port,
                                     FLV_OUTPUT_HOST, camera.flv_port))
                            else:
                                log_err("=== %s: hello has no usable MAC (%r); refusing to "
                                        "arm this camera, since it has no port of its own ==="
                                        % (addr, msg.get("payload", {}).get("mac")))
                            # Per SPEC.md 2.3: controller MUST reply to hello,
                            # regardless of responseExpected on the request.
                            hello_reply = build_envelope(
                                "ubnt_avclient_hello",
                                {
                                    "protocolVersion": 67,
                                    "controllerName": "MockController",
                                    "controllerUuid": None,
                                    "controllerVersion": "7.1.77",
                                    "overrideUuid": True,
                                },
                                in_response_to=msg.get("messageId"),
                                response_expected=False,
                            )
                            reply_text = json.dumps(hello_reply)
                            log("=== sending hello-reply (adoption gate) to %s: %s ===" % (addr, reply_text))
                            send_ws_frame(tls_conn, opcode, reply_text)

                            # Next step per spec: controller sends paramAgreement,
                            # camera answers with its authToken.
                            param_agreement = build_envelope(
                                "ubnt_avclient_paramAgreement", {}, response_expected=True
                            )
                            pa_text = json.dumps(param_agreement)
                            log("=== sending paramAgreement to %s: %s ===" % (addr, pa_text))
                            send_ws_frame(tls_conn, opcode, pa_text)

                        elif fn == "ubnt_avclient_timeSync":
                            t = now_ms()
                            ts_reply = build_envelope(
                                "ubnt_avclient_timeSync",
                                {"t1": t, "t2": t},
                                in_response_to=msg.get("messageId"),
                                response_expected=False,
                            )
                            ts_text = json.dumps(ts_reply)
                            send_ws_frame(tls_conn, opcode, ts_text)

                        elif fn == "ubnt_avclient_paramAgreement":
                            auth_token = msg.get("payload", {}).get("authToken")
                            log("=== camera authToken received: %r ===" % (auth_token,))

                            def _send_arm():
                                camera = camera_cell[0]
                                if camera is None:
                                    log_err("=== not arming %s: no camera identified "
                                            "(missing MAC in hello) ===" % (addr,))
                                    return
                                try:
                                    arm_msg = build_arm_message(camera.media_port,
                                                                camera.stream_name)
                                    arm_text = json.dumps(arm_msg)
                                    log("=== sending arm/ChangeVideoSettings to %s: %s ===" % (addr, arm_text))
                                    send_ws_frame(tls_conn, opcode, arm_text)
                                except Exception as e:
                                    log_err("=== failed to send arm message to %s: %r ===" % (addr, e))

                            def _send_device_settings():
                                try:
                                    ds_msg = build_device_settings_message(camera_name[0])
                                    ds_text = json.dumps(ds_msg)
                                    log("=== sending ChangeDeviceSettings (timezone=%s) to %s: %s ==="
                                        % (DEVICE_TIMEZONE, addr, ds_text))
                                    send_ws_frame(tls_conn, opcode, ds_text)
                                except Exception as e:
                                    log_err("=== failed to send device-settings message to %s: %r ===" % (addr, e))

                            timer = threading.Timer(1.5, _send_arm)
                            timer.daemon = True
                            timer.start()

                            tz_timer = threading.Timer(2.5, _send_device_settings)
                            tz_timer.daemon = True
                            tz_timer.start()

                            def _send_led_off():
                                try:
                                    led_msg = build_led_off_message()
                                    led_text = json.dumps(led_msg)
                                    log("=== sending ChangeSoundLedSettings (LED off) to %s: %s ===" % (addr, led_text))
                                    send_ws_frame(tls_conn, opcode, led_text)
                                except Exception as e:
                                    log_err("=== failed to send LED-off message to %s: %r ===" % (addr, e))

                            led_timer = threading.Timer(3.5, _send_led_off)
                            led_timer.daemon = True
                            led_timer.start()

                        elif msg.get("responseExpected"):
                            ack = build_ack_response(msg)
                            ack_text = json.dumps(ack)
                            log("=== sending generic ack to %s: %s ===" % (addr, ack_text))
                            send_ws_frame(tls_conn, opcode, ack_text)

            if opcode == 9:
                log("=== sending pong to %s ===" % (addr,))
                send_ws_frame(tls_conn, 10, payload)

            if opcode == 8:
                log("--- %s: received close frame ---" % (addr,))
                break
    except Exception as e:
        log_err("--- %s error: %r ---" % (addr, e))
    finally:
        try:
            if tls_conn is not None:
                tls_conn.close()
            else:
                conn.close()
        except Exception:
            pass


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


# --- FLV broadcaster: fans one camera's cleaned FLV byte stream out to any
# number of pull consumers (e.g. go2rtc's `tcp://host:<flv port>` source),
# skipping ffmpeg and mediamtx entirely. One instance per camera — FLV is a
# single continuous muxed stream, so two cameras must never share one. ---

# "GOP cache"-style config tags: the camera only sends these once near the
# start of the stream (AMF onMetaData, AVC sequence header, AAC sequence
# header). Any consumer connecting later needs them replayed first, or the
# downstream demuxer (e.g. go2rtc) can't identify codecs and finds zero
# tracks ("streams: unknown error"). Keyed by category so we always keep
# just the latest of each (metadata/video-config/audio-config), replayed to
# new consumers in a fixed, sensible order.
_CONFIG_ORDER = ("metadata", "video", "audio")


def _config_tag_category(tag_type, body):
    if tag_type == 18:
        return "metadata"  # AMF onMetaData script tag
    if tag_type == 9 and len(body) >= 2 and (body[1] == 0):
        return "video"  # AVC sequence header (avcPacketType == 0)
    if tag_type == 8 and len(body) >= 2 and ((body[0] >> 4) == 10) and (body[1] == 0):
        return "audio"  # AAC sequence header (soundformat == AAC, aacPacketType == 0)
    return None


def _flv_tag_timestamp(tag_hdr):
    """Read an FLV tag header's 24-bit timestamp plus its extended byte."""
    return (tag_hdr[4] << 16) | (tag_hdr[5] << 8) | tag_hdr[6] | (tag_hdr[7] << 24)


def _flv_rebase_timestamp(tag_hdr, ts_offset):
    """Rewrite an FLV tag header's timestamp by ``ts_offset`` milliseconds."""
    out_ts = _flv_tag_timestamp(tag_hdr) + ts_offset
    if out_ts < 0:
        out_ts = 0
    out_ts &= 0xFFFFFFFF
    new_hdr = bytearray(tag_hdr)
    new_hdr[4] = (out_ts >> 16) & 0xFF
    new_hdr[5] = (out_ts >> 8) & 0xFF
    new_hdr[6] = out_ts & 0xFF
    new_hdr[7] = (out_ts >> 24) & 0xFF
    return bytes(new_hdr), out_ts


class _Consumer(object):
    """One FLV pull consumer, with its own send lock.

    Every write to the socket goes through ``lock``, so the join payload
    (FLV header + cached config tags, written from the accept thread) can
    never be interleaved with a live tag written by the media thread — that
    corrupts the byte stream and makes demuxers like go2rtc drop and
    reconnect in a loop.
    """

    def __init__(self, sock):
        self.sock = sock
        self.lock = threading.Lock()
        self.joined = False        # join payload fully written
        self.want_keyframe = True  # hold live tags until a decodable start


class FlvBroadcaster(object):
    # Nudge applied after a camera reconnect, so the new stream's first tag
    # lands strictly after the last timestamp we emitted.
    TS_RECONNECT_GAP_MS = 40

    def __init__(self):
        self._lock = threading.Lock()
        self._consumers = []      # list of _Consumer
        self._pending_header = []  # consumers that connected before any FLV
                                   # header was seen; they get it on arrival
        self._last_header = None  # last FLV header + PreviousTagSize0, replayed
                                  # to new consumers that join mid-stream
        self._config_tags = {}    # category -> raw (tag_hdr + body + prevsize) bytes
        self._ts_lock = threading.Lock()
        self._last_out_ts = None  # highest timestamp (ms) emitted so far

    def add_consumer(self, sock):
        consumer = _Consumer(sock)
        with self._lock:
            self._consumers.append(consumer)
            header = self._last_header
            if header is None:
                # No camera stream yet; publish_header() finishes the join.
                self._pending_header.append(consumer)
                return
            config_tags = dict(self._config_tags)
        self._send_join(consumer, header, config_tags)

    def _send_join(self, consumer, header, config_tags):
        """Write header + cached config tags, then mark the consumer live."""
        with consumer.lock:
            if consumer.joined:
                return
            try:
                consumer.sock.sendall(header)
                for category in _CONFIG_ORDER:
                    blob = config_tags.get(category)
                    if blob:
                        consumer.sock.sendall(blob)
                consumer.joined = True
                return
            except Exception:
                pass
        self._drop(consumer)

    def _drop(self, consumer):
        with self._lock:
            if consumer in self._consumers:
                self._consumers.remove(consumer)
            if consumer in self._pending_header:
                self._pending_header.remove(consumer)
        try:
            consumer.sock.close()
        except Exception:
            pass

    def remove_consumer(self, sock):
        with self._lock:
            found = [c for c in self._consumers if c.sock is sock]
        for consumer in found:
            self._drop(consumer)
        if not found:
            try:
                sock.close()
            except Exception:
                pass

    def broadcast(self, data, tag_type=None, body=None, keyframe=False):
        is_config = False
        if tag_type is not None:
            category = _config_tag_category(tag_type, body)
            if category:
                is_config = True
                with self._lock:
                    self._config_tags[category] = data
        with self._lock:
            consumers = list(self._consumers)
        for consumer in consumers:
            failed = False
            with consumer.lock:
                if not consumer.joined:
                    continue  # still joining; it gets the cached tags instead
                if consumer.want_keyframe and not is_config:
                    # Starting a consumer mid-GOP gives it undecodable frames
                    # until the next keyframe; wait for one instead.
                    if not keyframe:
                        continue
                    consumer.want_keyframe = False
                try:
                    consumer.sock.sendall(data)
                except Exception:
                    failed = True
            if failed:
                log("=== FLV consumer dropped (send failed) ===")
                self._drop(consumer)

    def publish_header(self, header_bytes):
        """Record the FLV header, sending it only to consumers without one.

        The header must never reach a consumer that is already mid-stream:
        splicing a second ``FLV\\x01...`` signature into its byte stream is
        invalid FLV and desyncs the downstream demuxer.
        """
        with self._lock:
            self._last_header = header_bytes
            pending = list(self._pending_header)
            del self._pending_header[:]
            config_tags = dict(self._config_tags)
        for consumer in pending:
            self._send_join(consumer, header_bytes, config_tags)

    # --- output timeline ---
    #
    # The camera's FLV timestamps are uptime-based and restart near zero every
    # time it reconnects and re-pushes. Forwarding them verbatim makes DTS jump
    # backwards for consumers that stayed connected across the reconnect
    # (ffmpeg: "Non-monotonic DTS"), so each connection is rebased onto our own
    # continuous output clock instead.

    def ts_offset_for(self, first_ts):
        with self._ts_lock:
            base = (0 if self._last_out_ts is None
                    else self._last_out_ts + self.TS_RECONNECT_GAP_MS)
        return base - first_ts

    def note_out_ts(self, out_ts):
        with self._ts_lock:
            if self._last_out_ts is None or out_ts > self._last_out_ts:
                self._last_out_ts = out_ts

    def clear_config_tags(self):
        with self._lock:
            self._config_tags.clear()

    def consumer_count(self):
        with self._lock:
            return len(self._consumers)

    def close_all(self):
        with self._lock:
            consumers = list(self._consumers)
            self._consumers = []
            del self._pending_header[:]
        for consumer in consumers:
            try:
                consumer.sock.close()
            except Exception:
                pass


def flv_output_server(camera):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((FLV_OUTPUT_HOST, camera.flv_port))
    srv.listen(5)
    camera.register_listener(srv)
    log("FLV output server for %s (for go2rtc pull) listening on tcp://%s:%d" %
        (camera.mac, FLV_OUTPUT_HOST, camera.flv_port))
    while not camera.deleted:
        # Short select timeout rather than a blocking accept(), so deleting a
        # camera can tear its listeners down promptly and portably.
        try:
            readable, _, _ = select.select([srv], [], [], 0.5)
        except Exception:
            break
        if not readable:
            continue
        try:
            conn, addr = srv.accept()
        except Exception:
            break
        if camera.deleted:
            conn.close()
            break
        log("=== FLV consumer connected to %s: %s ===" % (camera.mac, addr))
        camera.flv.add_consumer(conn)
    try:
        srv.close()
    except Exception:
        pass


def handle_media(conn, addr, camera):
    """Accept the camera's plain-TCP extendedFlv media push (SPEC.md 3.2).

    extendedFlv is regular FLV with a 16-byte trailer appended after every
    tag's standard 4-byte PreviousTagSize field. We strip that trailer, rebase
    the camera's uptime-based timestamps onto a continuous output clock, and
    broadcast the resulting genuine FLV bytes to any consumers connected to
    this camera's own FLV output port — no ffmpeg/mediamtx needed.
    """
    log("=== MEDIA connection from %s for %s ===" % (addr, camera.mac))
    gen = camera.media_started(conn)
    try:
        header = recv_exact(conn, 9)
        if header is None or header[:3] != b"FLV":
            log_err("=== MEDIA %s: not an FLV header: %r ===" % (addr, header))
            return
        log("=== MEDIA %s: FLV header %s ===" % (addr, hexdump(header)))
        if not camera.media_is_current(gen):
            log("=== MEDIA %s: superseded by a newer connection, dropping ===" % (addr,))
            return
        header_and_prevsize0 = header + struct.pack("!I", 0)
        camera.flv.clear_config_tags()  # fresh camera connection => old config tags are stale
        # Only reaches consumers that never got a header; mid-stream consumers
        # keep the one they already have.
        camera.flv.publish_header(header_and_prevsize0)

        prevsize = recv_exact(conn, 4)  # wire's PreviousTagSize0, discard (we recompute our own)
        if prevsize is None:
            return

        # Only these are real FLV tag types; this camera also emits a
        # non-standard tag type (observed: 10, ~48kHz-clocked, likely the
        # Opus track from our withOpus request) that a standard FLV demuxer
        # doesn't understand and will choke on. Drop anything else.
        KNOWN_TAG_TYPES = (8, 9, 18)

        tag_count = 0
        forwarded_count = 0
        ts_offset = None
        while True:
            tag_hdr = recv_exact(conn, 11)
            if tag_hdr is None:
                log("=== MEDIA %s: connection closed after %d tags (%d forwarded) ===" %
                    (addr, tag_count, forwarded_count))
                break
            tag_type = tag_hdr[0]
            data_size = (tag_hdr[1] << 16) | (tag_hdr[2] << 8) | tag_hdr[3]
            body = recv_exact(conn, data_size)
            if body is None:
                break

            if tag_type in KNOWN_TAG_TYPES:
                if not camera.media_is_current(gen):
                    log("=== MEDIA %s: superseded by a newer connection, dropping ===" %
                        (addr,))
                    break
                if ts_offset is None:
                    raw_ts = _flv_tag_timestamp(tag_hdr)
                    ts_offset = camera.flv.ts_offset_for(raw_ts)
                    log("=== MEDIA %s: rebasing timestamps, camera ts=%d offset=%d ===" %
                        (addr, raw_ts, ts_offset))
                out_hdr, out_ts = _flv_rebase_timestamp(tag_hdr, ts_offset)
                camera.flv.note_out_ts(out_ts)
                # A consumer that joins mid-GOP can't decode until the next
                # keyframe, so flag them for the broadcaster.
                is_keyframe = (tag_type == 9 and len(body) >= 2 and
                               (body[0] >> 4) == 1 and body[1] == 1)
                # Recompute PreviousTagSize ourselves since we may have
                # excised non-standard tags in between.
                camera.flv.broadcast(out_hdr + body + struct.pack("!I", 11 + data_size),
                                     tag_type=tag_type, body=body,
                                     keyframe=is_keyframe)
                forwarded_count += 1
                camera.note_tag(11 + data_size)

            prevsize2 = recv_exact(conn, 4)  # wire's PreviousTagSize, discard
            if prevsize2 is None:
                break

            trailer = recv_exact(conn, 16)
            if trailer is None:
                break
            clockrate = (trailer[1] << 16) | (trailer[2] << 8) | trailer[3]
            elapsed = struct.unpack("!I", trailer[12:16])[0]

            tag_count += 1
            if tag_count <= 10 or tag_count % 100 == 0:
                extra = ""
                if tag_type == 9 and len(body) >= 2:
                    frametype = body[0] >> 4
                    codecid = body[0] & 0x0F
                    avc_pkt_type = body[1]
                    extra = " video frametype=%d codecid=%d avcPacketType=%d" % (
                        frametype, codecid, avc_pkt_type)
                elif tag_type == 8 and len(body) >= 1:
                    soundformat = body[0] >> 4
                    extra = " audio soundformat=%d" % soundformat
                elif tag_type == 18:
                    extra = " script/meta tag: %r" % (body[:80],)
                fwd = "fwd" if tag_type in KNOWN_TAG_TYPES else "DROPPED(non-standard)"
                log("=== MEDIA %s tag#%d type=%d size=%d clockrate=%d elapsed=%.2fs %s%s ===" %
                    (addr, tag_count, tag_type, data_size, clockrate, elapsed / 100000.0, fwd, extra))
    except Exception as e:
        log_err("=== MEDIA %s error: %r ===" % (addr, e))
    finally:
        camera.media_stopped(conn)
        try:
            conn.close()
        except Exception:
            pass
        log("=== MEDIA connection from %s closed ===" % (addr,))


def media_server(camera):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((MEDIA_HOST, camera.media_port))
    srv.listen(5)
    camera.register_listener(srv)
    log("Media (extendedFlv) server for %s listening on tcp://%s:%d" %
        (camera.mac, MEDIA_HOST, camera.media_port))
    while not camera.deleted:
        try:
            readable, _, _ = select.select([srv], [], [], 0.5)
        except Exception:
            break
        if not readable:
            continue
        try:
            conn, addr = srv.accept()
        except Exception:
            break
        if camera.deleted:
            conn.close()
            break
        t = threading.Thread(target=handle_media, args=(conn, addr, camera))
        t.daemon = True
        t.start()
    try:
        srv.close()
    except Exception:
        pass


# --- Camera registry: MAC -> Camera, with deterministic, persisted port
# assignment. The camera's MAC is available from ubnt_avclient_hello, which
# arrives well before the arm message fires, so ports can always be allocated
# in time. There is no cap on camera count. ---


def camera_web_url(ip):
    """The camera's own web UI. UniFi cameras serve it over HTTPS with a
    self-signed cert, so browsers will warn on first visit."""
    if not ip:
        return None
    host = "[%s]" % ip if ":" in ip else ip  # bracket IPv6 literals
    return "https://%s/" % host


class Camera(object):
    def __init__(self, mac, index, name=None, last_seen=None, ip=None):
        self.mac = mac
        self.index = index
        self.name = name or "UVC G6 Turret"
        self.last_seen = last_seen  # ISO string, last control-channel hello
        self.ip = ip               # last address we saw it connect from
        self.media_port = MEDIA_PORT_BASE + index
        self.flv_port = FLV_PORT_BASE + index
        self.flv = FlvBroadcaster()
        self.deleted = False
        self._started = False
        self._start_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._listeners = []       # bound server sockets, closed on delete
        self._media_conns = set()  # live camera->us media pushes
        self._media_generation = 0  # bumped per push, so a retired one stops
                                    # broadcasting into the shared output
        self.last_tag_at = None    # monotonic-ish wall clock of last forwarded tag
        self.tag_count = 0
        self.byte_count = 0

    @property
    def stream_name(self):
        """Unique per-camera stream name, within extendedFlv's 16-char limit."""
        return ("cam" + self.mac)[:16]

    # --- liveness ---

    def media_started(self, conn):
        """Make ``conn`` this camera's one live media push, retiring any older.

        Two overlapping pushes (the previous socket not yet torn down when the
        camera reconnects) would interleave two independent timelines into the
        same broadcaster, which looks exactly like a non-monotonic DTS bug
        downstream. Returns a generation token for ``media_is_current``.
        """
        with self._state_lock:
            self._media_generation += 1
            gen = self._media_generation
            stale = [c for c in self._media_conns if c is not conn]
            self._media_conns = set([conn])
        for old in stale:
            log("=== MEDIA %s: retiring previous media connection ===" % (self.mac,))
            try:
                old.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                old.close()
            except Exception:
                pass
        return gen

    def media_is_current(self, gen):
        with self._state_lock:
            return gen == self._media_generation

    def media_stopped(self, conn):
        with self._state_lock:
            self._media_conns.discard(conn)

    def note_tag(self, nbytes):
        with self._state_lock:
            self.last_tag_at = time.time()
            self.tag_count += 1
            self.byte_count += nbytes

    def is_streaming(self):
        """Online means the camera is pushing media *and* has done so
        recently — a half-open TCP connection that has gone quiet is not a
        live stream."""
        with self._state_lock:
            if not self._media_conns:
                return False
            last = self.last_tag_at
        return last is not None and (time.time() - last) <= STREAM_IDLE_TIMEOUT

    def status(self):
        return {
            "mac": self.mac,
            "name": self.name,
            "index": self.index,
            "media_port": self.media_port,
            "flv_port": self.flv_port,
            "stream_name": self.stream_name,
            "online": self.is_streaming(),
            "media_connections": len(self._media_conns),
            "flv_consumers": self.flv.consumer_count(),
            "tag_count": self.tag_count,
            "byte_count": self.byte_count,
            "last_tag_at": self.last_tag_at,
            "last_seen": self.last_seen,
            "ip": self.ip,
            "web_url": camera_web_url(self.ip),
            "flv_url": "tcp://%s:%d" % (CONTROLLER_HOST, self.flv_port),
        }

    # --- lifecycle ---

    def register_listener(self, sock):
        with self._state_lock:
            self._listeners.append(sock)

    def start_listeners(self):
        with self._start_lock:
            if self._started:
                return
            self._started = True
        for target in (media_server, flv_output_server):
            t = threading.Thread(target=self._run_listener, args=(target,))
            t.daemon = True
            t.start()

    def _run_listener(self, target):
        try:
            target(self)
        except Exception as e:
            log_err("=== listener %s for %s failed: %r ===" %
                    (target.__name__, self.mac, e))

    def shutdown(self):
        """Stop this camera's listeners and drop every live connection, so its
        ports are free for reuse by a future camera."""
        self.deleted = True
        with self._state_lock:
            listeners = list(self._listeners)
            media = list(self._media_conns)
            self._listeners = []
        self.flv.close_all()
        for sock in listeners + media:
            try:
                sock.close()
            except Exception:
                pass


class CameraRegistry(object):
    def __init__(self, state_file):
        self._state_file = state_file
        self._lock = threading.Lock()
        self._cameras = {}
        self._entries = self._load()

    def _load(self):
        """Read the persisted MAC -> {index, name, last_seen, ip} map.

        Also accepts the original flat ``{mac: index}`` format so an existing
        state file keeps working.
        """
        try:
            with open(self._state_file, "r") as fh:
                data = json.load(fh)
        except IOError:
            return {}
        except Exception as e:
            log_err("=== camera state file %s is unreadable (%r); starting "
                    "from an empty registry ===" % (self._state_file, e))
            return {}
        if not isinstance(data, dict):
            log_err("=== camera state file %s is malformed; starting from an "
                    "empty registry ===" % (self._state_file,))
            return {}
        entries = {}
        for mac, value in data.items():
            if isinstance(value, int):
                entries[mac] = {"index": value, "name": None,
                                "last_seen": None, "ip": None}
            elif isinstance(value, dict) and isinstance(value.get("index"), int):
                entries[mac] = {
                    "index": value["index"],
                    "name": value.get("name"),
                    "last_seen": value.get("last_seen"),
                    "ip": value.get("ip"),
                }
        return entries

    def _save(self):
        """Atomic write: temp file in the same directory, then rename.

        Caller must hold the lock.
        """
        for mac, entry in self._entries.items():
            camera = self._cameras.get(mac)
            if camera is not None:
                entry["name"] = camera.name
                entry["last_seen"] = camera.last_seen
                entry["ip"] = camera.ip
        tmp = self._state_file + ".tmp"
        try:
            directory = os.path.dirname(self._state_file)
            if directory and not os.path.isdir(directory):
                os.makedirs(directory)
            with open(tmp, "w") as fh:
                json.dump(self._entries, fh, indent=2, sort_keys=True)
            os.rename(tmp, self._state_file)
        except Exception as e:
            log_err("=== failed to persist camera state to %s: %r ===" %
                    (self._state_file, e))

    def get_or_create(self, mac):
        with self._lock:
            camera = self._cameras.get(mac)
            if camera is not None:
                return camera
            entry = self._entries.get(mac)
            if entry is None:
                used = set(e["index"] for e in self._entries.values())
                index = 0
                while index in used:
                    index += 1
                entry = {"index": index, "name": None, "last_seen": None,
                         "ip": None}
                self._entries[mac] = entry
                self._save()
                log("=== allocated camera %s index=%d media=%d flv=%d ===" %
                    (mac, index, MEDIA_PORT_BASE + index, FLV_PORT_BASE + index))
            camera = Camera(mac, entry["index"], name=entry.get("name"),
                            last_seen=entry.get("last_seen"),
                            ip=entry.get("ip"))
            self._cameras[mac] = camera
        camera.start_listeners()
        return camera

    def touch(self, mac, ip=None):
        """Record that we just heard from this camera, and persist its name
        and the address it connected from."""
        with self._lock:
            camera = self._cameras.get(mac)
            if camera is None:
                return
            camera.last_seen = now_iso()
            if ip:
                camera.ip = ip
            self._save()

    def delete(self, mac):
        """Forget a camera: free its index, tear down its listeners and drop
        its connections. If it ever adopts again it is treated as new and may
        be given a different index."""
        with self._lock:
            entry = self._entries.pop(mac, None)
            camera = self._cameras.pop(mac, None)
            if entry is None and camera is None:
                return False
            self._save()
        if camera is not None:
            camera.shutdown()
        log("=== deleted camera %s (freed index %s) ===" %
            (mac, entry["index"] if entry else "?"))
        return True

    def known_macs(self):
        with self._lock:
            return sorted(self._entries.keys())

    def statuses(self):
        """Status for every known camera, including ones that have never
        streamed since startup."""
        with self._lock:
            entries = dict(self._entries)
            cameras = dict(self._cameras)
        out = []
        for mac in sorted(entries, key=lambda m: entries[m]["index"]):
            camera = cameras.get(mac)
            if camera is not None:
                out.append(camera.status())
            else:
                index = entries[mac]["index"]
                out.append({
                    "mac": mac,
                    "name": entries[mac].get("name") or "unknown",
                    "index": index,
                    "media_port": MEDIA_PORT_BASE + index,
                    "flv_port": FLV_PORT_BASE + index,
                    "stream_name": ("cam" + mac)[:16],
                    "online": False,
                    "media_connections": 0,
                    "flv_consumers": 0,
                    "tag_count": 0,
                    "byte_count": 0,
                    "last_tag_at": None,
                    "last_seen": entries[mac].get("last_seen"),
                    "ip": entries[mac].get("ip"),
                    "web_url": camera_web_url(entries[mac].get("ip")),
                    "flv_url": "tcp://%s:%d" % (CONTROLLER_HOST, FLV_PORT_BASE + index),
                })
        return out


REGISTRY = CameraRegistry(STATE_FILE)


# --- Status/management web interface ---

_PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>unifi-controller \u2014 cameras</title>
<style>
 :root { color-scheme: light dark; }
 body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
        margin: 2rem auto; max-width: 60rem; padding: 0 1rem; line-height: 1.45; }
 h1 { margin-bottom: .25rem; font-size: 1.4rem; }
 .sub { opacity: .7; font-size: .85rem; margin-top: 0; }
 table { border-collapse: collapse; width: 100%%; margin-top: 1.5rem; font-size: .9rem; }
 th, td { text-align: left; padding: .55rem .6rem; border-bottom: 1px solid rgba(128,128,128,.3); }
 th { font-weight: 600; font-size: .78rem; text-transform: uppercase;
      letter-spacing: .04em; opacity: .7; }
 code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .88em; }
 .dot { display: inline-block; width: .55rem; height: .55rem; border-radius: 50%%;
        margin-right: .4rem; vertical-align: baseline; }
 .online .dot { background: #21a35a; }
 .offline .dot { background: #999; }
 .online { color: #21a35a; font-weight: 600; }
 .offline { opacity: .65; }
 .empty { margin-top: 2rem; opacity: .7; }
 .unknown { opacity: .45; }
 td a { color: #2d7dd2; text-decoration: none; }
 td a:hover { text-decoration: underline; }
 button { font: inherit; padding: .3rem .7rem; border-radius: .35rem;
          border: 1px solid rgba(128,128,128,.5); background: transparent;
          color: inherit; cursor: pointer; }
 button:hover { border-color: #c0392b; color: #c0392b; }
 .note { margin-top: 2rem; font-size: .82rem; opacity: .7; }
 .flash { margin-top: 1rem; padding: .6rem .8rem; border-radius: .35rem;
          background: rgba(33,163,90,.15); font-size: .88rem; }
</style>
</head>
<body>
<h1>Adopted cameras</h1>
<p class="sub">%(count)d camera(s) \u00b7 controller <code>%(controller)s</code> \u00b7 refreshes every %(refresh)ds</p>
%(flash)s
%(body)s
<p class="note">A camera is <strong>online</strong> when it is pushing media and has
sent data within the last %(idle)gs. Deleting a camera frees its slot and stops its
ports; if it adopts again it is treated as new and may get different ports.</p>
<script>
setTimeout(function () { location.replace(location.pathname); }, %(refresh)d000);
</script>
</body>
</html>
"""

_REFRESH_SECONDS = 5


def _esc(text):
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _human_bytes(n):
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return "%.0f %s" % (n, unit) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024.0


def _render_page(flash=None):
    cameras = REGISTRY.statuses()
    if cameras:
        rows = []
        for cam in cameras:
            state = "online" if cam["online"] else "offline"
            if cam.get("web_url"):
                ip_cell = ("<a href=\"%s\" target=\"_blank\" rel=\"noopener\">"
                           "<code>%s</code></a>"
                           % (_esc(cam["web_url"]), _esc(cam["ip"])))
            else:
                ip_cell = "<span class=\"unknown\">\u2014</span>"
            rows.append(
                "<tr>"
                "<td><code>%s</code></td>"
                "<td>%s</td>"
                "<td>%s</td>"
                "<td class=\"%s\"><span class=\"dot\"></span>%s</td>"
                "<td><code>%s</code></td>"
                "<td><code>%d</code></td>"
                "<td>%s</td>"
                "<td>%s</td>"
                "<td><form method=\"post\" action=\"delete\" "
                "onsubmit=\"return confirm('Delete camera %s? Its ports stop "
                "immediately and go2rtc will lose this stream.')\">"
                "<input type=\"hidden\" name=\"mac\" value=\"%s\">"
                "<button type=\"submit\">Delete</button></form></td>"
                "</tr>" % (
                    _esc(cam["mac"]),
                    _esc(cam["name"]),
                    ip_cell,
                    state,
                    state,
                    _esc(cam["flv_url"]),
                    cam["media_port"],
                    "%d" % cam["flv_consumers"],
                    _human_bytes(cam["byte_count"]) if cam["byte_count"] else "\u2014",
                    _esc(cam["mac"]),
                    _esc(cam["mac"]),
                ))
        body = (
            "<table><thead><tr>"
            "<th>MAC</th><th>Model</th><th>IP</th><th>Status</th>"
            "<th>go2rtc source</th><th>Media port</th>"
            "<th>Consumers</th><th>Forwarded</th><th></th>"
            "</tr></thead><tbody>%s</tbody></table>" % "".join(rows))
    else:
        body = ("<p class=\"empty\">No cameras adopted yet. Point a camera at "
                "this controller and it will appear here.</p>")

    return _PAGE_TEMPLATE % {
        "count": len(cameras),
        "controller": _esc(CONTROLLER_HOST),
        "refresh": _REFRESH_SECONDS,
        "idle": STREAM_IDLE_TIMEOUT,
        "flash": "<p class=\"flash\">%s</p>" % _esc(flash) if flash else "",
        "body": body,
    }


class StatusHandler(BaseHTTPRequestHandler):
    server_version = "unifi-controller"
    protocol_version = "HTTP/1.1"

    def _respond(self, status, body, content_type="text/html; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path.rstrip("/") or "/"
        if path == "/":
            flash = parse_qs(urlparse(self.path).query).get("deleted", [None])[0]
            self._respond(200, _render_page(
                "Deleted camera %s." % flash if flash else None))
        elif path == "/api/cameras":
            self._respond(200, json.dumps(REGISTRY.statuses(), indent=2),
                          "application/json")
        elif path == "/healthz":
            self._respond(200, "ok", "text/plain; charset=utf-8")
        else:
            self._respond(404, "not found", "text/plain; charset=utf-8")

    def do_POST(self):
        path = urlparse(self.path).path.rstrip("/") or "/"
        if path != "/delete":
            self._respond(404, "not found", "text/plain; charset=utf-8")
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        raw = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        mac = _normalize_mac(parse_qs(raw).get("mac", [""])[0])
        if not mac:
            self._respond(400, "bad or missing mac", "text/plain; charset=utf-8")
            return
        if not REGISTRY.delete(mac):
            self._respond(404, "no such camera", "text/plain; charset=utf-8")
            return
        # POST/redirect/GET so a refresh doesn't repeat the delete.
        self.send_response(303)
        self.send_header("Location", "/?deleted=%s" % mac)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt, *args):
        log("=== WEB %s %s ===" % (self.address_string(), fmt % args))


class _ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def web_server():
    httpd = _ThreadingHTTPServer((WEB_HOST, WEB_PORT), StatusHandler)
    log("Status web interface listening on http://%s:%d" % (WEB_HOST, WEB_PORT))
    httpd.serve_forever()


def main():
    # Start listeners eagerly for every camera we already know about, so
    # go2rtc can reconnect to its FLV port before the camera re-adopts.
    for mac in REGISTRY.known_macs():
        REGISTRY.get_or_create(mac)

    web_thread = threading.Thread(target=web_server)
    web_thread.daemon = True
    web_thread.start()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(50)
    log("TLS+WS dump server listening on tcp://%s:%d" % (HOST, PORT))
    while True:
        conn, addr = srv.accept()
        t = threading.Thread(target=handle, args=(conn, addr))
        t.daemon = True
        t.start()


if __name__ == "__main__":
    main()
