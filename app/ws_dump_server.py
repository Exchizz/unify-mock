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
import socket
import ssl
import struct
import sys
import threading
import time

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
MEDIA_PORT = int(os.environ.get("MEDIA_PORT", "7550"))

# Cleaned/genuine FLV byte stream is served here for go2rtc (or any other
# consumer) to pull directly via `tcp://<this-host>:7551` — no ffmpeg/mediamtx
# relay in between.
FLV_OUTPUT_HOST = os.environ.get("FLV_HOST", "0.0.0.0")
FLV_OUTPUT_PORT = int(os.environ.get("FLV_PORT", "7551"))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_DIR = os.environ.get("CERT_DIR", BASE_DIR)
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
    socket.getaddrinfo(CONTROLLER_HOST, MEDIA_PORT)
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


def build_arm_message():
    """Build the ChangeVideoSettings message that arms video1 for h264 at
    highest quality, pushed as extendedFlv to our media receiver (SPEC.md 3.1)."""
    stream_name = "mockstream00001"[:16]
    dest = "tcp://%s:%d?retryInterval=1&connectTimeout=5" % (CONTROLLER_HOST, MEDIA_PORT)
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


# POSIX TZ string sent in ChangeDeviceSettings (note: empirically this field
# appears to be camera->controller reporting only, not a working setter —
# kept configurable in case that changes on other firmware/models).
DEVICE_TIMEZONE = os.environ.get("DEVICE_TIMEZONE", "CET-1CEST,M3.5.0,M10.5.0/3")


def build_device_settings_message(camera_name):
    """Tell the camera its local timezone, so its OSD/overlay clock renders
    local time instead of defaulting to UTC. This is a real value (not a
    null query) so the camera applies it (see unifi-cam-proxy base.py
    process_device_settings / SPEC.md 2.5 "nulls are questions")."""
    payload = {
        "name": camera_name,
        "timezone": DEVICE_TIMEZONE,
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


def handle(conn, addr):
    log("=== TCP connection from %s ===" % (addr,))
    tls_conn = None
    try:
        tls_conn = ssl.wrap_socket(
            conn,
            server_side=True,
            certfile=CERTFILE,
            keyfile=KEYFILE,
        )
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
                            log("=== camera hello: adoptionCode=%r model=%r fw=%r mac=%r ==="
                                % (msg.get("payload", {}).get("adoptionCode"),
                                   model,
                                   msg.get("payload", {}).get("fwVersion"),
                                   msg.get("payload", {}).get("mac")))
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
                                try:
                                    arm_msg = build_arm_message()
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


# --- FLV broadcaster: fans the cleaned FLV byte stream out to any number of
# pull consumers (e.g. go2rtc's `tcp://host:7551` source), skipping ffmpeg
# and mediamtx entirely. ---
_flv_lock = threading.Lock()
_flv_consumers = []       # list of live consumer sockets
_flv_last_header = None   # last FLV header + PreviousTagSize0, replayed to
                           # new consumers that join mid-stream

# "GOP cache"-style config tags: the camera only sends these once near the
# start of the stream (AMF onMetaData, AVC sequence header, AAC sequence
# header). Any consumer connecting later needs them replayed first, or the
# downstream demuxer (e.g. go2rtc) can't identify codecs and finds zero
# tracks ("streams: unknown error"). Keyed by category so we always keep
# just the latest of each (metadata/video-config/audio-config), replayed to
# new consumers in a fixed, sensible order.
_flv_config_tags = {}  # category -> raw (tag_hdr + body + prevsize) bytes
_CONFIG_ORDER = ("metadata", "video", "audio")


def _config_tag_category(tag_type, body):
    if tag_type == 18:
        return "metadata"  # AMF onMetaData script tag
    if tag_type == 9 and len(body) >= 2 and (body[1] == 0):
        return "video"  # AVC sequence header (avcPacketType == 0)
    if tag_type == 8 and len(body) >= 2 and ((body[0] >> 4) == 10) and (body[1] == 0):
        return "audio"  # AAC sequence header (soundformat == AAC, aacPacketType == 0)
    return None


def _flv_add_consumer(sock):
    with _flv_lock:
        _flv_consumers.append(sock)
        header = _flv_last_header
        config_tags = dict(_flv_config_tags)
    try:
        if header:
            sock.sendall(header)
        for category in _CONFIG_ORDER:
            blob = config_tags.get(category)
            if blob:
                sock.sendall(blob)
    except Exception:
        _flv_remove_consumer(sock)


def _flv_remove_consumer(sock):
    with _flv_lock:
        if sock in _flv_consumers:
            _flv_consumers.remove(sock)
    try:
        sock.close()
    except Exception:
        pass


def _flv_broadcast(data, tag_type=None, body=None):
    if tag_type is not None:
        category = _config_tag_category(tag_type, body)
        if category:
            with _flv_lock:
                _flv_config_tags[category] = data
    with _flv_lock:
        consumers = list(_flv_consumers)
    for sock in consumers:
        try:
            sock.sendall(data)
        except Exception:
            _flv_remove_consumer(sock)


def _flv_set_header(header_bytes):
    global _flv_last_header
    with _flv_lock:
        _flv_last_header = header_bytes


def _flv_clear_config_tags():
    with _flv_lock:
        _flv_config_tags.clear()


def flv_output_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((FLV_OUTPUT_HOST, FLV_OUTPUT_PORT))
    srv.listen(5)
    log("FLV output server (for go2rtc pull) listening on tcp://%s:%d" %
        (FLV_OUTPUT_HOST, FLV_OUTPUT_PORT))
    while True:
        conn, addr = srv.accept()
        log("=== FLV consumer connected: %s ===" % (addr,))
        _flv_add_consumer(conn)


def handle_media(conn, addr):
    """Accept the camera's plain-TCP extendedFlv media push (SPEC.md 3.2).

    extendedFlv is regular FLV with a 16-byte trailer appended after every
    tag's standard 4-byte PreviousTagSize field. We strip that trailer and
    broadcast the resulting genuine FLV bytes to any connected consumers
    (e.g. go2rtc pulling via tcp://lappy:7551) — no ffmpeg/mediamtx needed.
    """
    log("=== MEDIA connection from %s ===" % (addr,))
    try:
        header = recv_exact(conn, 9)
        if header is None or header[:3] != b"FLV":
            log_err("=== MEDIA %s: not an FLV header: %r ===" % (addr, header))
            return
        log("=== MEDIA %s: FLV header %s ===" % (addr, hexdump(header)))
        header_and_prevsize0 = header + struct.pack("!I", 0)
        _flv_set_header(header_and_prevsize0)
        _flv_clear_config_tags()  # fresh camera connection => old config tags are stale
        _flv_broadcast(header_and_prevsize0)

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
                # Recompute PreviousTagSize ourselves since we may have
                # excised non-standard tags in between.
                _flv_broadcast(tag_hdr + body + struct.pack("!I", 11 + data_size),
                               tag_type=tag_type, body=body)
                forwarded_count += 1

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
        try:
            conn.close()
        except Exception:
            pass
        log("=== MEDIA connection from %s closed ===" % (addr,))


def media_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((MEDIA_HOST, MEDIA_PORT))
    srv.listen(5)
    log("Media (extendedFlv) server listening on tcp://%s:%d" % (MEDIA_HOST, MEDIA_PORT))
    while True:
        conn, addr = srv.accept()
        t = threading.Thread(target=handle_media, args=(conn, addr))
        t.daemon = True
        t.start()


def main():
    media_thread = threading.Thread(target=media_server)
    media_thread.daemon = True
    media_thread.start()

    flv_out_thread = threading.Thread(target=flv_output_server)
    flv_out_thread.daemon = True
    flv_out_thread.start()

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
