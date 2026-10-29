"""Bounded, canonical observation contract. No inferred physical identities."""
import datetime as dt
import hashlib
import ipaddress
import json
import math
import re
import unicodedata
from atlas.wifi.schema import RADIO_FIELDS, validate_radio
from atlas.bluetooth.schema import BLE_FIELDS, GATT_FIELDS, validate_ble

from atlas.cellular.schema import CELLULAR_FIELDS, validate_cellular

MAX_LINE = 16_384
KINDS = {"wifi", "ble", "ble_gatt", "neighbor", "route", "service", "cellular"}
FIELDS = {"kind", "id", "observed_at", "source", "name", "rssi", "security", "ip", "mac", "interface", "gateway", "port"} | RADIO_FIELDS | BLE_FIELDS | GATT_FIELDS | CELLULAR_FIELDS


def clean(value):
    return "".join(c for c in str(value) if not unicodedata.category(c).startswith("C"))


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds")


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("observed_at must be an ISO 8601 string")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid observed_at") from exc
    if parsed.tzinfo is None:
        raise ValueError("observed_at needs a timezone")
    if parsed > dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5):
        raise ValueError("observed_at is in the future")
    return parsed.astimezone(dt.timezone.utc).isoformat(timespec="microseconds")


def mac(value):
    if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", value):
        raise ValueError("invalid MAC address")
    return value.lower()


def address(value):
    if not isinstance(value, str) or "%" in value:
        raise ValueError("IP must be a literal without a zone identifier")
    return str(ipaddress.ip_address(value))


def validate(raw):
    if not isinstance(raw, dict) or set(raw) - FIELDS:
        raise ValueError("observation must be an object with documented fields")
    o = dict(raw)
    if not isinstance(o.get("kind"), str) or o['kind'] not in KINDS:
        raise ValueError("unsupported kind")
    for key in ("id", "source", "observed_at"):
        if not isinstance(o.get(key), str) or not o[key] or len(o[key]) > 256:
            raise ValueError(f"{key} must be a nonempty string of at most 256 characters")
    for key in ("name", "interface", "security"):
        if key in o and (not isinstance(o[key], str) or len(o[key]) > 256):
            raise ValueError(f"invalid {key}")
    o["observed_at"] = timestamp(o["observed_at"])
    for key in ("ip", "gateway"):
        if key in o:
            o[key] = address(o[key])
    if "mac" in o:
        o["mac"] = mac(o["mac"])
    if "rssi" in o:
        if isinstance(o["rssi"], bool) or not isinstance(o["rssi"], (int, float)) or not math.isfinite(o["rssi"]) or not -127 <= o["rssi"] <= 0:
            raise ValueError("rssi must be between -127 and 0 dBm")
    if "port" in o and (type(o["port"]) is not int or not 1 <= o["port"] <= 65535):
        raise ValueError("port must be 1..65535")
    if o["kind"] in {"wifi", "ble", "ble_gatt"}:
        o["id"] = mac(o["id"])
    if o["kind"] == "wifi":
        if "security" not in o:
            raise ValueError("wifi requires security (use UNKNOWN when unavailable)")
        o["security"] = o["security"].upper()
        validate_radio(o)
    elif RADIO_FIELDS & set(o):
        raise ValueError('Wi-Fi radio fields are only valid for wifi observations')
    if o['kind'] in {'ble','ble_gatt'}:
        validate_ble(o)
    elif (BLE_FIELDS | GATT_FIELDS) & set(o):
        raise ValueError('BLE fields require ble or ble_gatt observations')
    if o["kind"] == "cellular":
        validate_cellular(o)
    elif CELLULAR_FIELDS & set(o):
        raise ValueError("cellular fields require cellular observations")
    if o["kind"] in {"neighbor", "service"}:
        if "ip" not in o:
            raise ValueError("neighbor/service requires ip")
        expected = o["ip"] if o["kind"] == "neighbor" else f'{o["ip"]}/tcp/{o.get("port")}'
        if o["id"] != expected or (o["kind"] == "service" and "port" not in o):
            raise ValueError("id must match IP or IP/tcp/port")
    if o["kind"] == "neighbor" and "mac" not in o:
        raise ValueError("neighbor requires mac")
    if o["kind"] == "route" and "gateway" not in o:
        raise ValueError("route requires gateway")
    try:
        if len(encoded(o).encode()) > MAX_LINE:
            raise ValueError('observation exceeds 16 KiB')
    except (TypeError, RecursionError) as exc:
        raise ValueError('invalid observation structure') from exc
    return o


def encoded(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def fingerprint(o):
    return hashlib.sha256(encoded(o).encode()).hexdigest()
