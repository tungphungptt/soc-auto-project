import hashlib
import ipaddress
import json
import math
import os
import sqlite3
from pathlib import Path
from urllib import request, error


class APIError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message
        super().__init__(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def ip(value):
    if not isinstance(value, str) or "%" in value:
        raise APIError(422, "IP must be a literal address without zone ID")
    try:
        addr = ipaddress.ip_address(value)
    except ValueError as exc:
        raise APIError(422, "Invalid IP address") from exc
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return str(addr)


def number(value, name, low, high, integer=False):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise APIError(422, name + " must be numeric")
    if not math.isfinite(value) or not low <= value <= high:
        raise APIError(422, name + " outside allowed range")
    if integer and not isinstance(value, int):
        raise APIError(422, name + " must be an integer")
    return value


def db(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def http_json(url, payload=None, token=None, timeout=3):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = None if payload is None else canonical(payload).encode()
    req = request.Request(url, data=data, headers=headers)
    # Do not send service credentials to redirects or environment HTTP proxies.
    opener = request.build_opener(request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(req, timeout=timeout) as response:
            raw = response.read(65537)
            if len(raw) > 65536:
                raise APIError(502, "Upstream response too large")
            value = json.loads(raw, parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))
            if not isinstance(value, dict):
                raise APIError(502, "Upstream response must be an object")
            return value
    except error.HTTPError as exc:
        raise APIError(502, "Upstream HTTP " + str(exc.code)) from exc
    except (error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise APIError(503, "Upstream unavailable or invalid JSON") from exc


def load_policy(path=None):
    from .policy import Policy
    path = path or os.environ.get("SOC_POLICY", str(Path(__file__).resolve().parents[1] / "config" / "policy.json"))
    return Policy(json.loads(Path(path).read_text(encoding="utf-8")))
