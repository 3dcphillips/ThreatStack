# app/siem/log_parser.py
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional, Tuple

# Apache combined/common-ish:
# 127.0.0.1 - - [05/Mar/2026:10:10:10 -0500] "GET / HTTP/1.1" 200 1234
APACHE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<req>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
)

APACHE_TS_RE = re.compile(
    r"^(?P<day>\d{2})/(?P<mon>[A-Za-z]{3})/(?P<year>\d{4}):(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})\s+(?P<tz>[+\-]\d{4})$"
)

MON_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}


def _parse_apache_dt(ts: str) -> Optional[datetime]:
    """
    Parses: 05/Mar/2026:10:10:10 -0500
    Returns timezone-aware datetime.
    """
    m = APACHE_TS_RE.match(ts.strip())
    if not m:
        return None

    day = int(m.group("day"))
    mon = MON_MAP.get(m.group("mon"))
    year = int(m.group("year"))
    hh = int(m.group("h"))
    mm = int(m.group("m"))
    ss = int(m.group("s"))
    tz = m.group("tz")  # like -0500

    if not mon:
        return None

    # tz offset like -0500 -> hours=-5, minutes=0
    sign = -1 if tz.startswith("-") else 1
    tzh = int(tz[1:3])
    tzm = int(tz[3:5])
    offset = sign * (tzh * 60 + tzm)
    tzinfo = timezone.utc if offset == 0 else timezone(datetime.now().astimezone().utcoffset())  # fallback

    # More reliable tzinfo: build fixed offset
    tzinfo = timezone(sign * (datetime.min.replace(hour=tzh, minute=tzm) - datetime.min))

    return datetime(year, mon, day, hh, mm, ss, tzinfo=tzinfo)


def parse_apache_line(line: str) -> Optional[dict]:
    """
    Returns dict with: parsed_ip, timestamp, event_type, message
    or None if not parseable.
    """
    m = APACHE_RE.match(line.strip())
    if not m:
        return None

    ip = m.group("ip")
    ts_raw = m.group("ts")
    dt = _parse_apache_dt(ts_raw)

    # If timestamp parsing fails, we still ingest the message
    return {
        "parsed_ip": ip,
        "timestamp": dt,
        "event_type": "http_access",
        "message": line.rstrip("\n"),
    }


def parse_line(source: str, line: str) -> Tuple[Optional[dict], Optional[str]]:
    """
    Generic entry point. Returns (parsed_event, error_reason).
    """
    source = (source or "").lower().strip()

    if source == "apache":
        evt = parse_apache_line(line)
        if evt:
            return evt, None
        return None, "unrecognized_apache_format"

    # Unknown source -> store raw only (still useful for MVP)
    return {
        "parsed_ip": None,
        "timestamp": None,
        "event_type": source or "unknown",
        "message": line.rstrip("\n"),
    }, None