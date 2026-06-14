"""
First-time resource access detection.

Maintains a historical access index per user, built entirely from the
existing dataset (src/imports/anomaly_predictions.json) — no database
changes required. For any access event we can answer:

    "Has this user ever accessed this resource before?"

If the answer is no, the event is flagged with the feature
`is_first_time_resource_access = True`. First-time access to a resource is
a meaningful behavioral signal (a user reaching for data they have never
touched), so it contributes additional risk on top of the
Isolation-Forest-derived base score, WITHOUT altering model behavior.
"""

import json
import os
from collections import defaultdict

DATA_PATH = os.path.join(
    os.path.dirname(__file__), "..", "src", "imports", "anomaly_predictions.json"
)

# Risk contribution added when an access is the user's first time on a resource.
FIRST_TIME_RISK = 12

# (user_id, resource) -> earliest timestamp string seen historically.
_first_seen = {}
# user_id -> set of resources the user has historically accessed.
_user_resources = defaultdict(set)
_loaded = False


def _load_history():
    """Build the historical access index from the existing dataset (once)."""
    global _loaded
    if _loaded:
        return
    try:
        with open(DATA_PATH) as f:
            data = json.load(f)
    except Exception:
        data = []

    # Process chronologically so the earliest occurrence is recorded as the
    # "first time" for each (user, resource) pair.
    rows = sorted(data, key=lambda r: str(r.get("timestamp", "")))
    for r in rows:
        uid = r.get("user_id")
        resource = r.get("resource")
        if not uid or not resource:
            continue
        key = (uid, resource)
        if key not in _first_seen:
            _first_seen[key] = str(r.get("timestamp", ""))
        _user_resources[uid].add(resource)

    _loaded = True


def is_first_time_resource_access(event: dict) -> bool:
    """
    Return True if the user has never accessed this resource before.

    An event is treated as first-time when either:
      - the (user, resource) pair does not appear in the historical index, or
      - the event is the earliest recorded occurrence of that pair.
    Defaults to False (not first-time) when identity data is missing, so we
    never over-escalate on incomplete records.
    """
    _load_history()
    uid = event.get("user_id")
    resource = event.get("resource")
    if not uid or not resource:
        return False

    key = (uid, resource)
    if key not in _first_seen:
        return True

    ts = str(event.get("timestamp", ""))
    # If this event is at or before the earliest historical occurrence, it is
    # the first time the user touched this resource.
    return bool(ts) and ts <= _first_seen[key]


def first_time_score(is_first_time: bool) -> int:
    """Numeric risk contribution for a first-time resource access."""
    return FIRST_TIME_RISK if is_first_time else 0


def resolve_first_time(event: dict):
    """Return (is_first_time_resource_access, first_time_score) for an event."""
    is_first = is_first_time_resource_access(event)
    return is_first, first_time_score(is_first)


def apply_first_time_risk(base_risk, ft_score) -> int:
    """
    Blend the first-time-access contribution into the base risk score,
    keeping the result within the 0-100 range. The base (anomaly) score
    remains the dominant signal; first-time access escalates risk on top.
    """
    base = max(0, min(100, float(base_risk)))
    final = base + float(ft_score)
    return int(max(0, min(100, round(final))))
