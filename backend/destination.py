"""
Destination-aware risk scoring.

The original problem statement requires analyzing WHERE data is going
(local machine vs. external email, etc.). This module turns a raw
destination string into a normalized destination type and a numeric
destination risk contribution, and blends that contribution into the
final 0-100 risk score WITHOUT altering Isolation Forest behavior.

Destination contribution mapping (per the problem statement):
    LOCAL_MACHINE   ->  2
    CORPORATE_EMAIL ->  5
    CLOUD_STORAGE   -> 15
    USB             -> 20
    PERSONAL_EMAIL  -> 25

If destination data is missing or unrecognized, we default safely to
LOCAL_MACHINE (the lowest-risk destination).
"""

# Canonical destination types and their risk contribution.
DESTINATION_RISK = {
    "LOCAL_MACHINE": 2,
    "CORPORATE_EMAIL": 5,
    "INTERNAL_FILESHARE": 8,
    "CLOUD_STORAGE": 15,
    "EXTERNAL_FTP": 18,
    "USB": 20,
    "PERSONAL_EMAIL": 25,
}

# Safe default when destination data is missing or unknown.
DEFAULT_DESTINATION = "LOCAL_MACHINE"

# Maximum possible destination contribution (used to scale the blend).
MAX_DESTINATION_RISK = max(DESTINATION_RISK.values())

# Common aliases mapped onto the canonical destination types so that
# slightly different inputs still resolve correctly.
_DESTINATION_ALIASES = {
    "LOCAL": "LOCAL_MACHINE",
    "LOCAL_MACHINE": "LOCAL_MACHINE",
    "WORKSTATION": "LOCAL_MACHINE",
    "ENDPOINT": "LOCAL_MACHINE",
    "CORPORATE_EMAIL": "CORPORATE_EMAIL",
    "CORP_EMAIL": "CORPORATE_EMAIL",
    "INTERNAL_EMAIL": "CORPORATE_EMAIL",
    "COMPANY_EMAIL": "CORPORATE_EMAIL",
    "INTERNAL_FILESHARE": "INTERNAL_FILESHARE",
    "FILESHARE": "INTERNAL_FILESHARE",
    "NETWORK_SHARE": "INTERNAL_FILESHARE",
    "SMB": "INTERNAL_FILESHARE",
    "SHAREPOINT": "INTERNAL_FILESHARE",
    "CLOUD_STORAGE": "CLOUD_STORAGE",
    "CLOUD": "CLOUD_STORAGE",
    "S3": "CLOUD_STORAGE",
    "DROPBOX": "CLOUD_STORAGE",
    "GDRIVE": "CLOUD_STORAGE",
    "GOOGLE_DRIVE": "CLOUD_STORAGE",
    "EXTERNAL_FTP": "EXTERNAL_FTP",
    "FTP": "EXTERNAL_FTP",
    "SFTP": "EXTERNAL_FTP",
    "EXTERNAL_SERVER": "EXTERNAL_FTP",
    "USB": "USB",
    "USB_DRIVE": "USB",
    "REMOVABLE_MEDIA": "USB",
    "EXTERNAL_DRIVE": "USB",
    "PERSONAL_EMAIL": "PERSONAL_EMAIL",
    "EXTERNAL_EMAIL": "PERSONAL_EMAIL",
    "GMAIL": "PERSONAL_EMAIL",
    "PERSONAL": "PERSONAL_EMAIL",
}


def normalize_destination(raw) -> str:
    """
    Resolve an arbitrary destination value to a canonical destination type.
    Defaults safely to LOCAL_MACHINE when missing or unrecognized.
    """
    if not raw:
        return DEFAULT_DESTINATION
    key = str(raw).strip().upper().replace("-", "_").replace(" ", "_")
    if key in DESTINATION_RISK:
        return key
    return _DESTINATION_ALIASES.get(key, DEFAULT_DESTINATION)


def destination_score(destination_type: str) -> int:
    """Return the numeric risk contribution for a canonical destination type."""
    return DESTINATION_RISK.get(destination_type, DESTINATION_RISK[DEFAULT_DESTINATION])


def resolve_destination(event: dict):
    """
    Inspect an access event and return (destination_type, destination_score).

    Reads the event's 'destination' field (also accepts 'destination_type'
    or 'data_destination' as fallbacks) and defaults to LOCAL_MACHINE.
    """
    raw = (
        event.get("destination")
        or event.get("destination_type")
        or event.get("data_destination")
    )
    dest_type = normalize_destination(raw)
    return dest_type, destination_score(dest_type)


def apply_destination_risk(base_risk, dest_score) -> int:
    """
    Blend the destination contribution into the Isolation-Forest-derived
    base risk score, keeping the result within the 0-100 range.

    The base (anomaly) score is preserved as the dominant signal; the
    destination contribution escalates risk on top of it. A LOCAL_MACHINE
    destination (2) nudges risk only marginally, while a PERSONAL_EMAIL
    destination (25) pushes a borderline event into a higher band.
    """
    base = max(0, min(100, float(base_risk)))
    final = base + float(dest_score)
    return int(max(0, min(100, round(final))))
