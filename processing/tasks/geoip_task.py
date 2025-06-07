"""Task for locating host ip addresses."""

import functools
from pathlib import Path
from typing import Any

import geoip2.database

# cache geoip2.database.Reader to avoid reloading the database multiple times
geoip2.database.Reader = functools.cache(geoip2.database.Reader)

MMDB_PATH = Path("GeoLite2-Country.mmdb")


def pre_check():
    if not MMDB_PATH.exists():
        raise FileNotFoundError(
            f"GeoIP Database not found: {MMDB_PATH.absolute()}. Please download it from https://dev.maxmind.com/geoip/geoip2/geolite2/ and place it in the processing directory."
        )


def run(host_data: dict[str, Any]) -> dict[str, Any] | None:
    """Determine country and continent of given host."""
    geoip_db = geoip2.database.Reader(MMDB_PATH)
    ip = host_data.get("ip")
    if ip.startswith("192.168"):
        return {"country": "Germany", "continent": "Europe"}

    response = geoip_db.country(ip)
    return {"country": response.country.name, "continent": response.continent.name}
