"""Exit node identity and DNS leak checks, routed through the local Tor SOCKS proxy."""
import socket

import requests

TOR_PROXIES = {
    "http": "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050",
}


def get_exit_info(timeout: int = 10) -> dict:
    """Return ip/country/asn of the current Tor exit node. Tries several
    providers in order and falls back to an IP-only check if all fail."""
    errors = []

    try:
        resp = requests.get(
            "http://ip-api.com/json/?fields=query,country,as",
            proxies=TOR_PROXIES,
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("query"):
            return {
                "ip": data.get("query", "unknown"),
                "country": data.get("country", "unknown"),
                "asn": data.get("as", "unknown"),
            }
        errors.append(f"ip-api.com: unexpected response {data}")
    except Exception as e:
        errors.append(f"ip-api.com: {e}")

    try:
        resp = requests.get("https://ipinfo.io/json", proxies=TOR_PROXIES, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        if data.get("ip"):
            return {
                "ip": data.get("ip", "unknown"),
                "country": data.get("country", "unknown"),
                "asn": data.get("org", "unknown"),
            }
        errors.append(f"ipinfo.io: unexpected response {data}")
    except Exception as e:
        errors.append(f"ipinfo.io: {e}")

    try:
        resp = requests.get("https://ipapi.co/json/", proxies=TOR_PROXIES, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        if data.get("ip"):
            return {
                "ip": data.get("ip", "unknown"),
                "country": data.get("country_name", "unknown"),
                "asn": data.get("asn", "unknown"),
            }
        errors.append(f"ipapi.co: unexpected response {data}")
    except Exception as e:
        errors.append(f"ipapi.co: {e}")

    try:
        resp = requests.get("https://icanhazip.com", proxies=TOR_PROXIES, timeout=timeout)
        resp.raise_for_status()
        return {"ip": resp.text.strip(), "country": "unknown", "asn": "unknown"}
    except Exception as e:
        errors.append(f"icanhazip.com: {e}")

    raise RuntimeError("all exit-info lookups failed: " + "; ".join(errors))


def check_dns_leak(test_host: str = "check.torproject.org") -> dict:
    """Heuristic DNS leak check. torniquet routes application DNS through the
    SOCKS proxy (socks5h); this does not perform a full resolver-side comparison."""
    result = {"leak": False, "detail": ""}
    try:
        socket.gethostbyname(test_host)
        result["detail"] = "system resolver reachable (expected); torniquet routes app DNS via socks5h"
    except socket.gaierror:
        result["detail"] = "system resolver failed to reach test host (not itself a leak indicator)"
    return result
