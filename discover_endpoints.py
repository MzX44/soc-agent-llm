#!/usr/bin/env python3
"""
Helper: print the real API routes each SOC service exposes, so you can confirm
or fix the ENDPOINTS block in main.py.

Each service publishes OpenAPI. This reads /openapi.json from each port and
lists the method + path + a short summary for every route. Run it once, with
the VPN connected, BEFORE your first real agent run:

    python discover_endpoints.py

Then edit the ENDPOINTS dict at the top of main.py to match what you see here.
This script needs no API keys and makes no changes.
"""
import requests

SERVICES = {
    "Ticket Platform (3025)": "http://10.10.11.125:3025",
    "SIEM (3023)":            "http://10.10.11.125:3023",
    "DHCP Logs (3021)":       "http://10.10.11.125:3021",
    "Device Registry (3022)": "http://10.10.11.125:3022",
    "Identity Directory (3024)": "http://10.10.11.125:3024",
}


def show(name, base):
    print(f"\n=== {name} ===")
    for path in ("/openapi.json", "/docs/openapi.json"):
        try:
            r = requests.get(base + path, timeout=15)
        except requests.RequestException as e:
            print(f"  could not reach {base}{path}: {e}")
            continue
        if r.status_code != 200:
            print(f"  {base}{path} -> HTTP {r.status_code}")
            continue
        try:
            spec = r.json()
        except ValueError:
            print(f"  {base}{path} did not return JSON")
            continue
        paths = spec.get("paths", {})
        if not paths:
            print("  (no paths in spec)")
            return
        for p, methods in sorted(paths.items()):
            for method, meta in methods.items():
                if method.lower() not in ("get", "post", "put", "delete", "patch"):
                    continue
                summary = (meta.get("summary") or "").strip()
                params = [pm.get("name") for pm in meta.get("parameters", []) if pm.get("name")]
                param_str = f"  params={params}" if params else ""
                print(f"  {method.upper():5} {p}   {summary}{param_str}")
        return
    print("  no OpenAPI spec found at /openapi.json (open the service's /docs page in a browser instead)")


if __name__ == "__main__":
    print("Reading each SOC service's API spec (VPN must be connected)...")
    for name, base in SERVICES.items():
        show(name, base)
    print("\nNow update the ENDPOINTS dict in main.py to match the routes above.")
