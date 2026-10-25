import os
import time
import json
import ipaddress
import requests
from typing import Dict, Any, Optional, List
from PySide6.QtCore import QObject, Signal, QThread
from utils.logger import logger
from core.incident_db import IncidentDatabase

# Investigation URL templates
INVESTIGATION_URLS = {
    "VirusTotal": "https://www.virustotal.com/gui/ip-address/{ip}",
    "AbuseIPDB": "https://www.abuseipdb.com/check/{ip}",
    "Shodan": "https://www.shodan.io/host/{ip}",
    "Cisco Talos": "https://talosintelligence.com/reputation_center/lookup?search={ip}",
    "IPinfo": "https://ipinfo.io/{ip}",
}


def classify_ip_address(ip_str: str) -> Dict[str, Any]:
    """
    Classifies an IP address into scope and type (Private, Public, Loopback, Link-Local, etc.).
    Returns dict with classification, is_public, and safe description.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        is_loopback = ip.is_loopback
        is_private = ip.is_private
        is_link_local = ip.is_link_local
        is_multicast = ip.is_multicast
        is_reserved = ip.is_reserved

        if is_loopback:
            scope = "Loopback (Local Host)"
            desc = "Loopback interface (127.0.0.0/8 or ::1). Traffic does not leave this computer."
            is_public = False
        elif is_private:
            scope = "Private Network (RFC 1918 / ULA)"
            desc = "Private internal network address. Not routable on the public Internet."
            is_public = False
        elif is_link_local:
            scope = "Link-Local (APIPA)"
            desc = "Link-local address (169.254.0.0/16 or fe80::/10) for local subnet communication."
            is_public = False
        elif is_multicast:
            scope = "Multicast Group"
            desc = "Multicast destination for group broadcast/multicast."
            is_public = False
        elif is_reserved:
            scope = "Reserved / IANA"
            desc = "Reserved address space per IANA allocations."
            is_public = False
        else:
            scope = "Public Internet"
            desc = "Globally routable public Internet address."
            is_public = True

        return {
            "ip": ip_str,
            "version": ip.version,
            "scope": scope,
            "is_public": is_public,
            "description": desc,
        }
    except ValueError:
        return {
            "ip": ip_str,
            "version": 4,
            "scope": "Unknown / Invalid",
            "is_public": False,
            "description": "Invalid IP address string.",
        }


class BaseThreatIntelProvider:
    """Abstract base class for modular threat intelligence providers."""
    name: str = "BaseProvider"

    def lookup(self, ip: str) -> Dict[str, Any]:
        raise NotImplementedError


class IPApiGeoProvider(BaseThreatIntelProvider):
    """
    Free IP Geolocation and ASN provider using ip-api.com.
    Does not require an API key (up to 45 requests/min).
    Strictly queries public IPs only.
    """
    name = "ip-api.com (Geo & ASN)"

    def lookup(self, ip: str) -> Dict[str, Any]:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        try:
            resp = requests.get(url, timeout=5.0)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return {
                        "status": "success",
                        "provider": self.name,
                        "country": data.get("country", "Unknown"),
                        "country_code": data.get("countryCode", ""),
                        "region": data.get("regionName", ""),
                        "city": data.get("city", "Unknown"),
                        "lat": data.get("lat"),
                        "lon": data.get("lon"),
                        "timezone": data.get("timezone", ""),
                        "isp": data.get("isp", "Unknown"),
                        "org": data.get("org", "Unknown"),
                        "asn": data.get("as", "Unknown"),
                        "score": 0.0,
                        "is_malicious": False,
                        "details": data
                    }
                else:
                    return {"status": "error", "message": data.get("message", "Lookup returned fail status")}
            elif resp.status_code == 429:
                return {"status": "rate_limited", "message": "Rate limit reached (45 req/min). Please try again shortly."}
            else:
                return {"status": "error", "message": f"HTTP {resp.status_code}"}
        except Exception as e:
            logger.warning(f"IPApiGeoProvider failed for {ip}: {e}")
            return {"status": "error", "message": str(e)}


class AbuseIPDBProvider(BaseThreatIntelProvider):
    """
    AbuseIPDB reputation provider.
    Requires an API key.
    """
    name = "AbuseIPDB"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def lookup(self, ip: str) -> Dict[str, Any]:
        if not self.api_key:
            return {"status": "unconfigured", "message": "No AbuseIPDB API key configured."}

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Accept": "application/json",
            "Key": self.api_key
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": "90",
            "verbose": True
        }
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=6.0)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                abuse_score = float(data.get("abuseConfidenceScore", 0.0))
                total_reports = int(data.get("totalReports", 0))
                is_malicious = abuse_score >= 50 or total_reports > 5
                return {
                    "status": "success",
                    "provider": self.name,
                    "score": abuse_score,
                    "is_malicious": is_malicious,
                    "total_reports": total_reports,
                    "last_reported_at": data.get("lastReportedAt", "Never"),
                    "isp": data.get("isp", "Unknown"),
                    "usage_type": data.get("usageType", "Unknown"),
                    "domain": data.get("domain", "Unknown"),
                    "country_code": data.get("countryCode", ""),
                    "details": data
                }
            elif resp.status_code == 401 or resp.status_code == 403:
                return {"status": "auth_error", "message": "Invalid AbuseIPDB API key."}
            elif resp.status_code == 429:
                return {"status": "rate_limited", "message": "AbuseIPDB API rate limit exceeded."}
            else:
                return {"status": "error", "message": f"HTTP {resp.status_code}: {resp.text[:100]}"}
        except Exception as e:
            logger.warning(f"AbuseIPDB lookup failed for {ip}: {e}")
            return {"status": "error", "message": str(e)}


class VirusTotalProvider(BaseThreatIntelProvider):
    """
    VirusTotal IP lookup provider.
    Requires an API key.
    """
    name = "VirusTotal"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def lookup(self, ip: str) -> Dict[str, Any]:
        if not self.api_key:
            return {"status": "unconfigured", "message": "No VirusTotal API key configured."}

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {
            "x-apikey": self.api_key
        }
        try:
            resp = requests.get(url, headers=headers, timeout=6.0)
            if resp.status_code == 200:
                attr = resp.json().get("data", {}).get("attributes", {})
                stats = attr.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                total_engines = malicious + suspicious + harmless + undetected

                score = (malicious * 100.0) / max(1, total_engines)
                is_malicious = malicious >= 3

                return {
                    "status": "success",
                    "provider": self.name,
                    "score": round(score, 1),
                    "is_malicious": is_malicious,
                    "malicious_count": malicious,
                    "suspicious_count": suspicious,
                    "harmless_count": harmless,
                    "as_owner": attr.get("as_owner", "Unknown"),
                    "reputation": attr.get("reputation", 0),
                    "details": attr
                }
            elif resp.status_code == 401 or resp.status_code == 403:
                return {"status": "auth_error", "message": "Invalid VirusTotal API key."}
            elif resp.status_code == 429:
                return {"status": "rate_limited", "message": "VirusTotal API rate limit exceeded."}
            else:
                return {"status": "error", "message": f"HTTP {resp.status_code}"}
        except Exception as e:
            logger.warning(f"VirusTotal lookup failed for {ip}: {e}")
            return {"status": "error", "message": str(e)}


class ThreatIntelManager:
    """
    Orchestrates IP threat intelligence queries, classification,
    privacy guards, and local SQLite caching.
    """
    def __init__(self):
        self.db = IncidentDatabase()
        self.geo_provider = IPApiGeoProvider()

    def get_api_keys(self) -> Dict[str, str]:
        """Fetches API keys from local DB settings or environment variables."""
        saved_keys = self.db.get_setting("threat_intel_keys", {}) or {}
        return {
            "abuseipdb": saved_keys.get("abuseipdb") or os.environ.get("ABUSEIPDB_API_KEY", ""),
            "virustotal": saved_keys.get("virustotal") or os.environ.get("VIRUSTOTAL_API_KEY", "")
        }

    def set_api_keys(self, abuseipdb_key: str = "", virustotal_key: str = ""):
        keys = self.get_api_keys()
        if abuseipdb_key is not None:
            keys["abuseipdb"] = abuseipdb_key.strip()
        if virustotal_key is not None:
            keys["virustotal"] = virustotal_key.strip()
        self.db.set_setting("threat_intel_keys", keys)

    def lookup_ip(self, ip: str, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Main entry point for enriching an IP address.
        Enforces privacy guards: NEVER queries external services for private/RFC1918/loopback IPs.
        Checks local cache before contacting remote providers.
        """
        classification = classify_ip_address(ip)

        # 1. Privacy Guard: Never send private or non-public addresses externally
        if not classification["is_public"]:
            return {
                "ip": ip,
                "classification": classification,
                "cached": False,
                "lookup_time": time.time(),
                "providers": {
                    "Privacy Guard": {
                        "status": "info",
                        "message": f"External threat intelligence is disabled for {classification['scope']} addresses. "
                                   "Private/reserved addresses are never transmitted to third parties."
                    }
                },
                "summary": {
                    "country": "Local / Private",
                    "city": "Private Network",
                    "asn": "N/A (RFC 1918 / Local)",
                    "isp": "Local Network Interface",
                    "abuse_score": 0.0,
                    "is_malicious": False,
                    "confidence": "Verified Local Address"
                },
                "investigation_links": {}
            }

        # 2. Check local SQLite cache unless force_refresh is requested
        if not force_refresh:
            cached = self.db.get_cached_threat_intel(ip)
            if cached:
                cached_data = cached.get("data", {})
                cached_data["cached"] = True
                cached_data["cached_at"] = cached.get("cached_at")
                return cached_data

        # 3. Perform Live Lookups
        keys = self.get_api_keys()
        providers_result = {}

        # Always query Free Geolocation / ASN
        geo_res = self.geo_provider.lookup(ip)
        providers_result[self.geo_provider.name] = geo_res

        abuse_score = 0.0
        is_malicious = False

        # Query AbuseIPDB if key is configured
        if keys.get("abuseipdb"):
            abuse_prov = AbuseIPDBProvider(keys["abuseipdb"])
            abuse_res = abuse_prov.lookup(ip)
            providers_result[abuse_prov.name] = abuse_res
            if abuse_res.get("status") == "success":
                abuse_score = max(abuse_score, abuse_res.get("score", 0.0))
                if abuse_res.get("is_malicious"):
                    is_malicious = True

        # Query VirusTotal if key is configured
        if keys.get("virustotal"):
            vt_prov = VirusTotalProvider(keys["virustotal"])
            vt_res = vt_prov.lookup(ip)
            providers_result[vt_prov.name] = vt_res
            if vt_res.get("status") == "success":
                abuse_score = max(abuse_score, vt_res.get("score", 0.0))
                if vt_res.get("is_malicious"):
                    is_malicious = True

        # Build investigation links
        inv_links = {name: tmpl.format(ip=ip) for name, tmpl in INVESTIGATION_URLS.items()}

        summary = {
            "country": geo_res.get("country", "Unknown") if geo_res.get("status") == "success" else "Unknown",
            "city": geo_res.get("city", "Unknown") if geo_res.get("status") == "success" else "Unknown",
            "asn": geo_res.get("asn", "Unknown") if geo_res.get("status") == "success" else "Unknown",
            "isp": geo_res.get("isp", "Unknown") if geo_res.get("status") == "success" else "Unknown",
            "abuse_score": abuse_score,
            "is_malicious": is_malicious,
            "confidence": "Reputation & Geolocation"
        }

        result = {
            "ip": ip,
            "classification": classification,
            "cached": False,
            "lookup_time": time.time(),
            "providers": providers_result,
            "summary": summary,
            "investigation_links": inv_links
        }

        # Cache in SQLite (24 hours TTL)
        self.db.save_threat_intel_cache(
            ip=ip,
            provider="MultiProvider",
            score=abuse_score,
            is_malicious=is_malicious,
            data=result,
            ttl_seconds=86400
        )

        return result


class ThreatIntelWorker(QThread):
    """Asynchronous worker for performing IP threat lookups without freezing GUI."""
    result_ready = Signal(dict)
    error_occurred = Signal(str, str)

    def __init__(self, ip: str, force_refresh: bool = False, parent=None):
        super().__init__(parent)
        self.ip = ip
        self.force_refresh = force_refresh
        self.manager = ThreatIntelManager()

    def run(self):
        try:
            result = self.manager.lookup_ip(self.ip, force_refresh=self.force_refresh)
            self.result_ready.emit(result)
        except Exception as e:
            logger.error(f"ThreatIntelWorker failed for {self.ip}: {e}")
            self.error_occurred.emit(self.ip, str(e))
