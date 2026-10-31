"""FIRST EPSS API + CISA KEV 피드로 CVE 목록을 보강한다.

EPSS: https://api.first.org/data/v1/epss?cve=CVE-xxxx-xxxx (악용 가능성 확률, 0~1)
KEV : https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
      (CISA가 "실제로 악용이 확인된" 취약점만 추려놓은 리스트)
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error
from pathlib import Path

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
UA = {"User-Agent": "lotte-ax-poc/0.1 (security research PoC)"}


def _get_json(url: str, timeout: int = 15) -> dict:
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_epss(cve_ids: list[str], cache_path: Path | None = None) -> dict[str, dict]:
    """CVE별 EPSS score/percentile을 조회. 실패 시 빈 dict로 degrade."""
    if cache_path and cache_path.exists():
        return json.loads(cache_path.read_text(encoding="utf-8"))

    result: dict[str, dict] = {}
    # EPSS API는 콤마로 여러 CVE를 한 번에 조회 가능 (최대 수백 개)
    batch_size = 100
    for i in range(0, len(cve_ids), batch_size):
        batch = cve_ids[i:i + batch_size]
        url = f"{EPSS_URL}?cve={','.join(batch)}"
        try:
            data = _get_json(url)
            for row in data.get("data", []):
                result[row["cve"]] = {
                    "epss": float(row["epss"]),
                    "percentile": float(row["percentile"]),
                    "date": row.get("date"),
                }
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError) as e:
            print(f"[enrich] EPSS 조회 실패 (batch {i}): {e}")

    if cache_path:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def fetch_kev(cache_path: Path | None = None) -> dict[str, dict]:
    """CISA KEV 전체 피드를 받아 CVE ID -> 상세 정보 맵으로 변환. 실패 시 빈 dict."""
    if cache_path and cache_path.exists():
        raw = json.loads(cache_path.read_text(encoding="utf-8"))
        return raw

    result: dict[str, dict] = {}
    try:
        data = _get_json(KEV_URL)
        for vuln in data.get("vulnerabilities", []):
            result[vuln["cveID"]] = {
                "dateAdded": vuln.get("dateAdded"),
                "shortDescription": vuln.get("shortDescription"),
                "requiredAction": vuln.get("requiredAction"),
                "dueDate": vuln.get("dueDate"),
                "knownRansomwareCampaignUse": vuln.get("knownRansomwareCampaignUse"),
            }
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError) as e:
        print(f"[enrich] CISA KEV 조회 실패: {e}")

    if cache_path:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


if __name__ == "__main__":
    test_cves = ["CVE-2020-1938", "CVE-2021-3711", "CVE-2023-44487"]
    epss = fetch_epss(test_cves)
    kev = fetch_kev()
    for cve in test_cves:
        print(cve, "EPSS:", epss.get(cve), "| KEV:", cve in kev)
