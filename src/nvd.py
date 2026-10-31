"""NVD CVE API에서 각 CVE의 '공식 수정 버전'을 조회한다.

LLM이 조치안을 생성할 때 수정 버전을 추측하게 두면 다른 CVE의 수정 버전과
혼동하는 환각이 생긴다(실제로 CVE-2025-24813에 Ghostcat의 9.0.31을 잘못
제시한 사례를 PoC 리뷰 중 발견했다). 이 모듈은 NVD의 cpeMatch 버전 범위에서
설치된 버전(기본 9.0.30)이 속한 구간의 versionEndExcluding/Including을
"수정 버전"으로 추출해 프롬프트 근거에 미리 박아 넣는다.
"""
from __future__ import annotations

import json
import re
import urllib.request
import urllib.error
from pathlib import Path

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
UA = {"User-Agent": "lotte-ax-poc/0.1 (security research PoC)"}

PRODUCT_HINT = "apache:tomcat"
INSTALLED_VERSION = "9.0.30"


def _version_tuple(v: str) -> tuple:
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts) if parts else (0,)


def _in_range(version: str, start_incl: str | None, end_excl: str | None, end_incl: str | None) -> bool:
    v = _version_tuple(version)
    if start_incl and v < _version_tuple(start_incl):
        return False
    if end_excl and v >= _version_tuple(end_excl):
        return False
    if end_incl and v > _version_tuple(end_incl):
        return False
    return True


def _get_json(url: str, timeout: int = 20) -> dict:
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_fix_version(cve_id: str, installed_version: str = INSTALLED_VERSION) -> dict | None:
    """installed_version이 속한 취약 구간의 수정 버전을 NVD에서 찾아 반환.
    {"fix_version": "9.0.99", "range": "...", "source": "NVD cpeMatch"} 형태.
    매칭되는 구간이 없으면 None (제품이 아예 안 걸렸거나 설치 버전이 범위 밖)."""
    try:
        data = _get_json(f"{NVD_URL}?cveId={cve_id}")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError) as e:
        print(f"[nvd] {cve_id} 조회 실패: {e}")
        return None

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None
    cve = vulns[0]["cve"]

    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                criteria = match.get("criteria", "")
                if PRODUCT_HINT not in criteria:
                    continue
                start_incl = match.get("versionStartIncluding")
                end_excl = match.get("versionEndExcluding")
                end_incl = match.get("versionEndIncluding")
                if not _in_range(installed_version, start_incl, end_excl, end_incl):
                    continue
                fix_version = end_excl or end_incl
                if fix_version:
                    return {
                        "fix_version": fix_version,
                        "range": f">= {start_incl or '0'}, {'<' if end_excl else '<='} {fix_version}",
                        "source": "NVD cpeMatch",
                    }
    return None


def fetch_fix_versions(cve_ids: list[str], cache_path: Path | None = None,
                        installed_version: str = INSTALLED_VERSION) -> dict[str, dict]:
    cache: dict[str, dict] = {}
    if cache_path and cache_path.exists():
        cache = json.loads(cache_path.read_text(encoding="utf-8"))

    changed = False
    for cve_id in cve_ids:
        if cve_id in cache:
            continue
        result = fetch_fix_version(cve_id, installed_version)
        cache[cve_id] = result
        changed = True

    if cache_path and changed:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
    return cache


if __name__ == "__main__":
    for cve in ["CVE-2020-1938", "CVE-2025-24813", "CVE-2020-9484", "CVE-2023-44487"]:
        print(cve, fetch_fix_version(cve))
