"""grype 매칭 결과 + EPSS + KEV + 설정 기반 도달성 판정을 합쳐서
'진짜 위험' 우선순위를 매긴다.

3계층 중 '룰 → 통계' 두 단계까지가 이 모듈. LLM은 쓰지 않는다
(설명 가능성과 비용 통제를 위해 단순 가중합 공식을 그대로 노출).

score = (CVSS/10)*50 + EPSS*30 + (KEV 등재 시 +20)
        → 설정상 도달 불가로 판정되면 score *= REACHABILITY_DISCOUNT

같은 CVE라도 server.xml 설정에 따라 reachable 여부가 바뀌므로,
동일 스캔 결과에 대해 설정 시나리오별로 이 모듈을 두 번 실행하면
우선순위가 달라지는 것을 그대로 보여줄 수 있다.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path

from reachability import judge

REACHABILITY_DISCOUNT = 0.3  # 설정상 도달 불가 판정 시 점수를 70% 깎음 (완전히 0으로 만들지 않음: 패치 권고는 유지)

TIER_THRESHOLDS = [
    (70, "Critical"),
    (40, "High"),
    (15, "Medium"),
    (0, "Low"),
]


@dataclass
class Finding:
    cve_id: str
    severity: str
    cvss: float | None
    cvss_vector: str | None
    epss: float | None
    kev: bool
    kev_due_date: str | None
    affected_components: list[str]
    reachable: bool | None  # None = 해당 CVE에 대한 설정 기반 판정 룰이 없음 (판정 불가)
    reachability_reason: str | None
    score: float
    tier: str


def _best_cvss(vuln: dict) -> tuple[float | None, str | None]:
    cvss_list = vuln.get("cvss") or []
    # NVD Primary 3.x 우선, 없으면 가장 높은 baseScore
    best = None
    for c in cvss_list:
        score = c.get("metrics", {}).get("baseScore")
        if score is None:
            continue
        if best is None or score > best[0]:
            best = (score, c.get("vector"))
    return best if best else (None, None)


def _tier_for(score: float) -> str:
    for threshold, label in TIER_THRESHOLDS:
        if score >= threshold:
            return label
    return "Low"


def load_grype_matches(grype_json_path: Path) -> dict[str, dict]:
    """grype 매치를 cve_id로 그룹핑해 중복(같은 CVE가 여러 jar에 걸쳐
    반복 매칭되는 것)을 1건으로 합친다."""
    data = json.loads(grype_json_path.read_text(encoding="utf-8"))
    grouped: dict[str, dict] = {}
    for m in data.get("matches", []):
        vuln = m["vulnerability"]
        cve_id = vuln["id"]
        artifact = m["artifact"]
        comp_label = f"{artifact['name']}@{artifact['version']}"

        if cve_id not in grouped:
            grouped[cve_id] = {
                "vuln": vuln,
                "components": set(),
            }
        grouped[cve_id]["components"].add(comp_label)
    return grouped


def prioritize(
    grype_json_path: Path,
    config_dir: Path | None,
    epss_map: dict[str, dict],
    kev_map: dict[str, dict],
) -> list[Finding]:
    grouped = load_grype_matches(grype_json_path)
    findings: list[Finding] = []

    for cve_id, g in grouped.items():
        vuln = g["vuln"]
        cvss, vector = _best_cvss(vuln)
        epss_row = epss_map.get(cve_id)
        epss = epss_row["epss"] if epss_row else None
        kev_row = kev_map.get(cve_id)
        in_kev = kev_row is not None

        reachable = None
        reason = None
        if config_dir is not None:
            verdict = judge(cve_id, config_dir)
            if verdict is not None:
                reachable = verdict.reachable
                reason = verdict.reason

        score = 0.0
        if cvss is not None:
            score += (cvss / 10.0) * 50
        if epss is not None:
            score += epss * 30
        if in_kev:
            score += 20

        if reachable is False:
            score *= REACHABILITY_DISCOUNT

        findings.append(
            Finding(
                cve_id=cve_id,
                severity=vuln.get("severity", "Unknown"),
                cvss=cvss,
                cvss_vector=vector,
                epss=epss,
                kev=in_kev,
                kev_due_date=kev_row.get("dueDate") if kev_row else None,
                affected_components=sorted(g["components"]),
                reachable=reachable,
                reachability_reason=reason,
                score=round(score, 2),
                tier=_tier_for(score),
            )
        )

    findings.sort(key=lambda f: f.score, reverse=True)
    return findings


if __name__ == "__main__":
    import sys
    from enrich import fetch_epss, fetch_kev

    root = Path(__file__).resolve().parent.parent
    grype_path = root / "output" / "grype.json"

    grouped = load_grype_matches(grype_path)
    cve_ids = [c for c in grouped if c.startswith("CVE")]

    epss_map = fetch_epss(cve_ids, cache_path=root / "output" / "epss.json")
    kev_map = fetch_kev(cache_path=root / "output" / "kev.json")

    for scenario in ["ajp-vulnerable", "ajp-mitigated"]:
        cfg_dir = root / "config" / scenario
        findings = prioritize(grype_path, cfg_dir, epss_map, kev_map)
        out_path = root / "output" / f"priority_{scenario}.json"
        out_path.write_text(
            json.dumps([asdict(f) for f in findings], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"[{scenario}] total={len(findings)}")
        for cve_id in ["CVE-2020-1938", "CVE-2025-24813", "CVE-2020-9484"]:
            f = next((x for x in findings if x.cve_id == cve_id), None)
            rank = findings.index(f) + 1 if f else None
            print(f"  {cve_id} rank={rank} tier={f.tier if f else 'N/A'} score={f.score if f else 'N/A'}")
